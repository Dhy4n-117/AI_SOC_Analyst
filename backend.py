import os
import shutil
import json
import re  # For IoC Extraction
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from langchain_core.documents import Document
from typing import List, Dict, Any

from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.chains import RetrievalQAWithSourcesChain
from langchain.chains.summarize import load_summarize_chain
from langchain_community.chat_models import ChatOllama
from langchain.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

app = FastAPI(title="GenAI SOC Assistant API v5")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIGURATION ---
MODEL_NAME = "phi3"
VECTOR_DB_DIR = "./chroma_db"
MITRE_FILE = "enterprise-attack.json"
EMBEDDING_MODEL = "all-mpnet-base-v2"

# Global variables
rag_chain = None
llm = None


# --- Data Loader (Unchanged) ---
def load_mitre_data(filepath):
    print(f"   Parsing '{filepath}'...")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        objects = data.get('objects', [])
        attack_patterns = [
            obj for obj in objects
            if obj.get('type') == 'attack-pattern' and not obj.get('revoked')
        ]

        documents = []
        for obj in attack_patterns:
            technique_id = obj.get('external_references', [{}])[0].get('external_id', 'Unknown')
            technique_name = obj.get('name', 'Unknown')

            metadata = {
                "source": technique_id,
                "name": technique_name,
                "url": obj.get('external_references', [{}])[0].get('url', ''),
                "platforms": ", ".join(obj.get('x_mitre_platforms', ['Unknown'])),
                "tactics": ", ".join(t.replace('-', ' ') for t in obj.get('x_mitre_kill_chain_phases', []))
            }

            text_content = f"Technique: {technique_name} (ID: {technique_id})\nDescription: {obj.get('description')}\nTactics: {metadata['tactics']}\nPlatforms: {metadata['platforms']}"

            documents.append(Document(page_content=text_content, metadata=metadata))

        return documents
    except Exception as e:
        print(f"❌ Error parsing JSON: {e}")
        return []


# --- Startup Event (Unchanged) ---
@app.on_event("startup")
async def startup_event():
    global llm, rag_chain
    print("--- Initializing SOC Backend v5.5 (Robust IoC) ---")

    llm = ChatOllama(model=MODEL_NAME, temperature=0)
    print(f"✅ LLM '{MODEL_NAME}' ready.")

    print(f"📚 Loading Embeddings ({EMBEDDING_MODEL})...")
    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)

    if os.path.exists(VECTOR_DB_DIR) and os.listdir(VECTOR_DB_DIR):
        print("📂 Loading Vector Database...")
        vectorstore = Chroma(persist_directory=VECTOR_DB_DIR, embedding_function=embeddings)
    else:
        print(f"⚠️  Vector DB not found! Building from '{MITRE_FILE}'...")
        if not os.path.exists(MITRE_FILE):
            print(f"❌ FATAL: '{MITRE_FILE}' not found. Please download it and restart.")
            return

        docs = load_mitre_data(MITRE_FILE)
        if not docs:
            print(f"❌ FATAL: Could not load MITRE data.")
            return

        print(f"   Loaded {len(docs)} techniques. Splitting...")
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        splits = text_splitter.split_documents(docs)

        print(f"   Embedding {len(splits)} chunks... (This may take ~1-2 min on CPU)")
        vectorstore = Chroma.from_documents(
            documents=splits,
            embedding=embeddings,
            persist_directory=VECTOR_DB_DIR
        )
        print("✅ Database built successfully.")

    rag_prompt_template = """
    You are an AI SOC Analyst. Use the following context to answer the user's question concisely.
    Do NOT include the raw "Content:" or "(Citation: ...)" parts in your answer.
    Answer the question directly and professionally based on the context.

    CONTEXT:
    {summaries}

    QUESTION:
    {question}

    ANSWER:
    """
    RAG_PROMPT = PromptTemplate.from_template(rag_prompt_template)

    rag_chain = RetrievalQAWithSourcesChain.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever=vectorstore.as_retriever(search_kwargs={"k": 3}),
        chain_type_kwargs={"prompt": RAG_PROMPT}
    )
    print("✅ RAG System (with Sources) Online.")


# --- API Endpoints ---
class ChatRequest(BaseModel):
    query: str
    chat_history: List[Dict[str, str]] = []


@app.post("/api/chat")
async def chat_endpoint(request: ChatRequest):
    if not rag_chain:
        return {"response": "⚠️ System not ready. Check server logs."}

    try:
        payload = {"question": request.query}
        result = await run_in_threadpool(rag_chain.invoke, payload)

        sources_list = []
        if result.get("sources"):
            sources_list = result["sources"].split(", ")

        return {
            "response": result['answer'],
            "sources": sources_list
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class FollowupRequest(BaseModel):
    chat_history: List[Dict[str, str]]


@app.post("/api/followup", response_model=List[str])
async def followup_endpoint(request: FollowupRequest):
    if not llm:
        return []

    history_str = "\n".join([f"{msg['role']}: {msg['text']}" for msg in request.chat_history])

    prompt_template = f"""
    Based on this conversation, suggest 3 concise follow-up questions a security analyst might ask.

    CONVERSATION:
    {history_str}

    Return ONLY a numbered list.
    EXAMPLE:
    1. What are the mitigation steps?
    2. How do I detect this?
    3. Which platforms are affected?
    """

    try:
        parser = StrOutputParser()
        prompt = PromptTemplate.from_template(prompt_template)
        chain = prompt | llm | parser

        result_text = await run_in_threadpool(chain.invoke, {})

        questions = []
        if result_text:
            lines = [line.strip() for line in result_text.split('\n')]
            for line in lines:
                if (line.startswith(tuple(f"{i}." for i in range(1, 10))) or line.startswith("*") or line.startswith(
                        "-")):
                    question = line.split('.', 1)[-1].strip().lstrip('*- ')
                    if question:
                        questions.append(question)

        return questions
    except Exception as e:
        print(f"❌ Follow-up error: {e}")
        return []


@app.post("/api/summarize")
async def summarize_endpoint(file: UploadFile = File(...)):
    temp_path = f"temp_{file.filename}"
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        loader = PyPDFLoader(temp_path)
        docs = loader.load()

        text_splitter = RecursiveCharacterTextSplitter(chunk_size=8000, chunk_overlap=200)
        split_docs = text_splitter.split_documents(docs)

        map_prompt = """
        You are a Cyber Threat Intel Analyst. Extract key threat details from this section:
        "{text}"
        Focus on: Threat Actors, Malware, Targeted Industries, and IoCs (IPs, Hashes).
        """
        map_prompt_template = PromptTemplate(template=map_prompt, input_variables=["text"])

        combine_prompt = """
        Combine these notes into a single Executive Threat Brief:
        "{text}"

        FORMAT:
        ## 🚨 THREAT INTEL BRIEF
        **1. Adversaries:** [Who]
        **2. Malware:** [What]
        **3. Targets:** [Where]
        **4. Key IoCs:** [Indicators]
        """
        combine_prompt_template = PromptTemplate.from_template(combine_prompt, input_variables=["text"])

        chain = load_summarize_chain(
            llm,
            chain_type="map_reduce",
            map_prompt=map_prompt_template,
            combine_prompt=combine_prompt_template,
            verbose=False
        )

        summary = await run_in_threadpool(chain.invoke, split_docs)
        return {"summary": summary['output_text']}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# --- IoC Extractor Endpoint (FIXED v5.5) ---

class ExtractRequest(BaseModel):
    text: str


class IoCResponse(BaseModel):
    ips: List[str]
    domains: List[str]
    hashes_md5: List[str]
    hashes_sha256: List[str]
    cves: List[str]


@app.post("/api/extract", response_model=IoCResponse)
async def extract_endpoint(request: ExtractRequest):
    text = request.text

    try:
        # Regex to find all potential IoCs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        domains = re.findall(r'\b[a-zA-Z0-9-]{2,}\.[a-zA-Z]{2,}\b', text)
        hashes_md5 = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
        hashes_sha256 = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
        cves = re.findall(r'\bCVE-\d{4}-\d{4,7}\b', text)

        # --- Simple Python Filtering (FIXED) ---
        ip_blacklist = {'8.8.8.8', '1.1.1.1', '1.0.0.1', '1.0.0.0'}
        domain_blacklist = {'google.com', 'example.com', 'microsoft.com', 'github.com'}
        hash_blacklist = {'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}  # Empty file hash
        cve_blacklist = {'CVE-2025-12345'}
        file_extensions_blacklist = {'.exe', '.dll', '.py', '.js', '.ps1', '.bat', '.sh', '.pdf', '.doc', '.docx'}

        # Use set comprehension for fast, unique, filtered results
        final_ips = list(set(
            ip for ip in ips
            if ip not in ip_blacklist and not ip.startswith('192.168.') and not ip.startswith('10.')
        ))

        final_domains = list(set(
            d.lower() for d in domains
            if
            d.lower() not in domain_blacklist and not any(d.lower().endswith(ext) for ext in file_extensions_blacklist)
        ))

        final_md5 = list(set(h.lower() for h in hashes_md5))

        final_sha256 = list(set(
            h.lower() for h in hashes_sha256
            if h.lower() not in hash_blacklist
        ))

        # FIX: Strip punctuation (like commas or periods) from CVEs before checking blacklist
        final_cves = list(set(
            c.strip('.,!?;') for c in cves
            if c.strip('.,!?;') not in cve_blacklist
        ))

        return IoCResponse(
            ips=final_ips,
            domains=final_domains,
            hashes_md5=final_md5,
            hashes_sha256=final_sha256,
            cves=final_cves
        )

    except Exception as e:
        print(f"❌ IoC extraction error: {e}")
        raise HTTPException(status_code=500, detail="Error during IoC extraction")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
