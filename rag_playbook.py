import sys
import os
import json
import time
from langchain_text_splitters import RecursiveCharacterTextSplitter
# SWAPPED TO HUGGINGFACE (Runs inside Python, won't hang)
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.chains import RetrievalQA
from langchain_community.chat_models import ChatOllama
from langchain_core.documents import Document

# --- CONFIGURATION ---
MODEL_NAME = "phi3"  # <-- UPDATED
MITRE_FILE = "enterprise-attack.json"
DB_DIR = "chroma_db"


def load_mitre_data(filepath):
    print(f"   Parsing '{filepath}'...")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        objects = data.get('objects', [])
        # Filter for techniques
        attack_patterns = [
            obj for obj in objects
            if obj.get('type') == 'attack-pattern' and not obj.get('revoked')
        ]

        documents = []
        for obj in attack_patterns:
            text_content = f"Technique: {obj.get('name')}\nID: {obj.get('external_references', [{}])[0].get('external_id')}\nDescription: {obj.get('description')}"
            documents.append(Document(page_content=text_content, metadata={"source": filepath}))

        return documents
    except Exception as e:
        print(f"❌ Error parsing JSON: {e}")
        return []


def main():
    # 1. Setup
    if not os.path.exists(MITRE_FILE):
        print(f"❌ Error: '{MITRE_FILE}' not found.")
        return

    print(f"🤖 Initializing {MODEL_NAME} (for chatting)...")
    llm = ChatOllama(model=MODEL_NAME, temperature=0)

    print(f"📚 Initializing Embeddings (HuggingFace CPU Mode)...")
    # This runs locally in Python - no network calls, so it won't hang
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

    # 2. Check DB
    if os.path.exists(DB_DIR) and os.listdir(DB_DIR):
        print("📂 Loading existing Vector Database...")
        vectorstore = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)
    else:
        print("⚙️  Building Database (First Run)...")
        docs = load_mitre_data(MITRE_FILE)
        if not docs: return

        print(f"   Loaded {len(docs)} techniques. Splitting...")
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        splits = text_splitter.split_documents(docs)

        print(f"   Embedding {len(splits)} chunks... (Watch this happen fast!)")

        # Create DB
        start = time.time()
        vectorstore = Chroma.from_documents(
            documents=splits,
            embedding=embeddings,
            persist_directory=DB_DIR
        )
        print(f"✅ Database built in {time.time() - start:.2f} seconds!")

    # 3. Chat Loop
    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever=vectorstore.as_retriever(search_kwargs={"k": 3})
    )

    print("\n" + "=" * 50)
    print("🛡️  SOC ASSISTANT READY")
    print("=" * 50 + "\n")

    while True:
        query = input("User > ")
        if query.lower() in ['exit', 'quit']:
            break
        try:
            print("   Thinking...")
            response = qa_chain.invoke(query)
            print(f"\n🤖 Assistant:\n{response['result']}\n")
            print("-" * 50)
        except Exception as e:
            print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
