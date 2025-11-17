import sys
import os
import time

try:
    from langchain_community.document_loaders import PyPDFLoader

    # Try specific import first, then fallback to general
    try:
        from langchain.chains.summarize import load_summarize_chain
    except ImportError:
        from langchain.chains import load_summarize_chain

    from langchain_community.chat_models import ChatOllama
    from langchain.prompts import PromptTemplate
except ImportError as e:
    print("❌ IMPORT ERROR: Missing libraries.")
    print(f"Error details: {e}")
    print("Run this command to fix: pip install --force-reinstall langchain langchain-community langchain-ollama pypdf")
    sys.exit(1)

# --- CONFIGURATION ---
# If your laptop is slow, change "llama3" to "phi3"
MODEL_NAME = "phi3"  # <-- UPDATED


def main():
    # 1. Check for the PDF file argument
    if len(sys.argv) < 2:
        print("❌ Error: Please provide a PDF file.")
        print("Usage: python summarize_threat.py report.pdf")
        return

    pdf_path = sys.argv[1]

    if not os.path.exists(pdf_path):
        print(f"❌ Error: File '{pdf_path}' not found.")
        return

    print(f"📂 Loading '{pdf_path}'...")

    # 2. Load the PDF
    try:
        loader = PyPDFLoader(pdf_path)
        docs = loader.load()
        print(f"✅ Loaded {len(docs)} pages.")
    except Exception as e:
        print(f"❌ Error loading PDF: {e}")
        return

    # 3. Initialize the Intelligence
    print(f"🤖 Initializing {MODEL_NAME} (CPU Mode)...")
    try:
        llm = ChatOllama(model=MODEL_NAME, temperature=0)
    except Exception as e:
        print(f"❌ Error starting Ollama: {e}")
        print("Make sure Ollama is running!")
        return

    # 4. Define the Analyst Prompts
    map_prompt = """
    You are a Cyber Threat Intelligence Analyst. Read this section of a report:
    "{text}"

    Extract only the following technical details (if present):
    - Threat Actor Names (e.g., APT29)
    - Malware Names
    - Targeted Industries
    - Indicators of Compromise (IoCs): IPs, Domains, Hashes

    If no intelligence is found, say "None".
    Summary:
    """
    map_prompt_template = PromptTemplate(template=map_prompt, input_variables=["text"])

    combine_prompt = """
    You are a Senior Threat Analyst. Combine these extracted notes into a Final Intelligence Brief.

    NOTES:
    "{text}"

    FORMAT YOUR REPORT AS FOLLOWS:

    ## 🚨 EXECUTIVE THREAT BRIEF

    **1. ADVERSARIES & TARGETS**
    * [List Actors and who they target]

    **2. MALWARE & TOOLS**
    * [List malware families]

    **3. INDICATORS OF COMPROMISE (IoCs)**
    * [List IPs, Domains, and Hashes. Important: If none are found, state "No IoCs detected in this document".]

    **4. KEY FINDINGS**
    * [Brief summary of the attack chain]
    """
    combine_prompt_template = PromptTemplate(template=combine_prompt, input_variables=["text"])

    # 5. Run the Analysis
    print("🧠 Reading and analyzing document... (This may take 1-3 minutes on CPU)")
    start_time = time.time()

    try:
        chain = load_summarize_chain(
            llm,
            chain_type="map_reduce",
            map_prompt=map_prompt_template,
            combine_prompt=combine_prompt_template,
            verbose=True
        )

        result = chain.invoke(docs)

        end_time = time.time()
        duration = end_time - start_time

        # 6. Output Results
        print("\n" + "=" * 60)
        print(result['output_text'])
        print("=" * 60)
        print(f"✅ Analysis complete in {duration:.2f} seconds.")

        # Save to file
        with open("analysis_report.md", "w", encoding="utf-8") as f:
            f.write(result['output_text'])
        print("📄 Saved to 'analysis_report.md'")

    except Exception as e:
        print(f"❌ Error during analysis: {e}")


if __name__ == "__main__":
    main()
