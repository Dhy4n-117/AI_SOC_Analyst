# 🚨 AI SOC Analyst — Local Threat Intelligence Assistant

**AI SOC Analyst** is a lightweight, privacy-first security analysis assistant built for SOC analysts, threat hunters, and CTI teams.  
It runs **entirely on your local machine**, providing:

- 🧠 MITRE ATT&CK–aware Threat Chat (RAG)
- 📄 Automated PDF threat-report summarization
- 🧩 IoC extraction from raw text  
- 🔒 Zero cloud dependencies — no data ever leaves your device

Built with a compact **FastAPI backend** and a **single-file React frontend**, it delivers real-world analyst workflows with minimal setup.

---

## 🌟 Features

### ⚡ Threat Chat (MITRE-Enhanced)
Ask questions about ATT&CK techniques, malware behavior, adversary TTPs, and receive **context-augmented answers** using your local MITRE dataset.

### 📘 Report Summarization
Upload a CTI report (PDF) and instantly generate a structured summary highlighting key insights, IoCs, and analyst-relevant points.

### 🔍 IoC Extractor (*Text-Only Mode*)
Paste any raw text — logs, phishing content, forum dumps, malware notes — and extract:

- IPv4 / IPv6  
- Domains  
- MD5 & SHA-256 hashes  
- CVEs  


### 🔐 Fully Local
No cloud APIs.  
No external LLM calls.  
Everything is processed inside your system.

---

# 🚀 Running AI SOC Analyst

This guide explains exactly how to run the **backend** and **frontend** for AI SOC Analyst on your local machine.

---

# 📦 Prerequisites for AI SOC Analyst:

Installing Phi-3 or LLaMA 3: Using Ollama (easiest)
  > Install Ollama: https://ollama.com/download
  > Then pull Phi-3// or llama3:
  ``` 
     ollama pull phi3  
  ```
  > Update your backend to use Ollama’s endpoint:
  ```
    LLM_SOURCE = "ollama"
    MODEL_NAME = "phi3"
  ```
---

# 📁 Required Dataset (IMPORTANT)

AI SOC Analyst uses the **MITRE ATT&CK Enterprise dataset** to provide accurate, RAG-enhanced threat intelligence answers.

### ✅ Required file: enterprise-attack.json

### 📥 Download from MITRE:
Official ATT&CK dataset:  
🔗 https://attack.mitre.org/resources/working-with-attack/

Download the **“Enterprise ATT&CK JSON”** file.

### 📌 Where to place it:
Put the downloaded file **in the same directory as backend.py

### 🔍 Why it’s required:
- Enables MITRE ATT&CK lookups  
- Allows the assistant to cite TTPs and IDs  
- Powers the RAG-based Threat Chat  

### ⚠️ If the dataset is missing:
- The backend will start, but Threat Chat will NOT return MITRE-backed responses  
- You may see warnings or reduced accuracy  

Make sure the file exists before running the backend.

---
