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

> The **Scan URL UI was intentionally removed**.  
> The extractor currently accepts text only (to avoid missing-backend endpoint errors).

### 🔐 Fully Local
No cloud APIs.  
No external LLM calls.  
Everything is processed inside your system.

---


