<div align="center">

<img src="penagent_logo.svg" width="300" alt="PenAgent Logo"/>

# PenAgent

**Autonomous Penetration Testing Agent**

![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-research%20prototype-yellow?style=flat-square)
![Target](https://img.shields.io/badge/use-authorized%20labs%20only-red?style=flat-square)
![LLM](https://img.shields.io/badge/LLM-Claude%20Sonnet-purple?style=flat-square)

</div>

---

> ⚠️ **Legal Notice:** PenAgent is a research prototype built for authorized lab environments only. All development and testing was performed against Metasploitable2 and HackTheBox lab targets. Unauthorized use against systems you do not own or have explicit written permission to test is illegal.

---

## What is PenAgent?

PenAgent is an agentic, retrieval-augmented LLM system that automates the full penetration testing workflow. Give it an nmap XML scan — it handles everything from there.

```
nmap -sV -Pn -oX scan.xml <target_ip>
python3 main.py --scan scan.xml --output report.md --shell
```

```
 ____  ___  _  _    __    ___  ____  _  _  ____
(  _ \( __)( \( )  /__\  / __)( ___)( \( )(_  _)
 ) __/ ) _)  ) \( /(__)\( (_ \ ) _)  ) \(  )(
(____)(____)(_)\_)(__)(__)\___)(____)(_)\_)(__)

◆ PHASE 1  PARSE       Loading scan.xml
◆ PHASE 2  RETRIEVE    Querying RAG knowledge base + NVD CVE API
◆ PHASE 3  EXECUTE     LangChain ReAct agent → Metasploit RPC
  [+] Shell opened on 192.168.211.128:6200 — uid=0(root)
◆ PHASE 4  REPORT      Writing findings to report.md

  [+] ROOT SHELL ACQUIRED  192.168.211.128
      uid=0(root) gid=0(root) groups=0(root)
```

---

## How It Works

1. **Parse** — reads nmap XML into structured host/port/service/version data
2. **Retrieve** — hybrid RAG (ChromaDB + BM25) searches 47,405 indexed chunks from PayloadsAllTheThings + ExploitDB, plus live NIST NVD CVE lookup
3. **Execute** — LangChain ReAct agent autonomously calls Metasploit RPC, iterates until exploitation succeeds or exhausts options
4. **Report** — Claude Sonnet synthesizes all findings into a professional pentest report with CVSS scores, CVE references, exploitation evidence, and remediation steps

---

## Architecture

```
nmap XML
   │
   ▼
parser.py              ← host / port / service / version extraction
   │
   ▼
agent.py               ← LangChain ReAct agent (create_react_agent)
   ├── tools/retriever.py     ← ChromaDB + BM25 hybrid RAG
   ├── tools/cve_lookup.py    ← NIST NVD REST API v2.0
   └── tools/msf_exec.py      ← pymetasploit3 → msfrpcd
   │
   ▼
reporter.py            ← Claude Sonnet generates structured report
   │
   ▼
report.md  +  optional root shell
```

---

## Tech Stack

| Component        | Technology                                        |
|------------------|---------------------------------------------------|
| LLM              | Claude Sonnet 4 (Anthropic API)                   |
| Agent framework  | LangChain ReAct (`create_react_agent`)            |
| Vector store     | ChromaDB                                          |
| Keyword search   | BM25 (hybrid retrieval)                           |
| Embeddings       | `sentence-transformers/all-MiniLM-L6-v2`          |
| Exploitation     | `pymetasploit3` → `msfrpcd` RPC daemon            |
| CVE lookup       | NIST NVD REST API v2.0                            |
| CLI interface    | `rich` (styled terminal output)                   |
| Knowledge base   | PayloadsAllTheThings + ExploitDB (47,405 chunks)  |

---

## Installation

### Prerequisites
- Kali Linux (or Debian-based with Metasploit installed)
- Python 3.10+
- Metasploit Framework
- Anthropic API key

### Setup

```bash
git clone https://github.com/Jbuhrer/PenAgent.git
cd PenAgent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configure environment

```bash
cp .env.example .env
# Edit .env and fill in your values
```

```env
ANTHROPIC_API_KEY=sk-ant-...
MSF_PASSWORD=yourpassword
MSF_HOST=127.0.0.1
MSF_PORT=55553
```

### Build the knowledge base

```bash
python3 build_index.py
```

### Start Metasploit RPC daemon

```bash
msfrpcd -P yourpassword -S -f
```

---

## Usage

```bash
# Scan target
nmap -sV -Pn -oX scan.xml <target_ip>

# Run PenAgent
python3 main.py --scan scan.xml --output report.md --shell
```

### Flags

| Flag            | Description                                         |
|-----------------|-----------------------------------------------------|
| `--scan`        | Path to nmap XML file (required)                    |
| `--output`      | Output report filename (default: `report.md`)       |
| `--shell`       | Drop into interactive shell after exploitation      |
| `--shell-port`  | Manually specify shell port (overrides auto-detect) |

---

## Results

Tested against Metasploitable2 (Linux) and HackTheBox Archetype (Windows/MSSQL):

| Target          | Time     | Findings | Shell          |
|-----------------|----------|----------|----------------|
| Metasploitable2 | ~3.5 min | 9        | root@metasploitable |
| HTB Archetype   | ~4 min   | 3        | NT AUTHORITY\SYSTEM |

Compared against PentestGPT (USENIX 2024): both achieved root on Metasploitable2, but PentestGPT produced only a CTF-style summary vs. PenAgent's structured professional report with CVSS scores, CVE references, and remediation guidance.

---

## Project Structure

```
PenAgent/
├── main.py              ← CLI entry point
├── banner.py            ← Terminal UI (rich)
├── parser.py            ← nmap XML parser
├── agent.py             ← LangChain ReAct agent
├── reporter.py          ← Claude report generator
├── build_index.py       ← Knowledge base builder
├── tools/
│   ├── retriever.py     ← ChromaDB + BM25 hybrid search
│   ├── cve_lookup.py    ← NIST NVD API
│   └── msf_exec.py      ← Metasploit RPC
├── .env.example
├── requirements.txt
└── README.md
```

---

## References

- Yao et al. (2023). ReAct: Synergizing Reasoning and Acting in Language Models. ICLR.
- Lewis et al. (2020). Retrieval-Augmented Generation for NLP Tasks. NeurIPS.
- Deng et al. (2023). PentestGPT: An LLM-Empowered Automatic Penetration Testing Tool. arXiv:2308.06782.
- NIST NVD: https://nvd.nist.gov
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

---

## License

MIT

*Built for CSC 7644 (LLM Application Development) — Louisiana State University*
