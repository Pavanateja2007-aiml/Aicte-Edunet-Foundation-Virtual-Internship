> **AICTE–Edunet Foundation Virtual Internship Project**  
> An AI-powered network port scanner with real-time security analysis, built with Python, Tkinter, and the Anthropic Claude API.

---

## 👤 Intern Details

| Field | Value |
|---|---|
| **Name** | VEMURI VENKATA SATYA MARKANDEYA PAVANATEJA |
| **Student ID** | STU697054b4b297d1768969396 |
| **AICTE ID** | AICTE B3 OL 2001-4087-1884 |
| **Internship ID** | INTERNSHIP\_17703809656985dea55aec7 |

---

## 📌 Project Overview

NetRecon AI is a two-phase project developed during the AICTE–Edunet Foundation Virtual Internship:

1. **Phase 1 — Basic Port Scanner GUI** (`portscanergui.py`): A lightweight TCP port scanner with a clean Tkinter GUI, multi-threading, and service identification for common ports.

2. **Phase 2 — AI-Upgraded Scanner** (`ai_upgraded_port_scaner_gui.py`): A fully dark-themed, production-grade tool that integrates Claude Sonnet (claude-sonnet-4-20250514) for live, streamed security analysis and an interactive AI chat interface for follow-up questions.

---

## ✨ Features

### Basic Version (`portscanergui.py`)
- Simple 3-field interface — target host, start port, end port
- Multi-threaded scanning (up to 500 concurrent threads)
- Service identification for well-known ports (FTP, SSH, HTTP, HTTPS, MySQL, RDP, etc.)
- Real-time progress bar and elapsed-time counter
- Stop a scan gracefully at any time
- Save results to a `.txt` file
- Cross-platform (Windows, macOS, Linux)

### AI-Upgraded Version (`ai_upgraded_port_scaner_gui.py`)

Everything in the basic version, **plus**:

- **Dark hacker-style GUI** — Custom dark theme (`#0d1117` GitHub dark palette) with color-coded risk output
- **Extended service map** — 50+ ports recognized (Docker, Redis, Elasticsearch, MongoDB, Kubernetes, Jupyter, and more)
- **Risk classification** — Ports automatically tagged as `HIGH RISK`, `MEDIUM`, or `LOW`
- **AI Security Analysis** — One-click Claude Sonnet analysis delivering:
  - Executive risk overview (CRITICAL / HIGH / MEDIUM / LOW / MINIMAL)
  - Port-by-port security implications and attack vectors
  - Prioritized remediation recommendations
  - Compliance notes (PCI-DSS, HIPAA, SOC2)
- **Streaming output** — AI analysis streams in real time (no waiting for a full response)
- **AI Chat** (`Ask AI` tab) — Follow-up Q&A with Claude, context-aware of your scan results
- **Configurable scanning** — Adjustable thread count and per-connection timeout
- **Export** — Save scan data + full AI analysis to a single `.txt` report

---

## 🗂 Project Structure

```
Aicte-Edunet-Foundation-Virtual-Internship/
├── portscanergui.py                    # Phase 1 – Basic port scanner GUI
├── ai_upgraded_port_scaner_gui.py      # Phase 2 – AI-powered scanner (NetRecon AI)
├── netrecon_ai_port_scanner_mockup/    # HTML mockup / UI prototype
└── README.md
```

---

## ⚙️ Requirements

### Basic version
- Python 3.7+
- `tkinter` (included in standard Python; on Debian/Ubuntu: `sudo apt install python3-tk`)
- No third-party packages required

### AI-upgraded version
- Python 3.7+
- `tkinter`
- An **Anthropic API key** (get one at [console.anthropic.com](https://console.anthropic.com))
- Internet connection (for Claude API calls)
- No additional pip packages required — all API calls use the built-in `urllib` module

---

## 🚀 Installation

```bash
git clone https://github.com/Pavanateja2007-aiml/Aicte-Edunet-Foundation-Virtual-Internship.git
cd Aicte-Edunet-Foundation-Virtual-Internship
```

---

## ▶️ Usage

### Run the basic scanner
```bash
python portscanergui.py
```

### Run the AI-powered scanner
```bash
python ai_upgraded_port_scaner_gui.py
```

On first launch, you will be prompted to enter your Anthropic API key. The key is stored in memory for the session only.

### Step-by-step walkthrough

1. Enter the **Target** — an IP address (e.g. `192.168.1.1`) or hostname (e.g. `scanme.nmap.org`).
2. Set **Start Port** and **End Port** (defaults: `1` – `1024`).
3. Optionally adjust **Threads** (default 500) and **Timeout** in seconds (default 0.5).
4. Click **▶ Scan**. Open ports appear in real time in the **📡 Scan Results** tab, color-coded by risk level.
5. Click **■ Stop** to cancel early.
6. After the scan, switch to the **🤖 AI Analysis** tab and click **⚡ Analyze with AI** for a streamed Claude security report.
7. Switch to the **💬 Ask AI** tab to ask follow-up questions about the scan (e.g., *"How do I close port 6379?"*, *"Is this machine PCI-DSS compliant?"*).
8. Click **💾 Save Results** to export the scan + AI analysis to a `.txt` file.

---

## 🔍 Detected Services

The AI version recognizes 50+ services. The core set includes:

| Port | Service | Risk |
|---|---|---|
| 21 | FTP | 🔴 HIGH |
| 22 | SSH | 🟢 LOW |
| 23 | Telnet | 🔴 HIGH |
| 25 | SMTP | 🟢 LOW |
| 53 | DNS | 🟢 LOW |
| 80 | HTTP | 🟡 MEDIUM |
| 110 | POP3 | 🟡 MEDIUM |
| 139 / 445 | NetBIOS / SMB | 🔴 HIGH |
| 143 | IMAP | 🟡 MEDIUM |
| 443 | HTTPS | 🟢 LOW |
| 1433 | MSSQL | 🔴 HIGH |
| 3306 | MySQL | 🔴 HIGH |
| 3389 | RDP | 🟡 MEDIUM |
| 4444 | Metasploit | 🔴 HIGH |
| 5900 | VNC | 🔴 HIGH |
| 6379 | Redis | 🔴 HIGH |
| 8080 | HTTP-Alt | 🟡 MEDIUM |
| 8888 | Jupyter | 🟡 MEDIUM |
| 9200 | Elasticsearch | 🔴 HIGH |
| 27017 | MongoDB | 🔴 HIGH |

Ports not in the map are reported as `Unknown` with `LOW` risk.

---

## 🤖 AI Analysis — How It Works

The AI-upgraded scanner sends your port scan results to **Claude Sonnet** (claude-sonnet-4-20250514) via the Anthropic Messages API using Server-Sent Events (SSE) for real-time streaming. The model receives:

- The target host and resolved IP
- A full list of open ports with service names and risk classifications
- Total scan duration

Claude then responds with a structured security report covering risk overview, port-by-port analysis, key vulnerabilities, remediation steps, and compliance notes.

The **AI Chat** tab maintains a running conversation history, so you can ask contextual follow-up questions without re-scanning.

---

## 🏗 Architecture

```
ScannerGUI (tk.Tk)
├── Header bar      — branding, API key status indicator
├── Input panel     — target, port range, threads, timeout
├── Progress bar    — live scan progress
├── Notebook (tabs)
│   ├── 📡 Scan Results  — color-coded terminal-style output
│   ├── 🤖 AI Analysis   — streaming Claude security report
│   └── 💬 Ask AI        — multi-turn chat with scan context
└── Bottom bar      — Clear Scan / Save Results buttons

PortScanner (threading)
├── Semaphore-limited thread pool (default 500)
├── Queue-based result passing to GUI
└── Graceful stop via threading.Event

AnthropicClient
├── analyze_ports()  — initial security report (streaming SSE)
└── chat()           — follow-up Q&A (streaming SSE)
```

---

## 🛡 Disclaimer

Use this tool **only on hosts and networks you own or have explicit written permission to scan**. Unauthorized port scanning may violate computer fraud and abuse laws in your jurisdiction. This tool was developed strictly for educational purposes as part of the AICTE–Edunet Foundation Virtual Internship program.

---

## 📄 License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).

---

## 🙏 Acknowledgements

- **AICTE** and **Edunet Foundation** for providing the virtual internship opportunity
- **Anthropic** for the Claude API powering the AI security analysis
