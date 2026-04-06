import socket
import threading
import time
import queue
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import urllib.request
import urllib.error

# ---------------------------
# Service Map (extended)
# ---------------------------
COMMON_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    69: 'TFTP', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
    119: 'NNTP', 123: 'NTP', 135: 'MSRPC', 137: 'NetBIOS',
    139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 194: 'IRC',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    500: 'IPSec', 514: 'Syslog', 587: 'SMTP-Sub', 631: 'IPP',
    636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS',
    1194: 'OpenVPN', 1433: 'MSSQL', 1521: 'Oracle',
    1723: 'PPTP', 2049: 'NFS', 2181: 'ZooKeeper',
    2375: 'Docker', 2376: 'Docker-TLS', 3000: 'Dev-Server',
    3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit',
    5000: 'Flask/Dev', 5432: 'PostgreSQL', 5672: 'RabbitMQ',
    5900: 'VNC', 5985: 'WinRM', 6379: 'Redis',
    6443: 'K8s-API', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'Jupyter', 9200: 'Elasticsearch', 9300: 'Elasticsearch',
    27017: 'MongoDB', 27018: 'MongoDB', 50000: 'SAP',
}

# Risk levels per service
HIGH_RISK_PORTS = {23, 21, 69, 135, 137, 139, 445, 4444, 5900, 1433, 3306, 27017, 6379, 9200, 2375}
MEDIUM_RISK_PORTS = {80, 110, 143, 161, 3389, 5432, 5985, 8080, 8888}

# ---------------------------
# Anthropic API Client
# ---------------------------
class AnthropicClient:
    API_URL = "https://api.anthropic.com/v1/messages"
    MODEL = "claude-sonnet-4-20250514"

    def __init__(self, api_key):
        self.api_key = api_key

    def analyze_ports(self, target, resolved_ip, open_ports, scan_duration, callback):
        """
        Sends port data to Claude for analysis.
        callback(text_chunk, is_done, error) called repeatedly.
        """
        if not open_ports:
            port_desc = "No open ports were found."
        else:
            port_lines = "\n".join(
                f"  Port {p} ({s}) - Risk: {'HIGH' if p in HIGH_RISK_PORTS else 'MEDIUM' if p in MEDIUM_RISK_PORTS else 'LOW'}"
                for p, s in sorted(open_ports)
            )
            port_desc = f"Open ports discovered:\n{port_lines}"

        prompt = f"""You are a professional network security analyst. Analyze the following port scan results and provide a detailed security assessment.

Target: {target} ({resolved_ip})
Scan Duration: {scan_duration:.1f}s
{port_desc}

Provide your analysis in this exact structure:

## 🛡 Risk Overview
A 2-3 sentence executive summary with an overall risk rating: CRITICAL / HIGH / MEDIUM / LOW / MINIMAL

## 🔍 Port-by-Port Analysis
For each open port, explain what the service does and its security implications. Be specific about attack vectors.

## ⚠️ Key Vulnerabilities & Concerns
List the most important security concerns found, ordered by severity.

## ✅ Recommendations
Actionable remediation steps, prioritized by urgency.

## 📋 Compliance Notes
Any relevant compliance considerations (PCI-DSS, HIPAA, SOC2, etc.) based on exposed services.

Be concise, technical, and actionable. Use bullet points where appropriate."""

        payload = {
            "model": self.MODEL,
            "max_tokens": 1500,
            "stream": True,
            "messages": [{"role": "user", "content": prompt}]
        }

        def run():
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    self.API_URL,
                    data=data,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=60) as resp:
                    buffer = b""
                    for raw_chunk in resp:
                        buffer += raw_chunk
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            line = line.strip()
                            if not line:
                                continue
                            if line.startswith(b"data:"):
                                data_str = line[5:].strip()
                                if data_str == b"[DONE]":
                                    continue
                                try:
                                    event = json.loads(data_str)
                                    if event.get("type") == "content_block_delta":
                                        delta = event.get("delta", {})
                                        if delta.get("type") == "text_delta":
                                            callback(delta.get("text", ""), False, None)
                                except json.JSONDecodeError:
                                    pass
                callback("", True, None)
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")
                try:
                    err_json = json.loads(body)
                    msg = err_json.get("error", {}).get("message", body)
                except Exception:
                    msg = body
                callback("", True, f"API Error {e.code}: {msg}")
            except Exception as e:
                callback("", True, str(e))

        threading.Thread(target=run, daemon=True).start()

    def chat(self, messages, callback):
        """Generic chat call for follow-up questions."""
        payload = {
            "model": self.MODEL,
            "max_tokens": 800,
            "stream": True,
            "messages": messages
        }

        def run():
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    self.API_URL,
                    data=data,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=60) as resp:
                    buffer = b""
                    for raw_chunk in resp:
                        buffer += raw_chunk
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            line = line.strip()
                            if not line or not line.startswith(b"data:"):
                                continue
                            data_str = line[5:].strip()
                            if data_str == b"[DONE]":
                                continue
                            try:
                                event = json.loads(data_str)
                                if event.get("type") == "content_block_delta":
                                    delta = event.get("delta", {})
                                    if delta.get("type") == "text_delta":
                                        callback(delta.get("text", ""), False, None)
                            except json.JSONDecodeError:
                                pass
                callback("", True, None)
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")
                try:
                    msg = json.loads(body).get("error", {}).get("message", body)
                except Exception:
                    msg = body
                callback("", True, f"API Error {e.code}: {msg}")
            except Exception as e:
                callback("", True, str(e))

        threading.Thread(target=run, daemon=True).start()


# ---------------------------
# Scanner Worker
# ---------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=500):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()
        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                with self._lock:
                    self.open_ports.append((port, service))
                self.result_queue.put(('open', port, service))
            s.close()
        except Exception:
            pass
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def resolve_target(self):
        return socket.gethostbyname(self.target)

    def run(self):
        sem = threading.Semaphore(self.max_workers)
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        self.result_queue.put(('done', None, None))

    def _worker_wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()


# ---------------------------
# Theme & Style
# ---------------------------
DARK_BG      = "#0d1117"
DARK_PANEL   = "#161b22"
DARK_BORDER  = "#30363d"
ACCENT_GREEN = "#3fb950"
ACCENT_BLUE  = "#58a6ff"
ACCENT_RED   = "#f85149"
ACCENT_AMBER = "#d29922"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
FONT_MONO    = ("Courier New", 10)
FONT_MONO_LG = ("Courier New", 11)
FONT_UI      = ("Segoe UI", 10) if sys.platform == "win32" else ("Helvetica Neue", 10)
FONT_UI_SM   = ("Segoe UI", 9)  if sys.platform == "win32" else ("Helvetica Neue", 9)


# ---------------------------
# Styled Text Helpers
# ---------------------------
def apply_text_tags(widget):
    widget.tag_configure("header",   foreground=ACCENT_BLUE,  font=(FONT_MONO[0], 11, "bold"))
    widget.tag_configure("open",     foreground=ACCENT_GREEN, font=FONT_MONO)
    widget.tag_configure("high",     foreground=ACCENT_RED,   font=(FONT_MONO[0], 10, "bold"))
    widget.tag_configure("medium",   foreground=ACCENT_AMBER, font=FONT_MONO)
    widget.tag_configure("muted",    foreground=TEXT_MUTED,   font=FONT_MONO)
    widget.tag_configure("normal",   foreground=TEXT_PRIMARY, font=FONT_MONO)
    widget.tag_configure("ai_head",  foreground=ACCENT_BLUE,  font=(FONT_MONO[0], 11, "bold"))
    widget.tag_configure("ai_text",  foreground=TEXT_PRIMARY, font=FONT_MONO)
    widget.tag_configure("ai_code",  foreground=ACCENT_GREEN, font=FONT_MONO)
    widget.tag_configure("user_msg", foreground=ACCENT_AMBER, font=(FONT_MONO[0], 10, "bold"))
    widget.tag_configure("ai_msg",   foreground=ACCENT_BLUE,  font=(FONT_MONO[0], 10, "bold"))
    widget.tag_configure("error",    foreground=ACCENT_RED,   font=FONT_MONO)


# ---------------------------
# API Key Dialog
# ---------------------------
class APIKeyDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Anthropic API Key")
        self.configure(bg=DARK_BG)
        self.resizable(False, False)
        self.result = None
        self.grab_set()

        tk.Label(self, text="Enter your Anthropic API Key:", bg=DARK_BG, fg=TEXT_PRIMARY,
                 font=FONT_UI).pack(padx=20, pady=(20, 4))
        tk.Label(self, text="Get yours at: console.anthropic.com",
                 bg=DARK_BG, fg=TEXT_MUTED, font=FONT_UI_SM).pack(padx=20)

        self.ent = tk.Entry(self, width=52, show="*", bg=DARK_PANEL, fg=TEXT_PRIMARY,
                            insertbackground=TEXT_PRIMARY, font=FONT_MONO,
                            relief="flat", bd=1, highlightthickness=1,
                            highlightbackground=DARK_BORDER, highlightcolor=ACCENT_BLUE)
        self.ent.pack(padx=20, pady=12)
        self.ent.focus()

        frm = tk.Frame(self, bg=DARK_BG)
        frm.pack(pady=(0, 16))

        ok_btn = tk.Button(frm, text="Save Key", bg=ACCENT_BLUE, fg=DARK_BG, font=FONT_UI,
                           relief="flat", padx=14, pady=4, cursor="hand2",
                           command=self._ok)
        ok_btn.pack(side="left", padx=6)

        skip_btn = tk.Button(frm, text="Skip", bg=DARK_PANEL, fg=TEXT_MUTED, font=FONT_UI,
                             relief="flat", padx=14, pady=4, cursor="hand2",
                             command=self.destroy)
        skip_btn.pack(side="left", padx=6)

        self.bind("<Return>", lambda e: self._ok())

    def _ok(self):
        val = self.ent.get().strip()
        if val:
            self.result = val
        self.destroy()


# ---------------------------
# Main GUI
# ---------------------------
class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetRecon AI  |  Port Scanner + Security Analyst")
        self.geometry("920x700")
        self.minsize(800, 600)
        self.configure(bg=DARK_BG)

        self.scanner_thread = None
        self.scanner = None
        self.start_time = None
        self.resolved_ip = ""
        self.scan_duration = 0
        self.poll_after_ms = 40
        self.api_key = ""
        self.client = None
        self.chat_history = []
        self.ai_thinking = False

        self._setup_ttk_style()
        self._build_ui()
        self._prompt_api_key()

    # ----------------------------------------
    def _setup_ttk_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame",       background=DARK_BG)
        style.configure("TLabelframe",  background=DARK_PANEL,  foreground=ACCENT_BLUE,
                        bordercolor=DARK_BORDER, relief="flat")
        style.configure("TLabelframe.Label", background=DARK_PANEL, foreground=ACCENT_BLUE,
                        font=(FONT_UI[0], 10, "bold"))
        style.configure("TLabel",       background=DARK_PANEL,  foreground=TEXT_PRIMARY, font=FONT_UI)
        style.configure("TEntry",       fieldbackground=DARK_BG, foreground=TEXT_PRIMARY,
                        insertcolor=TEXT_PRIMARY, bordercolor=DARK_BORDER, font=FONT_MONO)
        style.configure("TButton",      background=DARK_BORDER, foreground=TEXT_PRIMARY, font=FONT_UI,
                        borderwidth=0, relief="flat", padding=(10, 5))
        style.map("TButton",
                  background=[("active", "#3d444d"), ("disabled", DARK_PANEL)],
                  foreground=[("disabled", TEXT_MUTED)])
        style.configure("Accent.TButton", background=ACCENT_GREEN, foreground=DARK_BG,
                        font=(FONT_UI[0], 10, "bold"), padding=(10, 5))
        style.map("Accent.TButton",
                  background=[("active", "#2da44e"), ("disabled", DARK_PANEL)])
        style.configure("AI.TButton", background=ACCENT_BLUE, foreground=DARK_BG,
                        font=(FONT_UI[0], 10, "bold"), padding=(10, 5))
        style.map("AI.TButton",
                  background=[("active", "#4493f8"), ("disabled", DARK_PANEL)])
        style.configure("Stop.TButton", background=ACCENT_RED, foreground=DARK_BG,
                        font=(FONT_UI[0], 10, "bold"), padding=(10, 5))
        style.map("Stop.TButton",
                  background=[("active", "#da3633"), ("disabled", DARK_PANEL)])
        style.configure("TProgressbar", background=ACCENT_GREEN, troughcolor=DARK_PANEL,
                        borderwidth=0, thickness=6)
        style.configure("TNotebook",    background=DARK_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=DARK_PANEL, foreground=TEXT_MUTED,
                        padding=(14, 6), font=FONT_UI)
        style.map("TNotebook.Tab",
                  background=[("selected", DARK_BG)],
                  foreground=[("selected", ACCENT_BLUE)])

    # ----------------------------------------
    def _build_ui(self):
        # Header bar
        hdr = tk.Frame(self, bg="#010409", height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="◈  NETRECON AI", bg="#010409", fg=ACCENT_GREEN,
                 font=("Courier New", 14, "bold")).pack(side="left", padx=16, pady=8)
        self.lbl_api_status = tk.Label(hdr, text="● API: Not configured",
                                       bg="#010409", fg=ACCENT_RED,
                                       font=("Courier New", 9))
        self.lbl_api_status.pack(side="right", padx=16)

        tk.Button(hdr, text="⚙ API Key", bg="#010409", fg=TEXT_MUTED,
                  font=FONT_UI_SM, relief="flat", cursor="hand2",
                  command=self._prompt_api_key).pack(side="right", padx=4)

        # Inputs
        frm_top = tk.Frame(self, bg=DARK_PANEL, pady=10)
        frm_top.pack(fill="x", padx=0)

        inner = tk.Frame(frm_top, bg=DARK_PANEL)
        inner.pack(padx=16, fill="x")

        def lbl(parent, text):
            return tk.Label(parent, text=text, bg=DARK_PANEL, fg=TEXT_MUTED, font=FONT_UI_SM)

        lbl(inner, "TARGET  (IP / Hostname)").grid(row=0, column=0, sticky="w", padx=(0,4))
        self.ent_target = self._entry(inner, width=30)
        self.ent_target.grid(row=1, column=0, padx=(0,16), sticky="ew")

        lbl(inner, "START PORT").grid(row=0, column=1, sticky="w")
        self.ent_start = self._entry(inner, width=10)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=1, column=1, padx=(0,8), sticky="ew")

        lbl(inner, "END PORT").grid(row=0, column=2, sticky="w")
        self.ent_end = self._entry(inner, width=10)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=1, column=2, padx=(0,16), sticky="ew")

        lbl(inner, "THREADS").grid(row=0, column=3, sticky="w")
        self.ent_threads = self._entry(inner, width=8)
        self.ent_threads.insert(0, "500")
        self.ent_threads.grid(row=1, column=3, padx=(0,8), sticky="ew")

        lbl(inner, "TIMEOUT (s)").grid(row=0, column=4, sticky="w")
        self.ent_timeout = self._entry(inner, width=8)
        self.ent_timeout.insert(0, "0.5")
        self.ent_timeout.grid(row=1, column=4, padx=(0,24), sticky="ew")

        self.btn_start = ttk.Button(inner, text="▶  Scan", style="Accent.TButton",
                                    command=self.start_scan)
        self.btn_start.grid(row=1, column=5, padx=(0,6))

        self.btn_stop = ttk.Button(inner, text="■  Stop", style="Stop.TButton",
                                   command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=1, column=6)

        for c in range(7):
            inner.grid_columnconfigure(c, weight=(1 if c < 5 else 0))

        # Status bar
        frm_st = tk.Frame(self, bg=DARK_BG, height=32)
        frm_st.pack(fill="x", padx=12, pady=(6, 0))
        frm_st.pack_propagate(False)

        self.var_status = tk.StringVar(value="Idle")
        tk.Label(frm_st, textvariable=self.var_status, bg=DARK_BG, fg=ACCENT_GREEN,
                 font=("Courier New", 9)).pack(side="left")

        self.var_elapsed = tk.StringVar(value="")
        tk.Label(frm_st, textvariable=self.var_elapsed, bg=DARK_BG, fg=TEXT_MUTED,
                 font=("Courier New", 9)).pack(side="right")

        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=12, pady=(2, 6))

        # Notebook (tabs)
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=12, pady=(0, 6))

        # Tab 1: Scan Results
        tab_scan = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(tab_scan, text="  📡 Scan Results  ")

        self.txt_results = tk.Text(tab_scan, bg=DARK_BG, fg=TEXT_PRIMARY,
                                   font=FONT_MONO_LG, wrap="none",
                                   insertbackground=TEXT_PRIMARY,
                                   selectbackground=DARK_BORDER,
                                   borderwidth=0, padx=12, pady=8)
        apply_text_tags(self.txt_results)
        self.txt_results.pack(fill="both", expand=True, side="left")

        ys = ttk.Scrollbar(tab_scan, orient="vertical", command=self.txt_results.yview)
        ys.pack(side="right", fill="y")
        self.txt_results.configure(yscrollcommand=ys.set)

        # Tab 2: AI Analysis
        tab_ai = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(tab_ai, text="  🤖 AI Analysis  ")

        # Top buttons for AI tab
        ai_controls = tk.Frame(tab_ai, bg=DARK_BG)
        ai_controls.pack(fill="x", pady=(8, 4), padx=12)

        self.btn_analyze = ttk.Button(ai_controls, text="⚡  Analyze with AI",
                                      style="AI.TButton",
                                      command=self.run_ai_analysis, state="disabled")
        self.btn_analyze.pack(side="left")

        tk.Label(ai_controls, text="  Powered by Claude claude-sonnet-4-20250514",
                 bg=DARK_BG, fg=TEXT_MUTED, font=FONT_UI_SM).pack(side="left", padx=8)

        self.btn_clear_ai = tk.Button(ai_controls, text="Clear", bg=DARK_PANEL, fg=TEXT_MUTED,
                                      font=FONT_UI_SM, relief="flat", cursor="hand2",
                                      command=self.clear_ai)
        self.btn_clear_ai.pack(side="right")

        self.txt_ai = tk.Text(tab_ai, bg=DARK_BG, fg=TEXT_PRIMARY, font=FONT_MONO,
                              wrap="word", insertbackground=TEXT_PRIMARY,
                              selectbackground=DARK_BORDER, borderwidth=0, padx=14, pady=10)
        apply_text_tags(self.txt_ai)
        self.txt_ai.pack(fill="both", expand=True, side="left")

        ys2 = ttk.Scrollbar(tab_ai, orient="vertical", command=self.txt_ai.yview)
        ys2.pack(side="right", fill="y")
        self.txt_ai.configure(yscrollcommand=ys2.set)

        # Tab 3: AI Chat
        tab_chat = tk.Frame(self.nb, bg=DARK_BG)
        self.nb.add(tab_chat, text="  💬 Ask AI  ")

        self.txt_chat = tk.Text(tab_chat, bg=DARK_BG, fg=TEXT_PRIMARY, font=FONT_MONO,
                                wrap="word", state="disabled",
                                selectbackground=DARK_BORDER, borderwidth=0, padx=14, pady=10)
        apply_text_tags(self.txt_chat)
        self.txt_chat.pack(fill="both", expand=True, side="left")

        ys3 = ttk.Scrollbar(tab_chat, orient="vertical", command=self.txt_chat.yview)
        ys3.pack(side="right", fill="y")
        self.txt_chat.configure(yscrollcommand=ys3.set)

        chat_input_frm = tk.Frame(self, bg=DARK_PANEL)
        chat_input_frm.pack(fill="x", padx=12, pady=(0, 8))

        self.ent_chat = tk.Entry(chat_input_frm, bg=DARK_BG, fg=TEXT_PRIMARY,
                                 insertbackground=TEXT_PRIMARY, font=FONT_MONO,
                                 relief="flat", bd=0)
        self.ent_chat.pack(side="left", fill="x", expand=True, padx=(10, 6), pady=8)
        self.ent_chat.bind("<Return>", lambda e: self.send_chat())

        self.btn_send = ttk.Button(chat_input_frm, text="Send ↵", style="AI.TButton",
                                   command=self.send_chat)
        self.btn_send.pack(side="right", padx=(0, 6), pady=6)

        # Bottom bar
        frm_bot = tk.Frame(self, bg=DARK_BG)
        frm_bot.pack(fill="x", padx=12, pady=(0, 8))

        self.btn_clear = tk.Button(frm_bot, text="Clear Scan", bg=DARK_PANEL, fg=TEXT_MUTED,
                                   font=FONT_UI_SM, relief="flat", cursor="hand2",
                                   command=self.clear_results)
        self.btn_clear.pack(side="left")

        self.btn_save = ttk.Button(frm_bot, text="💾  Save Results", command=self.save_results,
                                   state="disabled")
        self.btn_save.pack(side="right")

        self._append_welcome()

    # ----------------------------------------
    def _entry(self, parent, width=20):
        e = tk.Entry(parent, width=width, bg="#010409", fg=TEXT_PRIMARY,
                     insertbackground=TEXT_PRIMARY, font=FONT_MONO,
                     relief="flat", bd=1,
                     highlightthickness=1,
                     highlightbackground=DARK_BORDER,
                     highlightcolor=ACCENT_BLUE)
        return e

    def _append_welcome(self):
        self.txt_results.configure(state="normal")
        lines = [
            ("  ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗\n", "muted"),
            ("  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║\n", "header"),
            ("  ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║\n", "header"),
            ("  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║\n", "open"),
            ("  ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║\n", "open"),
            ("  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝\n", "muted"),
            ("\n", "normal"),
            ("  AI-Powered Port Scanner  •  claude-sonnet-4-20250514\n", "muted"),
            ("─" * 72 + "\n", "muted"),
            ("\n  Enter target, port range, then click ▶ Scan\n", "normal"),
            ("  After scan, use ⚡ Analyze with AI for security insights\n", "muted"),
        ]
        for text, tag in lines:
            self.txt_results.insert(tk.END, text, tag)
        self.txt_results.configure(state="disabled")

    # ----------------------------------------
    def _prompt_api_key(self):
        dlg = APIKeyDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            self.api_key = dlg.result
            self.client = AnthropicClient(self.api_key)
            self.lbl_api_status.configure(text="● API: Connected", fg=ACCENT_GREEN)
            if self.scanner and self.scanner.open_ports:
                self.btn_analyze.configure(state="normal")

    # ----------------------------------------
    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("NetRecon", "A scan is already running.")
            return

        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        try:
            start_port = int(self.ent_start.get().strip())
            end_port   = int(self.ent_end.get().strip())
            max_threads = int(self.ent_threads.get().strip())
            timeout     = float(self.ent_timeout.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Invalid port/thread/timeout values.")
            return

        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
            messagebox.showerror("Input Error", "Port range must be within 0–65535 and start ≤ end.")
            return

        self.scanner = PortScanner(target, start_port, end_port,
                                   timeout=timeout, max_workers=max_threads)
        try:
            self.resolved_ip = self.scanner.resolve_target()
        except Exception as e:
            messagebox.showerror("Resolution Error", f"Failed to resolve '{target}'\n{e}")
            self.scanner = None
            return

        self.txt_results.configure(state="normal")
        self.txt_results.delete("1.0", tk.END)
        self.txt_results.insert(tk.END, f"  Target  : {target} ({self.resolved_ip})\n", "header")
        self.txt_results.insert(tk.END, f"  Range   : {start_port} – {end_port}\n", "muted")
        self.txt_results.insert(tk.END, f"  Threads : {max_threads}   Timeout: {timeout}s\n", "muted")
        self.txt_results.insert(tk.END, "─" * 72 + "\n\n", "muted")
        self.txt_results.configure(state="disabled")

        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_save.configure(state="disabled")
        self.btn_analyze.configure(state="disabled")
        self.progress.configure(value=0, maximum=1)
        self.chat_history = []

        self.start_time = time.time()
        self.var_status.set("Scanning...")
        self.update_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()
        self.after(self.poll_after_ms, self.poll_results)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.var_status.set("Stopping...")

    def poll_results(self):
        if not self.scanner:
            return
        try:
            while True:
                msg_type, a, b = self.scanner.result_queue.get_nowait()
                if msg_type == 'open':
                    port, service = a, b
                    self.txt_results.configure(state="normal")
                    risk = "high" if port in HIGH_RISK_PORTS else ("medium" if port in MEDIUM_RISK_PORTS else "open")
                    risk_label = " ⚠ HIGH RISK" if risk == "high" else (" △ MEDIUM" if risk == "medium" else "")
                    self.txt_results.insert(tk.END, f"  [OPEN]  Port {port:>5}  {service:<18}{risk_label}\n", risk)
                    self.txt_results.configure(state="disabled")
                    self.txt_results.see(tk.END)
                elif msg_type == 'progress':
                    scanned, total = a, b
                    self.progress.configure(maximum=max(total, 1), value=scanned)
                    self.var_status.set(f"Scanning  {scanned}/{total}  ({len(self.scanner.open_ports)} open)")
                elif msg_type == 'done':
                    self._on_scan_done()
        except queue.Empty:
            pass

        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self.poll_results)
        else:
            self._on_scan_done()

    def _on_scan_done(self):
        if not self.scanner:
            return
        self.scan_duration = time.time() - self.start_time if self.start_time else 0
        n = len(self.scanner.open_ports)

        self.txt_results.configure(state="normal")
        self.txt_results.insert(tk.END, "\n" + "─" * 72 + "\n", "muted")
        self.txt_results.insert(tk.END, f"  Scan complete in {self.scan_duration:.2f}s  |  ", "muted")
        self.txt_results.insert(tk.END, f"{n} open port(s) found\n", "open" if n > 0 else "muted")
        if self.api_key:
            self.txt_results.insert(tk.END, "  → Switch to 🤖 AI Analysis tab and click ⚡ Analyze with AI\n", "header")
        self.txt_results.configure(state="disabled")

        self.var_status.set("Completed")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_save.configure(state="normal" if n else "disabled")
        if self.api_key:
            self.btn_analyze.configure(state="normal")
        self.start_time = None
        self.scanner_thread = None

    # ----------------------------------------
    # AI Analysis
    # ----------------------------------------
    def run_ai_analysis(self):
        if not self.client:
            messagebox.showerror("API Key Required", "Please configure your Anthropic API key first.")
            self._prompt_api_key()
            return
        if not self.scanner:
            messagebox.showinfo("No Data", "Run a scan first.")
            return

        self.btn_analyze.configure(state="disabled", text="⏳  Analyzing...")
        self.txt_ai.configure(state="normal")
        self.txt_ai.delete("1.0", tk.END)
        self.txt_ai.insert(tk.END, "Contacting Claude claude-sonnet-4-20250514...\n\n", "muted")
        self.nb.select(1)

        # Build initial context for chat
        port_summary = ", ".join(
            f"{p}/{s}" for p, s in sorted(self.scanner.open_ports)
        ) if self.scanner.open_ports else "none"

        self.chat_context = (
            f"You previously analyzed a port scan of {self.scanner.target} ({self.resolved_ip}). "
            f"Open ports: {port_summary}. "
            "Answer follow-up questions about this scan concisely."
        )

        def callback(chunk, done, error):
            self.after(0, lambda: self._ai_chunk(chunk, done, error, mode="analysis"))

        self.client.analyze_ports(
            self.scanner.target, self.resolved_ip,
            self.scanner.open_ports, self.scan_duration,
            callback
        )

    def _ai_chunk(self, chunk, done, error, mode="analysis"):
        if mode == "analysis":
            target_widget = self.txt_ai
        else:
            target_widget = self.txt_chat

        target_widget.configure(state="normal")

        if error:
            target_widget.insert(tk.END, f"\n[Error] {error}\n", "error")
        elif chunk:
            target_widget.insert(tk.END, chunk, "ai_text")
            target_widget.see(tk.END)

        if done:
            if mode == "analysis":
                self.btn_analyze.configure(state="normal", text="⚡  Analyze with AI")
                # Store full analysis in chat history
                full_text = target_widget.get("1.0", tk.END)
                self.chat_history = [
                    {"role": "user", "content": self.chat_context},
                    {"role": "assistant", "content": full_text.strip()}
                ]
            else:
                self.ai_thinking = False
                target_widget.insert(tk.END, "\n\n", "ai_text")
                self.btn_send.configure(state="normal")

        target_widget.configure(state="disabled")

    # ----------------------------------------
    # Chat
    # ----------------------------------------
    def send_chat(self):
        if not self.client:
            messagebox.showerror("API Key Required", "Configure API key first.")
            return
        if self.ai_thinking:
            return

        msg = self.ent_chat.get().strip()
        if not msg:
            return
        self.ent_chat.delete(0, tk.END)

        # Build context if first chat message
        if not self.chat_history and self.scanner:
            port_summary = ", ".join(
                f"{p}/{s}" for p, s in sorted(self.scanner.open_ports)
            ) if self.scanner.open_ports else "none"
            self.chat_history = [
                {"role": "user",
                 "content": f"I just ran a port scan on {self.scanner.target}. Open ports: {port_summary}. I'll ask follow-up questions."},
                {"role": "assistant",
                 "content": "Understood! I've noted the scan results. Ask me anything about the security implications, vulnerabilities, or remediation steps."}
            ]

        self.txt_chat.configure(state="normal")
        self.nb.select(2)
        self.txt_chat.insert(tk.END, f"You: {msg}\n\n", "user_msg")
        self.txt_chat.insert(tk.END, "Claude: ", "ai_msg")
        self.txt_chat.configure(state="disabled")
        self.txt_chat.see(tk.END)

        self.chat_history.append({"role": "user", "content": msg})
        self.ai_thinking = True
        self.btn_send.configure(state="disabled")

        def callback(chunk, done, error):
            self.after(0, lambda: self._ai_chunk(chunk, done, error, mode="chat"))
            if done and not error:
                # capture assistant reply
                pass

        self.client.chat(self.chat_history, callback)

    # ----------------------------------------
    def clear_ai(self):
        self.txt_ai.configure(state="normal")
        self.txt_ai.delete("1.0", tk.END)
        self.txt_ai.configure(state="disabled")

    def clear_results(self):
        self.txt_results.configure(state="normal")
        self.txt_results.delete("1.0", tk.END)
        self.txt_results.configure(state="disabled")
        self.progress.configure(value=0, maximum=1)
        self.var_status.set("Idle")
        self.var_elapsed.set("")
        self.btn_save.configure(state="disabled")
        self.btn_analyze.configure(state="disabled")
        self.scanner = None

    def save_results(self):
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Save", "No open ports to save.")
            return
        default_name = f"scan_{self.scanner.target}_{int(time.time())}.txt"
        fp = filedialog.asksaveasfilename(title="Save Scan Results",
                                          defaultextension=".txt",
                                          initialfile=default_name,
                                          filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not fp:
            return
        try:
            with open(fp, "w", encoding="utf-8") as f:
                f.write(f"NetRecon AI — Scan Report\n")
                f.write(f"Target : {self.scanner.target} ({self.resolved_ip})\n")
                f.write(f"Date   : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {self.scan_duration:.2f}s\n\n")
                f.write("Open Ports:\n")
                for port, service in sorted(self.scanner.open_ports):
                    risk = "HIGH" if port in HIGH_RISK_PORTS else ("MEDIUM" if port in MEDIUM_RISK_PORTS else "LOW")
                    f.write(f"  {port:>6}  {service:<20} [{risk}]\n")
                ai_text = self.txt_ai.get("1.0", tk.END).strip()
                if ai_text:
                    f.write("\n\nAI Security Analysis:\n")
                    f.write(ai_text)
            messagebox.showinfo("Saved", f"Saved to:\n{fp}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def append_text(self, text, tag="normal"):
        self.txt_results.configure(state="normal")
        self.txt_results.insert(tk.END, text, tag)
        self.txt_results.configure(state="disabled")
        self.txt_results.see(tk.END)

    def update_elapsed(self):
        if self.start_time and self.var_status.get() in ("Scanning...", "Stopping..."):
            e = time.time() - self.start_time
            self.var_elapsed.set(f"{e:.1f}s")
            self.after(200, self.update_elapsed)


# ---------------------------
def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
