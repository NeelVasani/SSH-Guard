#!/usr/bin/env python3
"""
SSH-Guard :: Real-Time SSH Brute-Force Detector & Auto-Blocker
=================================================================
A defensive security tool for Kali/Debian-based systems.

Features
--------
- Tails /var/log/auth.log (or a custom path) in real time
- Parses failed / accepted SSH login attempts per source IP
- Sliding-window threshold detection (configurable: N failures in M seconds)
- Automatic blocking via iptables, with automatic time-based unblocking
- Manual block / unblock of any IP from the GUI
- Whitelist support so you can't lock yourself out
- Persistent state (attempts + blocks) in a local SQLite database
- Full Tkinter GUI: live attempts table, blocked-IPs table, event log,
  manual controls, live settings (threshold/window/ban duration)

Requirements
------------
- Must be run as root (needed to read auth.log reliably and to run iptables)
- Linux with iptables available (Kali ships with it by default)
- Python 3.8+ (Tkinter included in standard Kali python3-tk package)

Usage
-----
    sudo python3 ssh_guard.py

Author: Generated for defensive/educational use only.
This tool BLOCKS attackers; it contains no attack/exploit functionality.
"""

import os
import re
import sys
import time
import sqlite3
import threading
import subprocess
import queue
from collections import defaultdict, deque
from datetime import datetime, timedelta

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

# ----------------------------------------------------------------------------
# Configuration defaults
# ----------------------------------------------------------------------------
DEFAULT_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_guard.db")
DEFAULT_THRESHOLD = 5          # failed attempts
DEFAULT_WINDOW_SECONDS = 60    # ...within this many seconds
DEFAULT_BAN_SECONDS = 1800     # 30 minute default ban
IPTABLES_CHAIN_COMMENT = "SSH_GUARD"

FAILED_PATTERNS = [
    re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"Connection closed by (?:invalid user \S+ )?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ \[preauth\]"),
]
ACCEPTED_PATTERN = re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+")

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_root() -> bool:
    return os.geteuid() == 0


def valid_ip(ip: str) -> bool:
    if not IPV4_RE.match(ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split("."))


# ----------------------------------------------------------------------------
# Persistence layer
# ----------------------------------------------------------------------------
class Database:
    def __init__(self, path=DB_PATH):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        with self.lock, self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    blocked_at TEXT,
                    expires_at TEXT,
                    reason TEXT,
                    manual INTEGER DEFAULT 0
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    ip TEXT PRIMARY KEY,
                    added_at TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT,
                    ip TEXT,
                    event_type TEXT,
                    detail TEXT
                )
            """)

    def add_block(self, ip, expires_at, reason, manual=False):
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, expires_at, reason, manual) VALUES (?, ?, ?, ?, ?)",
                (ip, datetime.now().isoformat(), expires_at.isoformat() if expires_at else None, reason, int(manual)),
            )

    def remove_block(self, ip):
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))

    def get_blocks(self):
        with self.lock:
            cur = self.conn.execute("SELECT ip, blocked_at, expires_at, reason, manual FROM blocked_ips")
            return cur.fetchall()

    def is_blocked(self, ip):
        with self.lock:
            cur = self.conn.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
            return cur.fetchone() is not None

    def add_whitelist(self, ip):
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO whitelist (ip, added_at) VALUES (?, ?)",
                (ip, datetime.now().isoformat()),
            )

    def remove_whitelist(self, ip):
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))

    def get_whitelist(self):
        with self.lock:
            cur = self.conn.execute("SELECT ip FROM whitelist")
            return [r[0] for r in cur.fetchall()]

    def log_event(self, ip, event_type, detail=""):
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO events (ts, ip, event_type, detail) VALUES (?, ?, ?, ?)",
                (datetime.now().isoformat(), ip, event_type, detail),
            )


# ----------------------------------------------------------------------------
# Firewall control (iptables)
# ----------------------------------------------------------------------------
class Firewall:
    """Wraps iptables so all SSH-Guard rules are tagged and easy to clean up."""

    @staticmethod
    def _run(cmd):
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr

    @classmethod
    def block_ip(cls, ip):
        # Avoid duplicate rules
        if cls._rule_exists(ip):
            return True, "already blocked"
        rc, out, err = cls._run([
            "iptables", "-I", "INPUT", "1", "-s", ip, "-p", "tcp", "--dport", "22",
            "-m", "comment", "--comment", IPTABLES_CHAIN_COMMENT, "-j", "DROP",
        ])
        return rc == 0, err

    @classmethod
    def unblock_ip(cls, ip):
        # Remove all matching rules (loop in case of duplicates)
        removed_any = False
        for _ in range(10):
            if not cls._rule_exists(ip):
                break
            rc, out, err = cls._run([
                "iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "--dport", "22",
                "-m", "comment", "--comment", IPTABLES_CHAIN_COMMENT, "-j", "DROP",
            ])
            if rc != 0:
                return removed_any, err
            removed_any = True
        return True, ""

    @classmethod
    def _rule_exists(cls, ip):
        rc, out, err = cls._run(["iptables", "-C", "INPUT", "-s", ip, "-p", "tcp", "--dport", "22",
                                  "-m", "comment", "--comment", IPTABLES_CHAIN_COMMENT, "-j", "DROP"])
        return rc == 0

    @classmethod
    def list_ssh_guard_rules(cls):
        rc, out, err = cls._run(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
        if rc != 0:
            return []
        ips = []
        for line in out.splitlines():
            if IPTABLES_CHAIN_COMMENT in line:
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                if m:
                    ips.append(m.group(1))
        return ips


# ----------------------------------------------------------------------------
# Detection engine
# ----------------------------------------------------------------------------
class DetectionEngine:
    """
    Watches the auth log, tracks failed attempts per IP in a sliding window,
    and triggers blocks when the threshold is exceeded.
    """

    def __init__(self, db: Database, event_queue: queue.Queue,
                 log_path=None, threshold=DEFAULT_THRESHOLD,
                 window_seconds=DEFAULT_WINDOW_SECONDS, ban_seconds=DEFAULT_BAN_SECONDS):
        self.db = db
        self.event_queue = event_queue
        self.log_path = log_path or self._find_log_path()
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.ban_seconds = ban_seconds

        self.attempts = defaultdict(deque)   # ip -> deque[timestamps]
        self.total_attempts = defaultdict(int)
        self.last_user_tried = {}
        self._stop_event = threading.Event()
        self._thread = None
        self._unban_thread = None

    @staticmethod
    def _find_log_path():
        for p in DEFAULT_LOG_PATHS:
            if os.path.exists(p):
                return p
        return DEFAULT_LOG_PATHS[0]

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._thread.start()
        self._unban_thread = threading.Thread(target=self._unban_loop, daemon=True)
        self._unban_thread.start()

    def stop(self):
        self._stop_event.set()

    def _emit(self, kind, payload):
        self.event_queue.put((kind, payload))

    def _tail_loop(self):
        if not os.path.exists(self.log_path):
            self._emit("error", f"Log file not found: {self.log_path}")
            return
        try:
            with open(self.log_path, "r", errors="ignore") as f:
                f.seek(0, os.SEEK_END)  # start at end -> real time only
                while not self._stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.3)
                        continue
                    self._process_line(line)
        except PermissionError:
            self._emit("error", f"Permission denied reading {self.log_path}. Run as root (sudo).")
        except Exception as e:
            self._emit("error", f"Log tail error: {e}")

    def _process_line(self, line):
        # Accepted login -> informational, also clears some suspicion
        m = ACCEPTED_PATTERN.search(line)
        if m:
            ip = m.group("ip")
            self._emit("accepted", {"ip": ip, "user": m.group("user"), "raw": line.strip()})
            return

        for pattern in FAILED_PATTERNS:
            m = pattern.search(line)
            if m:
                ip = m.groupdict().get("ip")
                user = m.groupdict().get("user", "?")
                if not ip or not valid_ip(ip):
                    continue
                self._register_failure(ip, user, line.strip())
                return

    def _register_failure(self, ip, user, raw_line):
        now = time.time()
        dq = self.attempts[ip]
        dq.append(now)
        self.total_attempts[ip] += 1
        self.last_user_tried[ip] = user

        # Trim window
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

        self._emit("failed", {
            "ip": ip, "user": user, "count_in_window": len(dq),
            "total": self.total_attempts[ip], "raw": raw_line,
        })

        if ip in self.db.get_whitelist():
            return

        if len(dq) >= self.threshold and not self.db.is_blocked(ip):
            self._trigger_block(ip, reason=f"{len(dq)} failed attempts in {self.window_seconds}s (user tried: {user})")

    def _trigger_block(self, ip, reason):
        ok, err = Firewall.block_ip(ip)
        expires = datetime.now() + timedelta(seconds=self.ban_seconds) if self.ban_seconds else None
        if ok:
            self.db.add_block(ip, expires, reason, manual=False)
            self.db.log_event(ip, "AUTO_BLOCK", reason)
            self._emit("blocked", {"ip": ip, "reason": reason, "expires": expires, "manual": False})
        else:
            self._emit("error", f"Failed to block {ip}: {err}")

    def _unban_loop(self):
        while not self._stop_event.is_set():
            try:
                for ip, blocked_at, expires_at, reason, manual in self.db.get_blocks():
                    if manual:
                        continue  # manual blocks never auto-expire
                    if expires_at and datetime.fromisoformat(expires_at) <= datetime.now():
                        ok, err = Firewall.unblock_ip(ip)
                        if ok:
                            self.db.remove_block(ip)
                            self.db.log_event(ip, "AUTO_UNBLOCK", "ban expired")
                            self._emit("unblocked", {"ip": ip, "manual": False})
            except Exception as e:
                self._emit("error", f"Unban loop error: {e}")
            time.sleep(5)


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
class SSHGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH-Guard :: Real-Time Brute-Force Detector")
        self.root.geometry("1150x720")
        self.root.configure(bg="#0d1117")

        self.db = Database()
        self.event_queue = queue.Queue()
        self.engine = DetectionEngine(self.db, self.event_queue)

        self._build_style()
        self._build_layout()
        self._refresh_blocked_table()
        self._refresh_whitelist_box()

        self.root.after(200, self._poll_events)

        if not is_root():
            messagebox.showwarning(
                "Root required",
                "SSH-Guard is not running as root.\n\n"
                "Reading /var/log/auth.log and controlling iptables both require root.\n"
                "Please restart with: sudo python3 ssh_guard.py"
            )

    # ---------------- styling ----------------
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        bg = "#0d1117"; fg = "#c9d1d9"; accent = "#238636"; row = "#161b22"
        style.configure("Treeview", background=row, fieldbackground=row, foreground=fg,
                         rowheight=24, borderwidth=0, font=("Consolas", 10))
        style.configure("Treeview.Heading", background="#21262d", foreground="#58a6ff",
                         font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", "#1f6feb")])
        style.configure("TButton", background=accent, foreground="white", font=("Segoe UI", 9, "bold"), padding=6)
        style.map("TButton", background=[("active", "#2ea043")])
        style.configure("Danger.TButton", background="#da3633")
        style.map("Danger.TButton", background=[("active", "#f85149")])
        style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=bg, foreground="#58a6ff", font=("Segoe UI", 14, "bold"))
        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=bg, foreground=fg)
        style.configure("TLabelframe.Label", background=bg, foreground="#58a6ff", font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", fieldbackground=row, foreground=fg)

    # ---------------- layout ----------------
    def _build_layout(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="🛡  SSH-Guard", style="Header.TLabel").pack(side="left")
        self.status_var = tk.StringVar(value="Stopped")
        self.status_lbl = ttk.Label(top, textvariable=self.status_var, foreground="#f85149")
        self.status_lbl.pack(side="left", padx=20)

        self.start_btn = ttk.Button(top, text="▶ Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side="right", padx=4)
        self.stop_btn = ttk.Button(top, text="■ Stop", command=self.stop_monitoring, state="disabled")
        self.stop_btn.pack(side="right", padx=4)

        # Settings bar
        settings = ttk.Labelframe(self.root, text="Detection Settings", padding=10)
        settings.pack(fill="x", padx=10, pady=5)

        ttk.Label(settings, text="Threshold (failed attempts):").grid(row=0, column=0, sticky="w", padx=4)
        self.threshold_var = tk.StringVar(value=str(DEFAULT_THRESHOLD))
        ttk.Entry(settings, textvariable=self.threshold_var, width=6).grid(row=0, column=1, padx=4)

        ttk.Label(settings, text="Window (seconds):").grid(row=0, column=2, sticky="w", padx=4)
        self.window_var = tk.StringVar(value=str(DEFAULT_WINDOW_SECONDS))
        ttk.Entry(settings, textvariable=self.window_var, width=6).grid(row=0, column=3, padx=4)

        ttk.Label(settings, text="Ban duration (seconds, 0=permanent):").grid(row=0, column=4, sticky="w", padx=4)
        self.ban_var = tk.StringVar(value=str(DEFAULT_BAN_SECONDS))
        ttk.Entry(settings, textvariable=self.ban_var, width=8).grid(row=0, column=5, padx=4)

        ttk.Label(settings, text="Log file:").grid(row=0, column=6, sticky="w", padx=4)
        self.logpath_var = tk.StringVar(value=self.engine.log_path)
        ttk.Entry(settings, textvariable=self.logpath_var, width=22).grid(row=0, column=7, padx=4)

        ttk.Button(settings, text="Apply", command=self.apply_settings).grid(row=0, column=8, padx=8)

        # Main paned area
        main = ttk.Frame(self.root, padding=(10, 5))
        main.pack(fill="both", expand=True)

        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True, padx=(0, 5))
        right = ttk.Frame(main)
        right.pack(side="right", fill="both", expand=True, padx=(5, 0))

        # Live attempts table
        attempts_frame = ttk.Labelframe(left, text="Live Login Attempts", padding=5)
        attempts_frame.pack(fill="both", expand=True, pady=(0, 5))
        cols = ("time", "ip", "user", "result", "count")
        self.attempts_tree = ttk.Treeview(attempts_frame, columns=cols, show="headings", height=14)
        for c, w in zip(cols, (90, 130, 110, 90, 60)):
            self.attempts_tree.heading(c, text=c.upper())
            self.attempts_tree.column(c, width=w, anchor="center")
        self.attempts_tree.pack(fill="both", expand=True)

        # Event log
        log_frame = ttk.Labelframe(left, text="Event Log", padding=5)
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=10, bg="#161b22", fg="#c9d1d9",
                                 insertbackground="#c9d1d9", font=("Consolas", 9), state="disabled")
        self.log_text.pack(fill="both", expand=True)

        # Blocked IPs table
        blocked_frame = ttk.Labelframe(right, text="Blocked IPs", padding=5)
        blocked_frame.pack(fill="both", expand=True, pady=(0, 5))
        bcols = ("ip", "blocked_at", "expires_at", "reason", "manual")
        self.blocked_tree = ttk.Treeview(blocked_frame, columns=bcols, show="headings", height=12)
        for c, w in zip(bcols, (110, 130, 130, 160, 60)):
            self.blocked_tree.heading(c, text=c.upper())
            self.blocked_tree.column(c, width=w, anchor="center")
        self.blocked_tree.pack(fill="both", expand=True)

        # Manual controls
        manual_frame = ttk.Labelframe(right, text="Manual Controls", padding=10)
        manual_frame.pack(fill="x", pady=(0, 5))

        ttk.Label(manual_frame, text="IP address:").grid(row=0, column=0, sticky="w")
        self.manual_ip_var = tk.StringVar()
        ttk.Entry(manual_frame, textvariable=self.manual_ip_var, width=18).grid(row=0, column=1, padx=5)
        ttk.Button(manual_frame, text="Block", command=self.manual_block).grid(row=0, column=2, padx=3)
        ttk.Button(manual_frame, text="Unblock", style="Danger.TButton",
                   command=self.manual_unblock).grid(row=0, column=3, padx=3)

        ttk.Button(manual_frame, text="Unblock Selected", command=self.unblock_selected).grid(row=1, column=1, pady=6)
        ttk.Button(manual_frame, text="Refresh", command=self._refresh_blocked_table).grid(row=1, column=2, pady=6)

        # Whitelist
        wl_frame = ttk.Labelframe(right, text="Whitelist (never auto-blocked)", padding=10)
        wl_frame.pack(fill="both", expand=True)

        wl_top = ttk.Frame(wl_frame)
        wl_top.pack(fill="x")
        self.wl_ip_var = tk.StringVar()
        ttk.Entry(wl_top, textvariable=self.wl_ip_var, width=18).pack(side="left", padx=5)
        ttk.Button(wl_top, text="Add", command=self.add_whitelist).pack(side="left", padx=3)
        ttk.Button(wl_top, text="Remove Selected", command=self.remove_whitelist).pack(side="left", padx=3)

        self.wl_listbox = tk.Listbox(wl_frame, bg="#161b22", fg="#c9d1d9", height=6, font=("Consolas", 10))
        self.wl_listbox.pack(fill="both", expand=True, pady=5)

    # ---------------- actions ----------------
    def apply_settings(self):
        try:
            self.engine.threshold = int(self.threshold_var.get())
            self.engine.window_seconds = int(self.window_var.get())
            self.engine.ban_seconds = int(self.ban_var.get())
            self.engine.log_path = self.logpath_var.get().strip()
            self._log(f"Settings applied: threshold={self.engine.threshold}, "
                       f"window={self.engine.window_seconds}s, ban={self.engine.ban_seconds}s, "
                       f"log={self.engine.log_path}")
        except ValueError:
            messagebox.showerror("Invalid settings", "Threshold, window, and ban duration must be integers.")

    def start_monitoring(self):
        if not is_root():
            if not messagebox.askyesno("Not root", "Not running as root — log reading/blocking may fail. Continue anyway?"):
                return
        self.apply_settings()
        self.engine.start()
        self.status_var.set("Monitoring...")
        self.status_lbl.configure(foreground="#3fb950")
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._log(f"Started monitoring {self.engine.log_path}")

    def stop_monitoring(self):
        self.engine.stop()
        self.status_var.set("Stopped")
        self.status_lbl.configure(foreground="#f85149")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self._log("Monitoring stopped.")

    def manual_block(self):
        ip = self.manual_ip_var.get().strip()
        if not valid_ip(ip):
            messagebox.showerror("Invalid IP", f"'{ip}' is not a valid IPv4 address.")
            return
        ok, err = Firewall.block_ip(ip)
        if ok:
            self.db.add_block(ip, None, "manual block", manual=True)
            self.db.log_event(ip, "MANUAL_BLOCK", "blocked via GUI")
            self._log(f"Manually blocked {ip}")
            self._refresh_blocked_table()
        else:
            messagebox.showerror("Block failed", err)

    def manual_unblock(self):
        ip = self.manual_ip_var.get().strip()
        if not valid_ip(ip):
            messagebox.showerror("Invalid IP", f"'{ip}' is not a valid IPv4 address.")
            return
        self._unblock_ip(ip)

    def unblock_selected(self):
        sel = self.blocked_tree.selection()
        if not sel:
            return
        for item in sel:
            ip = self.blocked_tree.item(item, "values")[0]
            self._unblock_ip(ip)

    def _unblock_ip(self, ip):
        ok, err = Firewall.unblock_ip(ip)
        if ok:
            self.db.remove_block(ip)
            self.db.log_event(ip, "MANUAL_UNBLOCK", "unblocked via GUI")
            self._log(f"Unblocked {ip}")
            self._refresh_blocked_table()
        else:
            messagebox.showerror("Unblock failed", err)

    def add_whitelist(self):
        ip = self.wl_ip_var.get().strip()
        if not valid_ip(ip):
            messagebox.showerror("Invalid IP", f"'{ip}' is not a valid IPv4 address.")
            return
        self.db.add_whitelist(ip)
        # If it was blocked, unblock it immediately
        if self.db.is_blocked(ip):
            self._unblock_ip(ip)
        self._log(f"Whitelisted {ip}")
        self._refresh_whitelist_box()

    def remove_whitelist(self):
        sel = self.wl_listbox.curselection()
        if not sel:
            return
        ip = self.wl_listbox.get(sel[0])
        self.db.remove_whitelist(ip)
        self._log(f"Removed {ip} from whitelist")
        self._refresh_whitelist_box()

    # ---------------- refresh / event polling ----------------
    def _refresh_blocked_table(self):
        for row in self.blocked_tree.get_children():
            self.blocked_tree.delete(row)
        for ip, blocked_at, expires_at, reason, manual in self.db.get_blocks():
            exp_display = "never" if not expires_at else expires_at.split(".")[0]
            self.blocked_tree.insert("", "end", values=(
                ip, blocked_at.split(".")[0], exp_display, reason, "yes" if manual else "no"
            ))

    def _refresh_whitelist_box(self):
        self.wl_listbox.delete(0, "end")
        for ip in self.db.get_whitelist():
            self.wl_listbox.insert("end", ip)

    def _log(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _add_attempt_row(self, ts, ip, user, result, count):
        self.attempts_tree.insert("", 0, values=(ts, ip, user, result, count))
        children = self.attempts_tree.get_children()
        if len(children) > 200:
            self.attempts_tree.delete(children[-1])

    def _poll_events(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                ts = datetime.now().strftime("%H:%M:%S")
                if kind == "failed":
                    self._add_attempt_row(ts, payload["ip"], payload["user"], "FAILED", payload["count_in_window"])
                elif kind == "accepted":
                    self._add_attempt_row(ts, payload["ip"], payload["user"], "ACCEPTED", "-")
                elif kind == "blocked":
                    self._log(f"🚫 BLOCKED {payload['ip']} — {payload['reason']}")
                    self._refresh_blocked_table()
                elif kind == "unblocked":
                    self._log(f"✅ UNBLOCKED {payload['ip']} (ban expired)")
                    self._refresh_blocked_table()
                elif kind == "error":
                    self._log(f"⚠ ERROR: {payload}")
        except queue.Empty:
            pass
        self.root.after(300, self._poll_events)

    def on_close(self):
        self.engine.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = SSHGuardGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
