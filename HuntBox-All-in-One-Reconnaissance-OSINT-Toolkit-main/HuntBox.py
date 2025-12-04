#!/usr/bin/env python3

# Run: python3 HuntBox.py

import threading
import subprocess
import shlex
import socket
import os
from datetime import datetime
import platform
import json
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Optional libs used earlier - keep checks for compatibility
try:
    import requests
except Exception:
    requests = None

try:
    import dns.resolver, dns.query, dns.zone, dns.exception
except Exception:
    dns = None

try:
    import whois as pywhois
except Exception:
    pywhois = None

# keep uploaded-file helper path from original
UPLOADED_FILE = "/mnt/data/dirbuster.py"

# ---------------------------
# Utility helpers
# ---------------------------

def center_window(root, w=1200, h=820):
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (w // 2)
    y = (root.winfo_screenheight() // 2) - (h // 2)
    root.geometry(f"{w}x{h}+{x}+{y}")

def read_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def run_subprocess_capture(cmd, timeout=None):
    try:
        proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out, _ = proc.communicate(timeout=timeout)
        return out
    except subprocess.TimeoutExpired:
        proc.kill()
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

# Small tooltip implementation
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _e=None):
        if self.tip:
            return
        x, y, cx, cy = self.widget.bbox("insert") if self.widget.winfo_class() == "Entry" else (0,0,0,0)
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry("+%d+%d" % (x, y))
        lbl = tk.Label(self.tip, text=self.text, justify=tk.LEFT,
                       background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                       font=("TkDefaultFont", 9))
        lbl.pack(ipadx=6, ipady=2)

    def hide(self, _e=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None

# ---------------------------
# Base UI components
# ---------------------------

def make_output(parent, height=18):
    txt = scrolledtext.ScrolledText(parent, height=height, font=("Consolas", 11), wrap=tk.NONE)
    # monospace look & feel
    txt.tag_config("time", foreground="#666")
    return txt

def make_label(parent, text):
    return ttk.Label(parent, text=text)

# ---------------------------
# DirBuster Frame (styled)
# ---------------------------

class DirBusterFrame(ttk.Frame):
    def __init__(self, parent, status_callback):
        super().__init__(parent, padding=(12,10))
        self.status = status_callback
        self.is_scanning = False
        self.stop_flag = False
        self.build()

    def build(self):
        header = ttk.Label(self, text="DirBuster", style="Header.TLabel")
        header.pack(anchor=tk.W)

        frm = ttk.Frame(self)
        frm.pack(fill=tk.X, pady=8)

        ttk.Label(frm, text="Target URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_var = tk.StringVar(value="https://example.com")
        ttk.Entry(frm, textvariable=self.url_var, width=48).grid(row=0, column=1, sticky=tk.W, padx=6)

        ttk.Label(frm, text="Wordlist:").grid(row=1, column=0, sticky=tk.W, pady=6)
        self.word_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.word_var, width=40).grid(row=1, column=1, sticky=tk.W, padx=6)
        brow = ttk.Button(frm, text="Browse", command=self.browse)
        brow.grid(row=1, column=2, padx=4)
        ToolTip(brow, "Select a wordlist (.txt)")

        up = ttk.Button(frm, text="Open uploaded", command=self.open_uploaded)
        up.grid(row=1, column=3, padx=4)
        ToolTip(up, "Open the uploaded helper script")

        btns = ttk.Frame(frm)
        btns.grid(row=2, column=0, columnspan=4, pady=8, sticky=tk.W)

        self.start_btn = ttk.Button(btns, text="Start", command=self.start_scan, style="Accent.TButton")
        self.start_btn.pack(side=tk.LEFT, padx=6)
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=6)
        self.save_btn = ttk.Button(btns, text="Save", command=self.save_results)
        self.save_btn.pack(side=tk.LEFT, padx=6)

        self.output = make_output(self, height=18)
        self.output.pack(fill=tk.BOTH, expand=True, pady=(6,0))

    def open_uploaded(self):
        if os.path.isfile(UPLOADED_FILE):
            try:
                with open(UPLOADED_FILE, "r", encoding="utf-8") as f:
                    content = f.read()
                win = tk.Toplevel(self)
                win.title(os.path.basename(UPLOADED_FILE))
                txt = scrolledtext.ScrolledText(win, width=100, height=40)
                txt.pack(fill=tk.BOTH, expand=True)
                txt.insert(tk.END, content)
                txt.config(state=tk.NORMAL)
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showinfo("Not found", f"Uploaded file not found: {UPLOADED_FILE}")

    def browse(self):
        p = filedialog.askopenfilename(filetypes=[("Text files","*.txt"),("All files","*.*")])
        if p:
            self.word_var.set(p)

    def start_scan(self):
        if requests is None:
            messagebox.showerror("Error", "requests library is required for DirBuster. Install with: pip install requests")
            return

        url = self.url_var.get().strip()
        wl = self.word_var.get().strip()
        if not url.startswith(("http://", "https://")):
            messagebox.showerror("Error", "URL must start with http:// or https://")
            return
        if not os.path.isfile(wl):
            messagebox.showerror("Error", "Invalid wordlist.")
            return

        self.is_scanning = True
        self.stop_flag = False
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.status("DirBuster: running")
        threading.Thread(target=self._worker, args=(url, wl), daemon=True).start()

    def stop_scan(self):
        self.stop_flag = True
        self.append("[!] Stop requested\n")
        self.status("DirBuster: stopping...")

    def _worker(self, url, wl):
        try:
            words = read_wordlist(wl)
        except Exception as e:
            self.append(f"[ERROR] {e}\n")
            self._finish()
            return

        for w in words:
            if self.stop_flag:
                break
            full = url.rstrip("/") + "/" + w.lstrip("/")
            try:
                r = requests.get(full, timeout=6)
                c = r.status_code
                if c < 400 or c in (401, 403):
                    self.append(f"[FOUND] {full} -> {c}\n")
                else:
                    self.append(f"[{c}] {full}\n")
            except Exception as e:
                self.append(f"[ERR] {full} -> {e}\n")

        self._finish()

    def _finish(self):
        self.is_scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.append("Scan complete.\n")
        self.status("DirBuster: done")

    def append(self, text):
        ts = datetime.now().strftime("%H:%M:%S")
        self.output.after(0, lambda: (self.output.insert(tk.END, f"[{ts}] {text}"), self.output.see(tk.END)))

    def save_results(self):
        txt = self.output.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showinfo("Empty", "No results to save.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".txt")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(txt)
            messagebox.showinfo("Saved", p)

# ---------------------------
# DNSRecon Frame
# ---------------------------

class DNSReconFrame(ttk.Frame):
    def __init__(self, parent, status_callback):
        super().__init__(parent, padding=(12,10))
        self.status = status_callback
        self.build()

    def build(self):
        hdr = ttk.Label(self, text="DNS Recon", style="Header.TLabel"); hdr.pack(anchor=tk.W)
        frm = ttk.Frame(self); frm.pack(fill=tk.X, pady=6)
        ttk.Label(frm, text="Domain:").grid(row=0, column=0, sticky=tk.W)
        self.domain = ttk.Entry(frm, width=40); self.domain.grid(row=0, column=1, padx=6); self.domain.insert(0, "example.com")
        ttk.Label(frm, text="Wordlist:").grid(row=1, column=0, sticky=tk.W)
        self.word = ttk.Entry(frm, width=40); self.word.grid(row=1, column=1, padx=6)
        ttk.Button(frm, text="Browse", command=self.browse).grid(row=1, column=2, padx=4)

        self.std_var = tk.BooleanVar(value=True)
        self.brt_var = tk.BooleanVar(value=False)
        self.axfr_var = tk.BooleanVar(value=False)
        chkfrm = ttk.Frame(frm); chkfrm.grid(row=2, column=0, columnspan=3, pady=8, sticky=tk.W)
        ttk.Checkbutton(chkfrm, text="Standard", variable=self.std_var).pack(side=tk.LEFT, padx=6)
        ttk.Checkbutton(chkfrm, text="Brute", variable=self.brt_var).pack(side=tk.LEFT, padx=6)
        ttk.Checkbutton(chkfrm, text="AXFR", variable=self.axfr_var).pack(side=tk.LEFT, padx=6)

        ttk.Button(frm, text="Run", command=self.run_thread, style="Accent.TButton").grid(row=3, column=0, pady=6)

        self.out = make_output(self, height=18); self.out.pack(fill=tk.BOTH, expand=True, pady=(6,0))

    def browse(self):
        p = filedialog.askopenfilename(filetypes=[("Text files","*.txt"),("All files","*.*")])
        if p:
            self.word.delete(0, tk.END); self.word.insert(0, p)

    def run_thread(self):
        threading.Thread(target=self.run_scan, daemon=True).start()

    def resolve(self, name, rtype):
        if dns is None:
            return []
        try:
            ans = dns.resolver.resolve(name, rtype)
            return [x.to_text() for x in ans]
        except:
            return []

    def standard(self, domain):
        rtypes = ["SOA","NS","A","AAAA","MX","TXT","SPF"]
        out = [f"=== Standard enum: {domain} ==="]
        for rt in rtypes:
            recs = self.resolve(domain, rt)
            if recs:
                out.append(f"-- {rt} --"); out.extend(["   " + r for r in recs])
        for b in ["_sip._tcp","_sip._udp","_xmpp-server._tcp","_ldap._tcp"]:
            name = f"{b}.{domain}"
            recs = self.resolve(name, "SRV")
            if recs:
                out.append(f"-- SRV {name} --"); out.extend(["   " + r for r in recs])
        return "\n".join(out)

    def brute(self, domain, wl):
        try:
            words = read_wordlist(wl)
        except Exception as e:
            return f"[ERROR] {e}"
        out = [f"=== Brute: {domain} ==="]
        for w in words:
            s = f"{w}.{domain}"
            a = self.resolve(s, "A"); aaaa = self.resolve(s, "AAAA")
            if a or aaaa:
                out.append(f"[+] {s}"); out.extend(["   " + r for r in (a + aaaa)])
        return "\n".join(out) if out else "[!] No results"

    def axfr(self, domain):
        if dns is None:
            return "[!] dnspython not installed"
        out = [f"=== AXFR: {domain} ==="]
        try:
            ns = dns.resolver.resolve(domain, "NS")
            names = [x.to_text().strip(".") for x in ns]
        except Exception as e:
            return f"[!] NS error: {e}"
        for n in names:
            out.append(f"Trying {n}")
            try:
                ip = dns.resolver.resolve(n, "A")[0].to_text()
                xfr = dns.query.xfr(ip, domain, timeout=5)
                zone = dns.zone.from_xfr(xfr)
                out.append(f"[+] Success from {n}")
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            out.append(f"{name}.{domain} {rdata}")
            except Exception as e:
                out.append(f"[!] Failed {n}: {e}")
        return "\n".join(out)

    def run_scan(self):
        domain = self.domain.get().strip()
        wl = self.word.get().strip()
        self.out.delete("1.0", tk.END)
        self.status("DNSRecon: running")
        if self.std_var.get():
            self.out.insert(tk.END, self.standard(domain) + "\n\n")
        if self.brt_var.get():
            if not wl:
                self.out.insert(tk.END, "[!] Brute selected but no wordlist.\n\n")
            else:
                self.out.insert(tk.END, self.brute(domain, wl) + "\n\n")
        if self.axfr_var.get():
            self.out.insert(tk.END, self.axfr(domain) + "\n\n")
        self.status("DNSRecon: done")

# ---------------------------
# Subdomain Finder Frame
# ---------------------------

class SubdomainFrame(ttk.Frame):
    def __init__(self, parent, status_callback):
        super().__init__(parent, padding=(12,10))
        self.subs = []
        self.stop_flag = False
        self.status = status_callback
        self.build()

    def build(self):
        hdr = ttk.Label(self, text="Subdomain Finder", style="Header.TLabel"); hdr.pack(anchor=tk.W)
        frm = ttk.Frame(self); frm.pack(fill=tk.X, pady=6)
        ttk.Label(frm, text="Domain:").grid(row=0, column=0, sticky=tk.W)
        self.domain = ttk.Entry(frm, width=36); self.domain.grid(row=0, column=1, padx=6); self.domain.insert(0,"example.com")
        ttk.Button(frm, text="Load Wordlist", command=self.load_wl).grid(row=0, column=2, padx=4)
        self.start_btn = ttk.Button(frm, text="Start", command=self.start, style="Accent.TButton"); self.start_btn.grid(row=1, column=0, pady=8)
        self.stop_btn = ttk.Button(frm, text="Stop", state=tk.DISABLED, command=self.stop); self.stop_btn.grid(row=1, column=1, pady=8)
        ttk.Button(frm, text="Save", command=self.save).grid(row=1, column=2, pady=8)
        self.status_label = ttk.Label(self, text="Status: Idle"); self.status_label.pack(fill=tk.X, pady=(2,8))
        self.out = make_output(self, height=18); self.out.pack(fill=tk.BOTH, expand=True)

    def load_wl(self):
        p = filedialog.askopenfilename(filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not p:
            return
        try:
            self.subs = read_wordlist(p)
            self.status_label.config(text=f"Loaded {len(self.subs)}")
            self.out.insert(tk.END, f"Loaded {len(self.subs)} entries\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def start(self):
        if not self.subs:
            messagebox.showerror("Error", "Load a wordlist first.")
            return
        domain = self.domain.get().strip()
        if not domain:
            messagebox.showerror("Error", "Enter domain.")
            return
        self.stop_flag = False
        self.start_btn.config(state=tk.DISABLED); self.stop_btn.config(state=tk.NORMAL)
        self.out.delete("1.0", tk.END)
        self.status("Subdomain: running")
        threading.Thread(target=self.scan, args=(domain,), daemon=True).start()

    def stop(self):
        self.stop_flag = True
        self.status_label.config(text="Stopping...")
        self.status("Subdomain: stopping...")

    def scan(self, domain):
        total = len(self.subs)
        for i,s in enumerate(self.subs, start=1):
            if self.stop_flag:
                self.out.insert(tk.END, "Stopped by user.\n"); break
            fqdn = f"{s}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                self.out.insert(tk.END, fqdn + "\n")
                self.out.see(tk.END)
            except:
                pass
            if i % 50 == 0:
                self.status_label.config(text=f"Scanned {i}/{total}")
        self.start_btn.config(state=tk.NORMAL); self.stop_btn.config(state=tk.DISABLED); self.status_label.config(text="Done")
        self.status("Subdomain: done")

    def save(self):
        txt = self.out.get("1.0", tk.END).strip()
        if not txt:
            return
        p = filedialog.asksaveasfilename(defaultextension=".txt")
        if not p:
            return
        with open(p, "w", encoding="utf-8") as f:
            f.write(txt)
        messagebox.showinfo("Saved", p)

# ---------------------------
# Nmap Frame
# ---------------------------

SCAN_PROFILES = {
    "quick": "-T4 -F",
    "full": "-T3 -p-",
    "syn": "-sS -T3",
    "udp": "-sU -T3",
    "aggressive": "-A -T4",
    "stealth": "-sS -T2 --scan-delay 100ms",
}

class NmapFrame(ttk.Frame):
    def __init__(self, parent, status_callback):
        super().__init__(parent, padding=(12,10))
        self.proc = None
        self.raw = ""
        self.status = status_callback
        self.build()

    def build(self):
        hdr = ttk.Label(self, text="Nmap", style="Header.TLabel"); hdr.pack(anchor=tk.W)
        frm = ttk.Frame(self); frm.pack(fill=tk.X, pady=6)
        ttk.Label(frm, text="Target:").grid(row=0, column=0)
        self.target = ttk.Entry(frm, width=36); self.target.grid(row=0, column=1, padx=6); self.target.insert(0,"127.0.0.1")
        ttk.Label(frm, text="Mode:").grid(row=0, column=2)
        self.mode = tk.StringVar(value="scan")
        ttk.Combobox(frm, textvariable=self.mode, values=["scan","discover"], width=12).grid(row=0, column=3, padx=6)
        ttk.Label(frm, text="Profile:").grid(row=1, column=0)
        self.profile = tk.StringVar(value="quick")
        ttk.Combobox(frm, textvariable=self.profile, values=list(SCAN_PROFILES.keys()), width=12).grid(row=1, column=1, padx=6)
        ttk.Label(frm, text="Extra:").grid(row=1, column=2)
        self.extra = ttk.Entry(frm, width=25); self.extra.grid(row=1, column=3, padx=6); self.extra.insert(0,"-sV")
        btns = ttk.Frame(frm); btns.grid(row=2, column=0, columnspan=4, pady=8)
        self.run_btn = ttk.Button(btns, text="Run", command=self.start, style="Accent.TButton"); self.run_btn.pack(side=tk.LEFT, padx=6)
        self.stop_btn = ttk.Button(btns, text="Stop", state=tk.DISABLED, command=self.stop); self.stop_btn.pack(side=tk.LEFT, padx=6)
        self.save_btn = ttk.Button(btns, text="Save", state=tk.DISABLED, command=self.save); self.save_btn.pack(side=tk.LEFT, padx=6)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN).pack(side=tk.BOTTOM, fill=tk.X, pady=(8,0))
        self.out = make_output(self, height=18); self.out.pack(fill=tk.BOTH, expand=True)

    def start(self):
        t = self.target.get().strip()
        if not t:
            messagebox.showerror("Error","Target required"); return
        mode = self.mode.get()
        extra = self.extra.get().strip()
        prof = SCAN_PROFILES.get(self.profile.get(), "")
        args = "-sn" if mode == "discover" else f"{prof} {extra}".strip()
        cmd = f"nmap {args} {t}"
        self.out.delete("1.0", tk.END)
        self.out.insert(tk.END, f"Command: {cmd}\n\n")
        self.status_var.set("Running...")
        self.status("Nmap: running")
        self.run_btn.config(state=tk.DISABLED); self.stop_btn.config(state=tk.NORMAL)
        threading.Thread(target=self.worker, args=(cmd,), daemon=True).start()

    def worker(self, cmd):
        self.raw = ""
        try:
            self.proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in self.proc.stdout:
                self.raw += line
                self.out.insert(tk.END, line); self.out.see(tk.END)
            self.proc.wait()
        except Exception as e:
            self.out.insert(tk.END, f"\n[ERROR] {e}\n")
        self.finish()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try: self.proc.terminate()
            except: pass
        self.status_var.set("Stopped")
        self.status("Nmap: stopped")

    def finish(self):
        self.status_var.set("Done"); self.run_btn.config(state=tk.NORMAL); self.stop_btn.config(state=tk.DISABLED); self.save_btn.config(state=tk.NORMAL)
        self.status("Nmap: done")

    def save(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt")
        if not p: return
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.raw)
        messagebox.showinfo("Saved", p)

# ---------------------------
# WHOIS Frame
# ---------------------------

class WhoisFrame(ttk.Frame):
    def __init__(self, parent, status_callback):
        super().__init__(parent, padding=(12,10))
        self.status = status_callback
        self.build()

    def build(self):
        hdr = ttk.Label(self, text="WHOIS Lookup", style="Header.TLabel"); hdr.pack(anchor=tk.W)
        frm = ttk.Frame(self); frm.pack(fill=tk.X, pady=6)
        ttk.Label(frm, text="Domain or IP:").grid(row=0, column=0, sticky=tk.W)
        self.query = ttk.Entry(frm, width=40); self.query.grid(row=0, column=1, padx=6)
        self.query.insert(0, "example.com")
        ttk.Button(frm, text="Lookup", command=self.lookup_thread, style="Accent.TButton").grid(row=0, column=2, padx=6)
        ttk.Button(frm, text="Open uploaded file", command=self.open_uploaded).grid(row=0, column=3, padx=6)
        self.out = make_output(self, height=22); self.out.pack(fill=tk.BOTH, expand=True)

    def open_uploaded(self):
        if os.path.isfile(UPLOADED_FILE):
            try:
                with open(UPLOADED_FILE, "r", encoding="utf-8") as f:
                    txt = f.read()
                win = tk.Toplevel(self); win.title(os.path.basename(UPLOADED_FILE))
                t = scrolledtext.ScrolledText(win, width=100, height=40); t.pack(fill=tk.BOTH, expand=True); t.insert(tk.END, txt)
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showinfo("Not found", f"Uploaded file not found: {UPLOADED_FILE}")

    def lookup_thread(self):
        threading.Thread(target=self.lookup, daemon=True).start()

    def lookup(self):
        q = self.query.get().strip()
        if not q:
            messagebox.showerror("Error","Enter domain or IP"); return
        self.out.delete("1.0", tk.END)
        self.out.insert(tk.END, f"WHOIS lookup for: {q}\n\n")
        if pywhois:
            try:
                w = pywhois.whois(q)
                try:
                    txt = json.dumps(dict(w), default=str, indent=2)
                except Exception:
                    txt = str(w)
                self.out.insert(tk.END, txt + "\n")
                self.status("WHOIS: done")
                return
            except Exception as e:
                self.out.insert(tk.END, f"[python-whois failed: {e}]\n\n")
        whois_cmd = "whois"
        if platform.system().lower().startswith("win"):
            self.out.insert(tk.END, "[!] python-whois not installed and 'whois' command may be unavailable on Windows.\n")
        else:
            cmd = f"{whois_cmd} {q}"
            out = run_subprocess_capture(cmd, timeout=15)
            self.out.insert(tk.END, out + "\n")
        self.status("WHOIS: done")

# ---------------------------
# WAF Detector Frame
# ---------------------------

class WAFFrame(ttk.Frame):
    KNOWN_WAF_SIGNATURES = {
        "cloudflare": {
            "headers": ["server", "cf-ray", "cf-cache-status", "cf-request-id"],
            "server_values": ["cloudflare"]
        },
        "sucuri": { "headers": ["x-sucuri-id", "x-sucuri-cache"] },
        "incapsula": { "headers": ["x-cdn", "incapsula"], "cookies": ["visid_incap_"] },
        "akamai": { "headers": ["akamai"] },
        "f5": { "headers": ["x-bigip-server"], "server_values": ["bigip", "f5"] },
        "modsecurity": { "headers": ["x-mod-security", "mod_security"], "server_values": ["mod_security", "mod_security2"] },
        "barracuda": { "headers": ["barracuda"], "server_values": ["barracuda"] },
        "aws-waf": { "headers": ["x-amzn-requestid", "x-amz-cf-id"], "server_values": ["awselb", "amazon"] },
        "imperva": { "headers": ["x-imperva-protection", "x-ava"] }
    }

    def __init__(self, parent, status_callback):
        super().__init__(parent, padding=(12,10))
        self.status = status_callback
        self.build()

    def build(self):
        hdr = ttk.Label(self, text="WAF Detector", style="Header.TLabel"); hdr.pack(anchor=tk.W)
        frm = ttk.Frame(self); frm.pack(fill=tk.X, pady=6)
        ttk.Label(frm, text="Target URL:").grid(row=0, column=0, sticky=tk.W)
        self.url = ttk.Entry(frm, width=60); self.url.grid(row=0, column=1, padx=6); self.url.insert(0,"https://example.com")
        ttk.Button(frm, text="Detect WAF", command=self.detect_thread, style="Accent.TButton").grid(row=0, column=2, padx=6)
        ttk.Button(frm, text="Open uploaded file", command=self.open_uploaded).grid(row=0, column=3, padx=6)
        self.out = make_output(self, height=22); self.out.pack(fill=tk.BOTH, expand=True)

    def open_uploaded(self):
        if os.path.isfile(UPLOADED_FILE):
            try:
                with open(UPLOADED_FILE, "r", encoding="utf-8") as f:
                    content = f.read()
                win = tk.Toplevel(self); win.title(os.path.basename(UPLOADED_FILE))
                t = scrolledtext.ScrolledText(win, width=100, height=40); t.pack(fill=tk.BOTH, expand=True); t.insert(tk.END, content)
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showinfo("Not found", f"Uploaded file not found: {UPLOADED_FILE}")

    def detect_thread(self):
        threading.Thread(target=self.detect, daemon=True).start()

    def detect(self):
        if requests is None:
            messagebox.showerror("Error", "requests required. Install with: pip install requests")
            return
        target = self.url.get().strip()
        if not target.startswith(("http://","https://")):
            messagebox.showerror("Error","URL must start with http/https"); return
        self.out.delete("1.0", tk.END)
        self.out.insert(tk.END, f"WAF detection for {target}\n\n")
        try:
            r = requests.get(target, timeout=10, allow_redirects=True)
        except Exception as e:
            self.out.insert(tk.END, f"[ERROR] {e}\n"); return

        headers = {k.lower(): v for k,v in r.headers.items()}
        cookies = ";".join([k for k in r.cookies.keys()])
        server = headers.get("server","").lower()
        self.out.insert(tk.END, f"Status: {r.status_code}\n")
        self.out.insert(tk.END, f"Server header: {server}\n")
        self.out.insert(tk.END, f"Cookies: {cookies}\n\n")

        detections = []
        for name, sig in self.KNOWN_WAF_SIGNATURES.items():
            found = False
            hdrs = sig.get("headers", [])
            for h in hdrs:
                for hk,hv in headers.items():
                    if h in hk or (isinstance(hv, str) and h in hv.lower()):
                        found = True; break
                if found: break
            for sv in sig.get("server_values", []):
                if sv in server:
                    found = True; break
            for cpat in sig.get("cookies", []):
                if cpat.lower() in cookies.lower():
                    found = True; break
            if found:
                detections.append(name)

        try:
            probe_resp = requests.get(target.rstrip("/") + "/__waf_probe__", timeout=6, allow_redirects=True)
            if probe_resp.status_code in (403,406,429):
                detections.append("generic-blocking")
        except:
            pass

        if "cf-ray" in headers or "cf-cache-status" in headers:
            detections.append("cloudflare")

        if detections:
            self.out.insert(tk.END, "Possible WAF(s) detected:\n")
            for d in sorted(set(detections)):
                self.out.insert(tk.END, f" - {d}\n")
        else:
            self.out.insert(tk.END, "No obvious WAF detected (heuristic). Try other tests or a more advanced fingerprint tool.\n")

        self.out.insert(tk.END, "\nFull response headers:\n")
        for k,v in headers.items():
            self.out.insert(tk.END, f"{k}: {v}\n")
        self.status("WAF: done")

# ---------------------------
# Main App builder
# ---------------------------

def build_app():
    root = tk.Tk()
    root.title("HuntBox - All in One Reconnaissance Tool")
    center_window(root, w=1200, h=820)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except:
        pass

    # Basic style improvements
    style.configure("TFrame", background="#f7f9fb")
    style.configure("TLabel", background="#f7f9fb")
    style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#222")
    style.configure("TButton", padding=6)
    style.configure("Accent.TButton", foreground="white", background="#007acc")
    # Emulate accent button using map
    style.map("Accent.TButton",
              foreground=[("active", "white"), ("!disabled", "white")],
              background=[("active", "#005f9e"), ("!disabled", "#007acc")])
    # Notebook tabs
    style.configure("TNotebook.Tab", padding=[12,8], font=("Segoe UI", 10, "normal"))

    # Top toolbar
    toolbar = ttk.Frame(root, padding=(6,6))
    toolbar.pack(side=tk.TOP, fill=tk.X)
    ttk.Label(toolbar, text="HuntBox", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT)
    ttk.Separator(root, orient=tk.HORIZONTAL).pack(fill=tk.X)

    # Notebook container
    nb = ttk.Notebook(root)
    nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # status area update callback
    def set_status(msg):
        status_lbl.config(text=msg)

    nb.add(DirBusterFrame(nb, set_status), text="DirBuster")
    nb.add(DNSReconFrame(nb, set_status), text="DNSRecon")
    nb.add(SubdomainFrame(nb, set_status), text="Subdomain Finder")
    nb.add(NmapFrame(nb, set_status), text="Nmap")
    nb.add(WhoisFrame(nb, set_status), text="WHOIS Lookup")
    nb.add(WAFFrame(nb, set_status), text="WAF Detector")

    status_lbl = ttk.Label(root, text="Ready.", relief=tk.SUNKEN, anchor=tk.W)
    status_lbl.pack(side=tk.BOTTOM, fill=tk.X)

    return root

if __name__ == "__main__":
    app = build_app()
    app.mainloop()

