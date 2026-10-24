"""
PhishGuard Pro - desktop application (Tkinter, part of Python)

Open this file in IDLE and press F5 (Run > Run Module).
"""

import os
import queue
import sqlite3
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import messages
import report
import samples
import scanner
import storage

GREEN, AMBER, RED, GREY = "#1e8e3e", "#d98a00", "#d93025", "#6b7280"
COLORS = {"Looks Safe": GREEN, "Suspicious": AMBER, "Likely Phishing": RED}

SAMPLE_MESSAGE = (
    "Dear customer, your SBI account will be blocked today. Update your KYC now: "
    "http://sbi-kyc-update.xyz/login and share the OTP to confirm. Do not tell anyone."
)
SAMPLE_URLS = ["https://www.google.com", "http://paypal.secure-login.xyz/verify", "https://paypa1.com/signin"]


class ScorePanel(tk.Frame):
    """Big verdict text + coloured risk bar."""

    def __init__(self, master):
        super().__init__(master)
        self.verdict = tk.Label(self, text="Ready", font=("Helvetica", 22, "bold"), fg=GREY)
        self.verdict.pack(anchor="w")
        self.bar = tk.Canvas(self, height=22, highlightthickness=0, bg="#e5e7eb")
        self.bar.pack(fill="x", pady=(6, 2))
        self.sub = tk.Label(self, text="", fg=GREY, anchor="w", justify="left")
        self.sub.pack(anchor="w")
        self._score = 0
        self._color = GREY
        self.bar.bind("<Configure>", lambda e: self._draw())

    def _draw(self):
        self.bar.delete("all")
        w = max(self.bar.winfo_width(), 1)
        self.bar.create_rectangle(0, 0, w * self._score / 100, 30, fill=self._color, width=0)
        self.bar.create_text(8, 11, anchor="w", text=f"Risk {self._score}/100", fill="white" if self._score > 12 else "#111")

    def show(self, verdict, score, sub=""):
        self._score, self._color = int(score), COLORS.get(verdict, GREY)
        self.verdict.config(text=verdict, fg=self._color)
        self.sub.config(text=sub)
        self._draw()

    def reset(self):
        self.verdict.config(text="Ready", fg=GREY)
        self.sub.config(text="")
        self._score, self._color = 0, GREY
        self._draw()


def readonly_text(parent, height=10):
    frame = ttk.Frame(parent)
    t = tk.Text(frame, height=height, wrap="word", state="disabled", font=("Helvetica", 12), padx=8, pady=6)
    sb = ttk.Scrollbar(frame, command=t.yview)
    t.configure(yscrollcommand=sb.set)
    t.tag_configure("h", font=("Helvetica", 12, "bold"), spacing1=6)
    t.tag_configure("bad", foreground=RED)
    t.tag_configure("warn", foreground=AMBER)
    t.tag_configure("ok", foreground=GREEN)
    t.tag_configure("dim", foreground=GREY)
    sb.pack(side="right", fill="y")
    t.pack(side="left", fill="both", expand=True)
    return frame, t


def write(t, parts):
    """parts: list of (text, tag-or-None)"""
    t.config(state="normal")
    t.delete("1.0", "end")
    for text, tag in parts:
        t.insert("end", text, tag) if tag else t.insert("end", text)
    t.config(state="disabled")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PhishGuard Pro - Phishing URL & Message Detection System")
        self.geometry("1000x720")
        self.minsize(860, 620)
        self.q = queue.Queue()
        self.batch_results = []

        head = tk.Frame(self, bg="#0f172a")
        head.pack(fill="x")
        tk.Label(head, text="PhishGuard Pro", font=("Helvetica", 20, "bold"), fg="white", bg="#0f172a").pack(side="left", padx=14, pady=10)
        tk.Label(head, text="Python-Based Phishing URL Detection System", fg="#94a3b8", bg="#0f172a").pack(side="left")

        self.status = tk.Label(self, anchor="w", fg=GREY, text=self._model_status())
        self.status.pack(side="bottom", fill="x", padx=12, pady=(0, 6))
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=10)
        self.t_url, self.t_msg, self.t_batch, self.t_hist, self.t_about = (ttk.Frame(self.nb) for _ in range(5))
        for tab, name in ((self.t_url, "  URL Scan  "), (self.t_msg, "  Message Scan  "), (self.t_batch, "  Batch Scan  "),
                          (self.t_hist, "  History  "), (self.t_about, "  About  ")):
            self.nb.add(tab, text=name)
        self._url_tab()
        self._msg_tab()
        self._batch_tab()
        self._hist_tab()
        self._about_tab()
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.refresh_history() if self.nb.index("current") == 3 else None)

        self.after(150, self._poll)

    # ------------------------------------------------------------ helpers
    def _model_status(self):
        m = scanner.get_model()
        if not m:
            return "ML model: not found (rules only). Run train.py to create one."
        src = m["meta"].get("source", "unknown")
        demo = "  -  DEMO model, retrain on real data for real accuracy" if "demo" in src else ""
        return f"ML model loaded (trained on {m['meta'].get('trained_on', '?')} domain names, source: {src}){demo}"

    def _log(self, *args):
        """Save to history; a read-only folder must never break scanning."""
        try:
            storage.add_scan(*args)
        except (OSError, sqlite3.Error):
            pass

    def run_bg(self, func, done):
        """Run func in a thread so the window never freezes; call done(result|Exception) in the UI thread."""
        def work():
            try:
                self.q.put((done, func()))
            except Exception as e:                     # noqa: BLE001 - shown to the user
                self.q.put((done, e))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                done, res = self.q.get_nowait()
                done(res)
        except queue.Empty:
            pass
        self.after(120, self._poll)

    # ------------------------------------------------------------ URL tab
    def _url_tab(self):
        f = self.t_url
        top = ttk.Frame(f)
        top.pack(fill="x", padx=14, pady=(14, 4))
        ttk.Label(top, text="URL:").pack(side="left")
        self.url_var = tk.StringVar()
        e = ttk.Entry(top, textvariable=self.url_var)
        e.pack(side="left", fill="x", expand=True, padx=8)
        e.bind("<Return>", lambda ev: self.scan_url())
        e.focus_set()
        self.url_btn = ttk.Button(top, text="Scan", command=self.scan_url)
        self.url_btn.pack(side="left")
        ttk.Button(top, text="Clear", command=self._url_clear).pack(side="left", padx=(6, 0))

        opts = ttk.Frame(f)
        opts.pack(fill="x", padx=14)
        self.deep_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Deep scan (contacts the website: DNS, SSL certificate, redirects)", variable=self.deep_var).pack(side="left")
        ttk.Label(opts, text="   Try:").pack(side="left")
        for s in SAMPLE_URLS:
            ttk.Button(opts, text=s.split("//")[1].split("/")[0], command=lambda s=s: (self.url_var.set(s), self.scan_url())).pack(side="left", padx=2)

        ex = ttk.Frame(f)
        ex.pack(fill="x", padx=14, pady=(8, 0))
        ttk.Label(ex, text="Real examples:").pack(side="left")
        self._url_examples = ([("REAL phishing (public feed)  " + u[:60], u) for u in samples.REAL_PHISHING]
                              + [("GENUINE site  " + u[:60], u) for u in samples.REAL_LEGIT])
        box = ttk.Combobox(ex, state="readonly", values=[l for l, _ in self._url_examples], width=88)
        box.set("Choose a real phishing link or a genuine site...")
        box.pack(side="left", padx=8)
        box.bind("<<ComboboxSelected>>", lambda e: (self.url_var.set(self._url_examples[box.current()][1]), self.scan_url()))
        self.url_panel = ScorePanel(f)
        self.url_panel.pack(fill="x", padx=14, pady=12)
        box, self.url_text = readonly_text(f, 14)
        box.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        write(self.url_text, [("Type or paste a link above and press Enter.\n", "dim"),
                              ("The URL is analysed as text only - it is never opened (unless you tick Deep scan).", "dim")])

    def _url_clear(self):
        self.url_var.set("")
        self.url_panel.reset()
        write(self.url_text, [])

    def scan_url(self):
        url = self.url_var.get().strip()
        if not url:
            return
        deep = self.deep_var.get()
        self.url_btn.config(state="disabled")
        self.url_panel.show("Scanning...", 0, "Deep scan can take a few seconds" if deep else "")
        self.run_bg(lambda: scanner.scan_url(url, deep=deep), self._url_done)

    def _url_done(self, res):
        self.url_btn.config(state="normal")
        if isinstance(res, Exception):
            self.url_panel.reset()
            write(self.url_text, [("Could not scan: ", "bad"), (str(res), None)])
            return
        ml = "n/a" if res["ml_prob"] is None else f"{res['ml_prob']:.0%}"
        self.url_panel.show(res["verdict"], res["score"], f"Rule score {res['rule_score']}/100   |   ML phishing probability {ml}")
        tag = {"Looks Safe": "ok", "Suspicious": "warn", "Likely Phishing": "bad"}[res["verdict"]]
        parts = [("Why this verdict\n", "h")]
        parts += [(f"  • {r}\n", tag if res["verdict"] != "Looks Safe" else None) for r in res["reasons"]]
        d = res["details"]
        parts += [("\nTechnical details\n", "h"),
                  (f"  Host: {d['host']}\n  Registered domain: {d['registered_domain']}\n  Scheme: {d['scheme']}\n"
                   f"  URL length: {d['url_length']}   Subdomains: {d['subdomains']}   Host entropy: {d['host_entropy']}\n", "dim")]
        if res["deep"]:
            parts.append(("\nDeep scan\n", "h"))
            ip = res["deep"].get("ip")
            parts.append((f"  Resolved IP: {ip or 'none'}\n", "dim"))
            parts += [(f"  {n}\n", "dim") for n in res["deep"]["notes"]]
        parts.append(("\nThis is a preliminary automated check; it cannot prove a site is safe or phishing.", "dim"))
        write(self.url_text, parts)
        self._log("url", res["url"], res["verdict"], res["score"], res["reasons"])

    # ------------------------------------------------------------ Message tab
    def _msg_tab(self):
        f = self.t_msg
        ttk.Label(f, text="Paste an SMS / WhatsApp / e-mail message:").pack(anchor="w", padx=14, pady=(14, 4))
        self.msg_in = tk.Text(f, height=6, wrap="word", font=("Helvetica", 12), padx=8, pady=6)
        self.msg_in.pack(fill="x", padx=14)
        row = ttk.Frame(f)
        row.pack(fill="x", padx=14, pady=8)
        self.msg_btn = ttk.Button(row, text="Scan Message", command=self.scan_msg)
        self.msg_btn.pack(side="left")
        ttk.Button(row, text="Paste sample scam", command=lambda: (self.msg_in.delete("1.0", "end"), self.msg_in.insert("1.0", SAMPLE_MESSAGE))).pack(side="left", padx=6)
        ttk.Button(row, text="Clear", command=lambda: self.msg_in.delete("1.0", "end")).pack(side="left")
        mbox = ttk.Combobox(row, state="readonly", values=[l for l, _ in samples.MESSAGES], width=34)
        mbox.set("Real-style examples...")
        mbox.pack(side="left", padx=6)
        mbox.bind("<<ComboboxSelected>>", lambda e: (self.msg_in.delete("1.0", "end"),
                                                      self.msg_in.insert("1.0", samples.MESSAGES[mbox.current()][1]),
                                                      self.scan_msg()))
        self.msg_deep = tk.BooleanVar()
        ttk.Checkbutton(row, text="Deep scan links", variable=self.msg_deep).pack(side="left", padx=12)
        self.msg_panel = ScorePanel(f)
        self.msg_panel.pack(fill="x", padx=14, pady=4)
        box, self.msg_text = readonly_text(f, 9)
        box.pack(fill="both", expand=True, padx=14, pady=(6, 14))
        write(self.msg_text, [("Scam messages often combine pressure words (urgent, blocked, KYC, OTP) with a fake link.\n"
                               "This tab checks both the wording and every link inside the message.", "dim")])

    def scan_msg(self):
        text = self.msg_in.get("1.0", "end").strip()
        if not text:
            return
        deep = self.msg_deep.get()
        self.msg_btn.config(state="disabled")
        self.run_bg(lambda: messages.scan_message(text, deep=deep), self._msg_done)

    def _msg_done(self, res):
        self.msg_btn.config(state="normal")
        if isinstance(res, Exception):
            write(self.msg_text, [("Could not scan: ", "bad"), (str(res), None)])
            return
        self.msg_panel.show(res["verdict"], res["score"], f"Wording score {res['language_score']}/100   |   {len(res['links'])} link(s) found")
        tag = {"Looks Safe": "ok", "Suspicious": "warn", "Likely Phishing": "bad"}[res["verdict"]]
        parts = [("Why this verdict\n", "h")] + [(f"  • {r}\n", tag if res["verdict"] != "Looks Safe" else None) for r in res["reasons"]]
        if res["links"]:
            parts.append(("\nLinks found\n", "h"))
            for r in res["links"]:
                parts.append((f"  [{r['verdict']} {r['score']}/100] {r['url']}\n", {"Looks Safe": "ok", "Suspicious": "warn", "Likely Phishing": "bad"}[r["verdict"]]))
        write(self.msg_text, parts)
        self._log("message", self.msg_in.get("1.0", "end").strip(), res["verdict"], res["score"], res["reasons"])

    # ------------------------------------------------------------ Batch tab
    def _batch_tab(self):
        f = self.t_batch
        row = ttk.Frame(f)
        row.pack(fill="x", padx=14, pady=14)
        ttk.Button(row, text="Open .txt / .csv file of URLs...", command=self.open_batch).pack(side="left")
        self.exp_csv = ttk.Button(row, text="Export CSV", command=lambda: self.export("csv"), state="disabled")
        self.exp_csv.pack(side="left", padx=6)
        self.exp_html = ttk.Button(row, text="Export HTML report", command=lambda: self.export("html"), state="disabled")
        self.exp_html.pack(side="left")
        self.batch_info = ttk.Label(row, text="")
        self.batch_info.pack(side="left", padx=12)
        self.batch_tree = self._tree(f, ("verdict", "score", "url"), ("Verdict", "Score", "URL"), (130, 60, 700))
        self.batch_tree.master.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.batch_tree.bind("<<TreeviewSelect>>", self._batch_select)
        self.batch_why = tk.Label(f, text="", anchor="w", justify="left", fg=GREY, wraplength=900)
        self.batch_why.pack(fill="x", padx=14, pady=(0, 10))

    def _tree(self, parent, cols, heads, widths):
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=cols, show="headings", height=14)
        for c, h, w in zip(cols, heads, widths):
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        for name, col in COLORS.items():
            tree.tag_configure(name, foreground=col)
        return tree

    def open_batch(self):
        path = filedialog.askopenfilename(title="Choose a file of URLs", filetypes=[("URL lists", "*.txt *.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            urls = scanner.read_url_file(path)
        except OSError as e:
            messagebox.showerror("PhishGuard Pro", f"Could not read the file:\n{e}")
            return
        self.batch_info.config(text=f"Scanning {len(urls)} URLs...")
        self.run_bg(lambda: scanner.scan_many(urls), self._batch_done)

    def _batch_done(self, res):
        if isinstance(res, Exception):
            self.batch_info.config(text=f"Error: {res}")
            return
        results, errors = res
        self.batch_results = sorted(results, key=lambda r: -r["score"])
        self.batch_tree.delete(*self.batch_tree.get_children())
        for i, r in enumerate(self.batch_results):
            self.batch_tree.insert("", "end", iid=str(i), values=(r["verdict"], r["score"], r["url"]), tags=(r["verdict"],))
        c = {k: sum(1 for r in results if r["verdict"] == k) for k in COLORS}
        self.batch_info.config(text=f"{len(results)} scanned | Safe {c['Looks Safe']} | Suspicious {c['Suspicious']} | Phishing {c['Likely Phishing']}"
                                    + (f" | {len(errors)} skipped" if errors else ""))
        state = "normal" if results else "disabled"
        self.exp_csv.config(state=state)
        self.exp_html.config(state=state)
        for r in results:
            self._log("batch", r["url"], r["verdict"], r["score"], r["reasons"])

    def _batch_select(self, _):
        sel = self.batch_tree.selection()
        if sel:
            r = self.batch_results[int(sel[0])]
            self.batch_why.config(text="Why: " + "  •  ".join(r["reasons"]))

    def export(self, kind):
        if not self.batch_results:
            return
        ext = ".csv" if kind == "csv" else ".html"
        path = filedialog.asksaveasfilename(defaultextension=ext, initialfile="phishguard_report" + ext)
        if not path:
            return
        (report.to_csv if kind == "csv" else report.to_html)(self.batch_results, path)
        messagebox.showinfo("PhishGuard Pro", f"Saved:\n{path}")

    # ------------------------------------------------------------ History tab
    def _hist_tab(self):
        f = self.t_hist
        row = ttk.Frame(f)
        row.pack(fill="x", padx=14, pady=14)
        ttk.Button(row, text="Refresh", command=self.refresh_history).pack(side="left")
        ttk.Button(row, text="Clear history", command=self.clear_history).pack(side="left", padx=6)
        self.hist_info = ttk.Label(row, text="")
        self.hist_info.pack(side="left", padx=12)
        self.hist_tree = self._tree(f, ("ts", "kind", "verdict", "score", "input"), ("Time", "Type", "Verdict", "Score", "Input"), (150, 70, 120, 55, 560))
        self.hist_tree.master.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def refresh_history(self):
        self.hist_tree.delete(*self.hist_tree.get_children())
        for ts, kind, text, verdict, score in storage.recent():
            self.hist_tree.insert("", "end", values=(ts, kind, verdict, score, text.replace("\n", " ")), tags=(verdict,))
        s = storage.stats()
        self.hist_info.config(text=f"Total {s['total']} | Safe {s['Looks Safe']} | Suspicious {s['Suspicious']} | Phishing {s['Likely Phishing']}")

    def clear_history(self):
        if messagebox.askyesno("PhishGuard Pro", "Delete all saved scans?"):
            storage.clear()
            self.refresh_history()

    # ------------------------------------------------------------ About tab
    def _about_tab(self):
        box, t = readonly_text(self.t_about, 30)
        box.pack(fill="both", expand=True, padx=14, pady=14)
        write(t, [
            ("How PhishGuard Pro decides\n", "h"),
            ("1. Rule engine  - 25+ checks on the URL text: IP addresses, '@' tricks, look-alike / typosquatted domains "
             "(paypa1.com), brand names in foreign domains, risky TLDs, shorteners, free hosting, punycode, random-looking domains, "
             ".apk links, open redirects, scam keywords.\n"
             "2. Machine learning - a logistic-regression model written from scratch in Python. It judges the domain name "
             "(features + character n-grams) and was trained on real phishing domains vs real popular domains. "
             "It can raise a score but never lowers one, and it cannot accuse alone.\n"
             "3. Message analysis - detects scam wording (urgency, KYC, OTP requests, fake prizes, parcel fees, APK installs).\n"
             "4. Deep scan (optional) - DNS, SSL certificate age/validity, and redirect chain.\n\n", None),
            ("Verdicts\n", "h"),
            ("0-24 Looks Safe   |   25-54 Suspicious   |   55-100 Likely Phishing\n\n", None),
            ("Measured on real data (see EVALUATION.md)\n", "h"),
            ("On 9,481 real phishing URLs the tool had never seen: 77% flagged (22% as Likely Phishing). "
             "False alarms on 3,106 genuine URLs: 2.3% (0% as Likely Phishing). Most misses are normal-looking, "
             "hacked websites that a URL check cannot see.\n\n", None),
            ("Honest limits\n", "h"),
            ("A URL-text check can miss phishing on a clean-looking or compromised domain, and can flag unusual but legitimate links. "
             "Treat results as a warning, not proof. Never enter passwords on a link you are unsure about - open the official app or "
             "type the official address yourself.\n\n", None),
            ("Pure Python. Standard library only: tkinter, sqlite3, urllib, ssl, socket.\n", "dim"),
        ])


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
