"""
ThreatScope V2 — Premium Desktop GUI
Author: 0xSABRY

Professional DFIR analysis interface built with CustomTkinter.
Premium dark theme with refined color palette and polished output.
"""

import sys
import math
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import customtkinter as ctk

from config import VERSION, APP_NAME
from core.analyzer import LogAnalyzer
from ai.ai_core import NarrativeEngine, AnalystCopilot
from export.exporters import export_json, export_csv, export_stix

try:
    from export.exporters import export_pdf
    PDF_OK = True
except Exception:
    PDF_OK = False
try:
    from export.exporters import export_docx
    DOCX_OK = True
except Exception:
    DOCX_OK = False


# ════════════════════════════════════════════════════════════════
# Premium Color System
# ════════════════════════════════════════════════════════════════
C = {
    # Backgrounds — layered depth system
    "bg0":      "#05080f",       # Deepest background
    "bg1":      "#0a1020",       # Primary card background
    "bg2":      "#0f1830",       # Elevated card / hover
    "bg3":      "#162040",       # Input fields / active areas
    "sidebar":  "#070c18",       # Sidebar — slightly different tone

    # Borders — subtle, refined
    "border":   "#1a2a50",       # Default border
    "border_h": "#2a3a6a",       # Hover / active border
    "border_g": "#0d9488",       # Glowing accent border (teal)

    # Accent Colors — premium trio
    "cyan":     "#22d3ee",       # Primary accent — electric cyan
    "teal":     "#14b8a6",       # Secondary accent — teal
    "indigo":   "#818cf8",       # Tertiary accent — soft indigo
    "gold":     "#fbbf24",       # Highlight / premium indicator
    "emerald":  "#34d399",       # Success / positive

    # Severity — vivid but refined
    "critical": "#f43f5e",       # Rose red
    "high":     "#fb923c",       # Warm orange
    "medium":   "#facc15",       # Bright yellow
    "low":      "#60a5fa",       # Sky blue

    # Text — clear hierarchy
    "t1":       "#f1f5f9",       # Primary text — almost white
    "t2":       "#94a3b8",       # Secondary text — cool gray
    "t3":       "#475569",       # Muted text — slate
    "t4":       "#1e293b",       # Very muted — barely visible
}

SEV = {"critical": C["critical"], "high": C["high"],
       "medium": C["medium"], "low": C["low"]}

# Typography
F  = "Segoe UI"
FM = "Consolas"
FB = (F, 13, "bold")


# ════════════════════════════════════════════════════════════════
# Premium Symbols & Decorators
# ════════════════════════════════════════════════════════════════
SYM = {
    "critical": "\u25cf",  # ●
    "high":     "\u25cf",
    "medium":   "\u25cf",
    "low":      "\u25cf",
    "bullet":   "\u25b8",  # ▸
    "arrow":    "\u25ba",  # ►
    "check":    "\u2713",  # ✓
    "cross":    "\u2717",  # ✗
    "diamond":  "\u25c6",  # ◆
    "star":     "\u2605",  # ★
    "dash":     "\u2500",  # ─
    "ddash":    "\u2550",  # ═
    "vline":    "\u2502",  # │
    "corner":   "\u2514",  # └
    "tee":      "\u251c",  # ├
    "dot":      "\u00b7",  # ·
}

# Decorative line builders
def hline(char="\u2500", width=80):
    return char * width

def section_header(title, width=80):
    pad = width - len(title) - 4
    left = pad // 2
    right = pad - left
    return f"\u2552{'═' * left} {title} {'═' * right}\u2555"

def section_footer(width=80):
    return f"\u2558{'═' * (width - 2)}\u255b"


# ════════════════════════════════════════════════════════════════
# Canvas Charts (instant render, premium style)
# ════════════════════════════════════════════════════════════════
def draw_donut(canvas, w, h, data, colors):
    canvas.delete("all")
    total = sum(data.values())
    if total == 0:
        canvas.create_text(w//2, h//2, text="No findings", fill=C["t3"], font=(F, 13))
        return

    cx, cy = w // 2, h // 2
    r = min(w, h) // 2 - 35
    inner = r * 0.58
    start = 90

    for label, val in data.items():
        if val == 0:
            continue
        ext = -(val / total) * 360
        col = colors.get(label, C["t3"])

        # Draw arc
        canvas.create_arc(cx-r, cy-r, cx+r, cy+r, start=start, extent=ext,
                          fill=col, outline=C["bg1"], width=2, style="pieslice")

        # Label on arc
        mid = math.radians(start + ext / 2)
        lx = cx + (r + 22) * math.cos(mid)
        ly = cy - (r + 22) * math.sin(mid)
        pct = f"{val/total*100:.0f}%"
        canvas.create_text(lx, ly, text=f"{label} {pct}", fill=col,
                           font=(F, 9, "bold"))
        start += ext

    # Center hole
    canvas.create_oval(cx-inner, cy-inner, cx+inner, cy+inner,
                       fill=C["bg1"], outline=C["bg1"])
    canvas.create_text(cx, cy - 10, text=str(total), fill=C["t1"], font=(F, 26, "bold"))
    canvas.create_text(cx, cy + 16, text="findings", fill=C["t3"], font=(F, 10))


def draw_bars(canvas, w, h, data, color=None, n=8):
    canvas.delete("all")
    if not data:
        canvas.create_text(w//2, h//2, text="No data", fill=C["t3"], font=(F, 13))
        return

    items = data[:n]
    mx = max(v for _, v in items) or 1
    bh = max(14, min(22, (h - 16) // len(items) - 5))
    y = 8
    lbl_w = 145
    bar_end = w - 55

    for label, val in items:
        disp = label if len(label) <= 20 else label[:18] + ".."
        canvas.create_text(8, y + bh//2, text=disp, fill=C["t2"], font=(FM, 9), anchor="w")

        # Bar background
        canvas.create_rectangle(lbl_w, y+1, bar_end, y+bh-1, fill=C["bg3"], outline="")
        # Bar fill
        bw = max(3, int((bar_end - lbl_w) * (val / mx)))
        c = color or C["cyan"]
        canvas.create_rectangle(lbl_w, y+1, lbl_w + bw, y+bh-1, fill=c, outline="")
        # Value
        canvas.create_text(bar_end + 8, y + bh//2, text=str(val), fill=C["t2"],
                           font=(FM, 9), anchor="w")
        y += bh + 4


# ════════════════════════════════════════════════════════════════
# Main Application
# ════════════════════════════════════════════════════════════════
class ThreatScopeGUI(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} V{VERSION} \u2014 Advanced DFIR Platform")
        self.geometry("1480x900")
        self.minsize(1100, 650)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=C["bg0"])

        self.analyzer = None
        self.results = None
        self.copilot = AnalystCopilot()
        self.narrative_engine = NarrativeEngine()
        self.current_page = "dashboard"

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

        # Main content with subtle left border
        self.main = ctk.CTkFrame(self, fg_color=C["bg0"], corner_radius=0)
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(0, weight=1)

        self.pages = {}
        self._show("dashboard")

    # ════════════════════════════════════════════════════════════
    # Sidebar
    # ════════════════════════════════════════════════════════════
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=C["sidebar"],
                           border_width=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)

        # ── Brand ──
        brand = ctk.CTkFrame(sb, fg_color="transparent")
        brand.pack(fill="x", padx=22, pady=(28, 0))
        ctk.CTkLabel(brand, text="\u2b22 THREATSCOPE", font=(F, 19, "bold"),
                     text_color=C["cyan"]).pack(anchor="w")
        ctk.CTkLabel(brand, text=f"V{VERSION}  {SYM['dot']}  0xSABRY", font=(F, 10),
                     text_color=C["t3"]).pack(anchor="w", pady=(2, 0))

        # ── Accent line ──
        ctk.CTkFrame(sb, height=2, fg_color=C["teal"]).pack(fill="x", padx=22, pady=(16, 14))

        # ── File controls ──
        self.file_lbl = ctk.CTkLabel(sb, text="\u25cb  No file loaded", font=(F, 10),
                                      text_color=C["t3"], wraplength=195)
        self.file_lbl.pack(padx=22, anchor="w")

        bf = ctk.CTkFrame(sb, fg_color="transparent")
        bf.pack(fill="x", padx=18, pady=(10, 0))

        self.btn_browse = ctk.CTkButton(
            bf, text=f"{SYM['arrow']}  Browse File", height=40, font=(F, 13, "bold"),
            fg_color=C["cyan"], hover_color="#0ea5e9", text_color="#000",
            corner_radius=8, command=self._browse)
        self.btn_browse.pack(fill="x")

        self.btn_analyze = ctk.CTkButton(
            bf, text=f"{SYM['diamond']}  Analyze", height=40, font=(F, 13, "bold"),
            fg_color=C["emerald"], hover_color="#10b981", text_color="#000",
            corner_radius=8, command=self._analyze, state="disabled")
        self.btn_analyze.pack(fill="x", pady=(6, 0))

        self.prog = ctk.CTkProgressBar(sb, mode="indeterminate",
                                        progress_color=C["cyan"], height=3)
        self.status_lbl = ctk.CTkLabel(sb, text="", font=(F, 10),
                                        text_color=C["cyan"])
        self.status_lbl.pack(padx=22, pady=(6, 0), anchor="w")

        # ── Nav divider ──
        ctk.CTkFrame(sb, height=1, fg_color=C["border"]).pack(fill="x", padx=18, pady=14)

        # ── Navigation ──
        nav = [
            ("dashboard",  f"{SYM['diamond']}  Dashboard"),
            ("findings",   f"{SYM['bullet']}  Findings"),
            ("timeline",   f"{SYM['bullet']}  Timeline"),
            ("mitre",      f"{SYM['bullet']}  MITRE ATT&CK"),
            ("iocs",       f"{SYM['bullet']}  IOCs"),
            ("copilot",    f"{SYM['star']}  AI Copilot"),
            ("narrative",  f"{SYM['star']}  Narrative"),
            ("export",     f"{SYM['bullet']}  Export"),
        ]

        self.nav_btns = {}
        for key, label in nav:
            b = ctk.CTkButton(
                sb, text=label, height=36, font=(F, 13),
                fg_color="transparent", hover_color=C["bg2"],
                text_color=C["t2"], anchor="w", corner_radius=6,
                command=lambda k=key: self._show(k))
            b.pack(fill="x", padx=12, pady=1)
            self.nav_btns[key] = b

        # ── Bottom ──
        bot = ctk.CTkFrame(sb, fg_color="transparent")
        bot.pack(side="bottom", fill="x", padx=22, pady=16)
        ctk.CTkFrame(bot, height=1, fg_color=C["border"]).pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(bot, text=f"{SYM['diamond']} github.com/0xsabry", font=(F, 9),
                     text_color=C["t3"]).pack(anchor="w")

    # ════════════════════════════════════════════════════════════
    # Navigation
    # ════════════════════════════════════════════════════════════
    def _show(self, page):
        self.current_page = page
        for k, b in self.nav_btns.items():
            if k == page:
                b.configure(fg_color=C["bg2"], text_color=C["cyan"])
            else:
                b.configure(fg_color="transparent", text_color=C["t2"])

        for p in self.pages.values():
            p.grid_forget()

        if page not in self.pages:
            builder = getattr(self, f"_pg_{page}", None)
            self.pages[page] = builder() if builder else self._pg_empty()
        self.pages[page].grid(row=0, column=0, sticky="nsew")

    def _pg_empty(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg0"])
        ctk.CTkLabel(f, text="Coming soon", font=(F, 16), text_color=C["t3"]
                     ).place(relx=.5, rely=.5, anchor="center")
        return f

    # ════════════════════════════════════════════════════════════
    # File & Analysis
    # ════════════════════════════════════════════════════════════
    def _browse(self):
        fp = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("All Supported", "*.evtx *.log *.txt *.json *.csv *.xml *.syslog"),
                       ("Windows Event Log", "*.evtx"), ("Log Files", "*.log *.txt"),
                       ("JSON", "*.json"), ("All", "*.*")])
        if fp:
            self.analyzer = LogAnalyzer(fp)
            self.file_lbl.configure(text=f"\u25cf  {Path(fp).name}", text_color=C["emerald"])
            self.btn_analyze.configure(state="normal")
            self.status_lbl.configure(text=f"{SYM['check']} Ready", text_color=C["emerald"])

    def _analyze(self):
        if not self.analyzer:
            return
        self.btn_analyze.configure(state="disabled")
        self.btn_browse.configure(state="disabled")
        self.prog.pack(fill="x", padx=18, pady=(4, 0))
        self.prog.start()
        self.status_lbl.configure(text="Loading...", text_color=C["cyan"])

        def work():
            try:
                self.analyzer.load()
                n = self.analyzer.total_lines
                self.after(0, lambda: self.status_lbl.configure(
                    text=f"Analyzing {n:,} events..."))
                r = self.analyzer.analyze()
                self.results = r
                self.copilot.set_context(r)
                self.after(0, self._done)
            except Exception as e:
                self.after(0, lambda: self._fail(str(e)))

        threading.Thread(target=work, daemon=True).start()

    def _done(self):
        self.prog.stop()
        self.prog.pack_forget()
        self.btn_analyze.configure(state="normal")
        self.btn_browse.configure(state="normal")
        s = self.results["threat_score"]
        lv = self.results["threat_level"]
        sc = C["critical"] if s >= 60 else C["high"] if s >= 30 else C["emerald"]
        self.status_lbl.configure(text=f"{SYM['check']} {s}% {lv}", text_color=sc)

        for k in list(self.pages.keys()):
            self.pages[k].destroy()
            del self.pages[k]
        self._show("dashboard")

    def _fail(self, err):
        self.prog.stop()
        self.prog.pack_forget()
        self.btn_analyze.configure(state="normal")
        self.btn_browse.configure(state="normal")
        self.status_lbl.configure(text=f"{SYM['cross']} Error", text_color=C["critical"])
        messagebox.showerror("Analysis Error", err)

    # ════════════════════════════════════════════════════════════
    # UI Helpers
    # ════════════════════════════════════════════════════════════
    def _card(self, parent, accent_color=None):
        """Premium card with optional colored top accent."""
        outer = ctk.CTkFrame(parent, fg_color="transparent")
        if accent_color:
            ctk.CTkFrame(outer, height=3, fg_color=accent_color,
                          corner_radius=2).pack(fill="x", padx=4)
        card = ctk.CTkFrame(outer, corner_radius=10, fg_color=C["bg1"],
                              border_width=1, border_color=C["border"])
        card.pack(fill="both", expand=True)
        return outer, card

    def _stat_card(self, parent, label, value, color=None, accent=None):
        """Premium stat card with top accent strip."""
        outer, card = self._card(parent, accent_color=accent or color)
        ctk.CTkLabel(card, text=str(value), font=(F, 34, "bold"),
                     text_color=color or C["cyan"]).pack(padx=16, pady=(16, 0))
        ctk.CTkLabel(card, text=label, font=(F, 11),
                     text_color=C["t2"]).pack(padx=16, pady=(2, 16))
        return outer

    def _header(self, parent, title, subtitle=None):
        """Page header with accent underline."""
        hf = ctk.CTkFrame(parent, fg_color="transparent")
        hf.pack(fill="x", padx=20, pady=(20, 4))
        ctk.CTkLabel(hf, text=title, font=(F, 22, "bold"),
                     text_color=C["t1"]).pack(side="left")
        if subtitle:
            ctk.CTkLabel(hf, text=f"  {SYM['dot']}  {subtitle}", font=(F, 12),
                         text_color=C["t3"]).pack(side="left", padx=(8, 0))
        ctk.CTkFrame(parent, height=2, fg_color=C["border"]).pack(fill="x", padx=20, pady=(6, 10))
        return hf

    def _textbox(self, parent, **kw):
        """Premium textbox with refined styling."""
        return ctk.CTkTextbox(parent, font=(FM, 12), fg_color=C["bg1"],
                               text_color=C["t1"], border_width=1,
                               border_color=C["border"], corner_radius=10,
                               wrap="word", activate_scrollbars=True, **kw)

    # ════════════════════════════════════════════════════════════
    # Premium Text Formatters
    # ════════════════════════════════════════════════════════════
    def _fmt_finding(self, f):
        """Format a single finding as premium text block."""
        sev = f.get("severity", "low").upper()
        title = f.get("title", "Unknown")
        desc = f.get("description", "")
        mitre = f.get("mitre", "")
        ts = f.get("timestamp", "")
        ln = f.get("line_number", "")

        sym = SYM.get(sev.lower(), SYM["bullet"])
        lines = [f"  {sym} [{sev}]  {title}"]
        if mitre:
            lines[0] += f"   {SYM['diamond']} {mitre}"
        if desc:
            lines.append(f"    {SYM['corner']} {desc}")
        meta = []
        if ts:
            meta.append(f"Time: {ts}")
        if ln:
            meta.append(f"Line: {ln}")
        if meta:
            lines.append(f"    {SYM['corner']} {' | '.join(meta)}")
        return "\n".join(lines)

    def _fmt_section(self, title, items, indent="  "):
        """Format a labeled section with items."""
        lines = [f"\n{section_header(title)}\n"]
        for item in items:
            lines.append(f"{indent}{SYM['bullet']} {item}")
        lines.append(f"{section_footer()}")
        return "\n".join(lines)

    # ════════════════════════════════════════════════════════════
    # PAGE: Dashboard
    # ════════════════════════════════════════════════════════════
    def _pg_dashboard(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg0"])

        if not self.results:
            # Premium empty state
            ef = ctk.CTkFrame(f, fg_color="transparent")
            ef.place(relx=0.5, rely=0.42, anchor="center")

            ctk.CTkLabel(ef, text="\u2b22", font=(F, 48),
                         text_color=C["cyan"]).pack()
            ctk.CTkLabel(ef, text="THREATSCOPE", font=(F, 44, "bold"),
                         text_color=C["t1"]).pack(pady=(4, 0))
            ctk.CTkLabel(ef, text="Advanced DFIR & Threat Detection Platform",
                         font=(F, 14), text_color=C["t2"]).pack(pady=(4, 0))
            ctk.CTkLabel(ef, text=f"V{VERSION}  {SYM['dot']}  by 0xSABRY",
                         font=(F, 11), text_color=C["t3"]).pack(pady=(4, 28))

            # Feature grid
            features = [
                f"{SYM['diamond']} 115+ Detection Rules",
                f"{SYM['diamond']} Sigma & YARA Engine",
                f"{SYM['diamond']} MITRE ATT&CK Mapping",
                f"{SYM['diamond']} Behavioral Chain Analysis",
                f"{SYM['diamond']} IOC Extraction & Correlation",
                f"{SYM['diamond']} AI-Powered Narrative Engine",
            ]
            fg = ctk.CTkFrame(ef, fg_color="transparent")
            fg.pack()
            fg.grid_columnconfigure((0, 1), weight=1)
            for i, feat in enumerate(features):
                ctk.CTkLabel(fg, text=feat, font=(F, 11),
                             text_color=C["teal"]).grid(row=i//2, column=i%2,
                             sticky="w", padx=16, pady=2)

            ctk.CTkFrame(ef, height=2, fg_color=C["border"]).pack(fill="x", pady=(24, 16), padx=60)
            ctk.CTkLabel(ef, text=f"{SYM['arrow']}  Browse a log file to begin analysis",
                         font=(F, 12), text_color=C["t3"]).pack()
            return f

        # ═══ With Results ═══
        r = self.results
        sm = r["summary"]
        score = r["threat_score"]
        level = r["threat_level"]

        scroll = ctk.CTkScrollableFrame(f, fg_color="transparent",
                                         scrollbar_button_color=C["border"],
                                         scrollbar_button_hover_color=C["teal"])
        scroll.pack(fill="both", expand=True)

        # ── Score Banner ──
        score_color = C["critical"] if score >= 60 else C["high"] if score >= 30 else C["emerald"]
        outer, banner = self._card(scroll, accent_color=score_color)
        outer.pack(fill="x", padx=14, pady=(10, 8))

        bi = ctk.CTkFrame(banner, fg_color="transparent")
        bi.pack(fill="x", padx=24, pady=20)
        bi.grid_columnconfigure(1, weight=1)

        # Left: Score
        lf = ctk.CTkFrame(bi, fg_color="transparent")
        lf.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(lf, text=f"{score}%", font=(F, 58, "bold"),
                     text_color=score_color).pack(anchor="w")
        ctk.CTkLabel(lf, text=f"{SYM['diamond']}  THREAT LEVEL: {level}",
                     font=(F, 15, "bold"), text_color=score_color).pack(anchor="w")

        # Right: Metadata
        rf = ctk.CTkFrame(bi, fg_color="transparent")
        rf.grid(row=0, column=1, sticky="e")
        meta = r["metadata"]
        fname = Path(meta.get("filepath", "")).name or "Unknown"
        time_range = meta.get("time_range", {})

        meta_lines = [
            (f"{SYM['bullet']}  File:", fname),
            (f"{SYM['bullet']}  Events:", f"{meta.get('total_events', 0):,}"),
            (f"{SYM['bullet']}  Sigma:", f"{meta.get('sigma_rules_loaded', 0)} rules"),
            (f"{SYM['bullet']}  YARA:", f"{meta.get('yara_rules_loaded', 0)} rules"),
        ]
        for lbl, val in meta_lines:
            row = ctk.CTkFrame(rf, fg_color="transparent")
            row.pack(anchor="e")
            ctk.CTkLabel(row, text=lbl, font=(F, 11),
                         text_color=C["t3"]).pack(side="left", padx=(0, 4))
            ctk.CTkLabel(row, text=val, font=(F, 11, "bold"),
                         text_color=C["t2"]).pack(side="left")

        # ── Stats Row ──
        sf = ctk.CTkFrame(scroll, fg_color="transparent")
        sf.pack(fill="x", padx=14, pady=(0, 8))
        sf.grid_columnconfigure((0,1,2,3,4,5), weight=1)

        stats = [
            ("Findings", sm["total_findings"], C["cyan"],     C["cyan"]),
            ("Critical", sm["critical"],       C["critical"],  C["critical"]),
            ("High",     sm["high"],           C["high"],      C["high"]),
            ("Medium",   sm["medium"],         C["medium"],    C["medium"]),
            ("MITRE",    sm["mitre_techniques"], C["indigo"],  C["indigo"]),
            ("IOCs",     sm["total_iocs"],      C["emerald"],  C["emerald"]),
        ]
        for i, (lbl, val, col, accent) in enumerate(stats):
            self._stat_card(sf, lbl, val, col, accent).grid(
                row=0, column=i, sticky="nsew", padx=3)

        # ── Charts Row ──
        cf = ctk.CTkFrame(scroll, fg_color="transparent")
        cf.pack(fill="x", padx=14, pady=(0, 8))
        cf.grid_columnconfigure((0,1), weight=1)

        # Donut
        d_outer, d_card = self._card(cf, accent_color=C["indigo"])
        d_outer.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        ctk.CTkLabel(d_card, text=f"{SYM['diamond']}  Severity Distribution",
                     font=FB, text_color=C["t1"]).pack(padx=16, pady=(16, 4), anchor="w")
        dc = tk.Canvas(d_card, width=360, height=230, bg=C["bg1"],
                        highlightthickness=0, bd=0)
        dc.pack(padx=16, pady=(0, 16))
        draw_donut(dc, 360, 230,
                   {"Critical": sm["critical"], "High": sm["high"],
                    "Medium": sm["medium"], "Low": sm["low"]},
                   {"Critical": C["critical"], "High": C["high"],
                    "Medium": C["medium"], "Low": C["low"]})

        # Bars
        b_outer, b_card = self._card(cf, accent_color=C["teal"])
        b_outer.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        ctk.CTkLabel(b_card, text=f"{SYM['diamond']}  Top Source IPs",
                     font=FB, text_color=C["t1"]).pack(padx=16, pady=(16, 4), anchor="w")
        bc = tk.Canvas(b_card, width=460, height=230, bg=C["bg1"],
                        highlightthickness=0, bd=0)
        bc.pack(padx=16, pady=(0, 16), fill="x")
        draw_bars(bc, 460, 230, r.get("top_ips", []), color=C["teal"])

        # ── Top Findings ──
        f_outer, f_card = self._card(scroll, accent_color=C["cyan"])
        f_outer.pack(fill="x", padx=14, pady=(0, 12))
        ctk.CTkLabel(f_card, text=f"{SYM['diamond']}  Top Findings",
                     font=FB, text_color=C["t1"]).pack(padx=16, pady=(16, 6), anchor="w")

        tb = self._textbox(f_card, height=220)
        tb.pack(fill="x", padx=12, pady=(0, 16))

        out = []
        for fi in r.get("findings", [])[:12]:
            out.append(self._fmt_finding(fi))
            out.append(f"  {hline(SYM['dash'], 70)}")
        tb.insert("1.0", "\n".join(out) if out else "  No findings detected.")
        tb.configure(state="disabled")

        return f

    # ════════════════════════════════════════════════════════════
    # PAGE: Findings
    # ════════════════════════════════════════════════════════════
    def _pg_findings(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg0"])
        if not self.results:
            ctk.CTkLabel(f, text="Run analysis first", font=(F, 16),
                         text_color=C["t3"]).place(relx=.5, rely=.5, anchor="center")
            return f

        findings = self.results.get("findings", [])
        hdr = self._header(f, f"{SYM['diamond']}  Findings", f"{len(findings)} detected")

        # Filter
        self._f_var = ctk.StringVar(value="All")
        filt = ctk.CTkSegmentedButton(
            hdr, values=["All", "Critical", "High", "Medium", "Low"],
            font=(F, 11), selected_color=C["teal"],
            selected_hover_color=C["teal"],
            variable=self._f_var, command=lambda v: self._render_findings(v))
        filt.pack(side="right")

        self._f_tb = self._textbox(f)
        self._f_tb.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self._render_findings("All")
        return f

    def _render_findings(self, sev_filter):
        findings = self.results.get("findings", [])
        if sev_filter != "All":
            findings = [fi for fi in findings if fi.get("severity", "").lower() == sev_filter.lower()]

        tb = self._f_tb
        tb.configure(state="normal")
        tb.delete("1.0", "end")

        if not findings:
            tb.insert("1.0", f"\n  {SYM['check']}  No findings match '{sev_filter}' filter.\n")
            tb.configure(state="disabled")
            return

        header = f"\n{section_header(f'{len(findings)} FINDINGS - {sev_filter.upper()}')}\n\n"
        out = [header]

        for i, fi in enumerate(findings, 1):
            out.append(f"  {SYM['tee']} #{i}")
            out.append(self._fmt_finding(fi))
            out.append(f"  {SYM['vline']}")

        out.append(f"\n{section_footer()}\n")
        tb.insert("1.0", "\n".join(out))
        tb.configure(state="disabled")

    # ════════════════════════════════════════════════════════════
    # PAGE: Timeline
    # ════════════════════════════════════════════════════════════
    def _pg_timeline(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg0"])
        if not self.results or not self.results.get("timeline"):
            ctk.CTkLabel(f, text="No timeline data", font=(F, 16),
                         text_color=C["t3"]).place(relx=.5, rely=.5, anchor="center")
            return f

        timeline = self.results["timeline"]
        self._header(f, f"{SYM['diamond']}  Attack Timeline", f"{len(timeline)} events")

        tb = self._textbox(f)
        tb.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        out = [f"\n{section_header('ATTACK TIMELINE')}\n"]
        for i, ev in enumerate(timeline[:300], 1):
            ts = ev.get("timestamp", "N/A")
            sev = ev.get("severity", "low").upper()
            title = ev.get("title", "")
            sym = SYM.get(sev.lower(), SYM["dot"])
            out.append(f"  {SYM['tee']} {ts:24s}  {sym} [{sev:8s}]  {title}")

        out.append(f"\n{section_footer()}\n")
        if len(timeline) > 300:
            out.append(f"\n  {SYM['bullet']} {len(timeline) - 300} more events not shown")

        tb.insert("1.0", "\n".join(out))
        tb.configure(state="disabled")
        return f

    # ════════════════════════════════════════════════════════════
    # PAGE: MITRE ATT&CK
    # ════════════════════════════════════════════════════════════
    def _pg_mitre(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg0"])
        if not self.results or not self.results.get("mitre_hits"):
            ctk.CTkLabel(f, text="No MITRE data", font=(F, 16),
                         text_color=C["t3"]).place(relx=.5, rely=.5, anchor="center")
            return f

        hits = self.results["mitre_hits"]
        total = sum(hits.values())
        self._header(f, f"{SYM['diamond']}  MITRE ATT&CK",
                     f"{len(hits)} techniques  {SYM['dot']}  {total} hits")

        scroll = ctk.CTkScrollableFrame(f, fg_color="transparent",
                                         scrollbar_button_color=C["border"],
                                         scrollbar_button_hover_color=C["teal"])
        scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        scroll.grid_columnconfigure(0, weight=1)

        mx = max(hits.values())
        for tech, cnt in sorted(hits.items(), key=lambda x: x[1], reverse=True):
            row = ctk.CTkFrame(scroll, corner_radius=8, fg_color=C["bg1"],
                                border_width=1, border_color=C["border"], height=44)
            row.pack(fill="x", padx=4, pady=2)
            row.pack_propagate(False)

            inner = ctk.CTkFrame(row, fg_color="transparent")
            inner.pack(fill="both", expand=True, padx=16)
            inner.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(inner, text=tech, font=(FM, 13, "bold"),
                         text_color=C["indigo"], width=110).grid(row=0, column=0, sticky="w")

            col = C["emerald"] if cnt >= 5 else C["gold"] if cnt >= 2 else C["critical"]
            pb = ctk.CTkProgressBar(inner, height=8, corner_radius=4,
                                     progress_color=col, fg_color=C["bg3"])
            pb.grid(row=0, column=1, sticky="ew", padx=14)
            pb.set(cnt / mx)

            ctk.CTkLabel(inner, text=f"{cnt} hits", font=(FM, 11, "bold"),
                         text_color=col, width=70).grid(row=0, column=2, sticky="e")

        return f

    # ════════════════════════════════════════════════════════════
    # PAGE: IOCs
    # ════════════════════════════════════════════════════════════
    def _pg_iocs(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg0"])
        if not self.results:
            ctk.CTkLabel(f, text="No IOC data", font=(F, 16),
                         text_color=C["t3"]).place(relx=.5, rely=.5, anchor="center")
            return f

        iocs = self.results.get("iocs", {})
        self._header(f, f"{SYM['diamond']}  Indicators of Compromise",
                     f"{iocs.get('total_iocs', 0)} extracted")

        tb = self._textbox(f)
        tb.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        out = []

        # Type summary
        by_type = iocs.get("by_type", {})
        if by_type:
            out.append(f"\n{section_header('IOC TYPE SUMMARY')}\n")
            for t, c in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
                bar = "\u2588" * min(c, 30)
                out.append(f"  {t.upper():20s}  {c:>4d}  {bar}")
            out.append(f"\n{section_footer()}")

        # IPs
        ips = iocs.get("top_ips", [])
        if ips:
            out.append(self._fmt_section("SUSPICIOUS IP ADDRESSES",
                       [ip for ip in ips[:20]]))

        # Domains
        doms = iocs.get("top_domains", [])
        if doms:
            out.append(self._fmt_section("SUSPICIOUS DOMAINS",
                       [d for d in doms[:20]]))

        # Hashes
        hashes = iocs.get("hashes", {})
        all_h = hashes.get("md5", [])[:8] + hashes.get("sha256", [])[:5]
        if all_h:
            out.append(self._fmt_section("FILE HASHES", all_h))

        # CVEs
        cves = iocs.get("cves", [])
        if cves:
            out.append(self._fmt_section("CVEs REFERENCED", cves))

        # URLs
        urls = iocs.get("urls", [])
        if urls:
            out.append(self._fmt_section("SUSPICIOUS URLs", urls[:10]))

        tb.insert("1.0", "\n".join(out) if out else f"\n  {SYM['check']}  No IOCs extracted.")
        tb.configure(state="disabled")
        return f

    # ════════════════════════════════════════════════════════════
    # PAGE: AI Copilot
    # ════════════════════════════════════════════════════════════
    def _pg_copilot(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg0"])
        self._header(f, f"{SYM['star']}  AI Analyst Copilot")

        self._chat = self._textbox(f)
        self._chat.pack(fill="both", expand=True, padx=14, pady=(0, 6))

        welcome = (
            f"\n{section_header('THREATSCOPE AI COPILOT')}\n\n"
            f"  {SYM['diamond']}  Ask questions about your analysis results.\n"
            f"  {SYM['diamond']}  All responses are generated locally — no API key needed.\n\n"
            f"  {SYM['bullet']}  \"What are the critical findings?\"\n"
            f"  {SYM['bullet']}  \"Show me the IOCs\"\n"
            f"  {SYM['bullet']}  \"What MITRE techniques were detected?\"\n"
            f"  {SYM['bullet']}  \"What are your recommendations?\"\n"
            f"  {SYM['bullet']}  \"Show me the attack timeline\"\n"
            f"  {SYM['bullet']}  \"What correlations were found?\"\n\n"
            f"{section_footer()}\n"
        )
        self._chat.insert("1.0", welcome)
        self._chat.configure(state="disabled")

        # Quick buttons
        qf = ctk.CTkFrame(f, fg_color="transparent")
        qf.pack(fill="x", padx=14, pady=(0, 6))
        for txt, col in [("Summary", C["cyan"]), ("Critical", C["critical"]),
                         ("IOCs", C["teal"]), ("MITRE", C["indigo"]),
                         ("Recommendations", C["gold"]), ("Timeline", C["emerald"])]:
            ctk.CTkButton(qf, text=txt, height=30, font=(F, 10, "bold"),
                           fg_color=C["bg1"], hover_color=C["bg2"],
                           text_color=col, corner_radius=6, width=95,
                           border_width=1, border_color=C["border"],
                           command=lambda t=txt: self._ask(f"Show {t.lower()}")
                           ).pack(side="left", padx=2)

        # Input
        inf = ctk.CTkFrame(f, fg_color="transparent")
        inf.pack(fill="x", padx=14, pady=(0, 14))
        inf.grid_columnconfigure(0, weight=1)

        self._cop_in = ctk.CTkEntry(
            inf, height=44, font=(F, 13),
            placeholder_text=f"{SYM['arrow']}  Ask about the analysis...",
            fg_color=C["bg3"], border_color=C["border_h"],
            text_color=C["t1"], corner_radius=8)
        self._cop_in.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self._cop_in.bind("<Return>", lambda e: self._ask())

        ctk.CTkButton(inf, text="Send", width=85, height=44, font=(F, 13, "bold"),
                       fg_color=C["cyan"], hover_color=C["accent_dim"],
                       text_color="#000", corner_radius=8,
                       command=self._ask).grid(row=0, column=1)
        return f

    def _ask(self, msg=None):
        if msg is None:
            msg = self._cop_in.get().strip()
            self._cop_in.delete(0, "end")
        if not msg:
            return

        self._chat.configure(state="normal")
        self._chat.insert("end", f"\n  {SYM['arrow']}  YOU:  {msg}\n")

        if not self.results:
            self._chat.insert("end",
                f"\n  {SYM['cross']}  No analysis loaded. Analyze a file first.\n")
            self._chat.configure(state="disabled")
            self._chat.see("end")
            return

        def work():
            resp = self.copilot.ask(msg)
            self.after(0, lambda: self._cop_resp(resp))
        threading.Thread(target=work, daemon=True).start()

    def _cop_resp(self, resp):
        self._chat.configure(state="normal")
        self._chat.insert("end", f"\n  {SYM['diamond']}  COPILOT:\n")
        for line in resp.split("\n"):
            self._chat.insert("end", f"  {line}\n")
        self._chat.insert("end", f"\n  {hline(SYM['dash'], 60)}\n")
        self._chat.configure(state="disabled")
        self._chat.see("end")

    # ════════════════════════════════════════════════════════════
    # PAGE: Narrative
    # ════════════════════════════════════════════════════════════
    def _pg_narrative(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg0"])
        hdr = self._header(f, f"{SYM['star']}  Attack Narrative")

        self._gen_btn = ctk.CTkButton(
            hdr, text=f"{SYM['diamond']}  Generate", height=38, font=(F, 13, "bold"),
            fg_color=C["cyan"], hover_color=C["accent_dim"],
            text_color="#000", corner_radius=8, command=self._gen_narr)
        self._gen_btn.pack(side="right")

        self._narr = self._textbox(f)
        self._narr.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        info = (
            f"\n{section_header('ATTACK NARRATIVE ENGINE')}\n\n"
            f"  {SYM['diamond']}  Click 'Generate' to create a professional incident report.\n"
            f"  {SYM['diamond']}  No API key required — fully local heuristic engine.\n\n"
            f"  The narrative includes:\n\n"
            f"  {SYM['bullet']}  Executive Summary\n"
            f"  {SYM['bullet']}  Initial Access Vector Analysis\n"
            f"  {SYM['bullet']}  Attack Progression Timeline\n"
            f"  {SYM['bullet']}  Impact Assessment\n"
            f"  {SYM['bullet']}  IOCs & Artifacts\n"
            f"  {SYM['bullet']}  MITRE ATT&CK Technique Mapping\n"
            f"  {SYM['bullet']}  Actionable Recommendations\n\n"
            f"{section_footer()}\n"
        )
        self._narr.insert("1.0", info)
        self._narr.configure(state="disabled")
        return f

    def _gen_narr(self):
        if not self.results:
            messagebox.showinfo("Info", "Analyze a file first.")
            return
        self._gen_btn.configure(state="disabled", text="Generating...")

        def work():
            narr = self.narrative_engine.generate_narrative(self.results)
            self.after(0, lambda: self._show_narr(narr))
        threading.Thread(target=work, daemon=True).start()

    def _show_narr(self, narr):
        self._narr.configure(state="normal")
        self._narr.delete("1.0", "end")
        self._narr.insert("1.0", f"\n{narr}\n")
        self._narr.configure(state="disabled")
        self._gen_btn.configure(state="normal", text=f"{SYM['diamond']}  Generate")

    # ════════════════════════════════════════════════════════════
    # PAGE: Export
    # ════════════════════════════════════════════════════════════
    def _pg_export(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg0"])
        self._header(f, f"{SYM['diamond']}  Export Report")

        scroll = ctk.CTkScrollableFrame(f, fg_color="transparent",
                                         scrollbar_button_color=C["border"])
        scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        formats = [
            ("JSON",     "Full analysis results in JSON format",         "json", True,    C["cyan"]),
            ("CSV",      "Findings exported as CSV spreadsheet",         "csv",  True,    C["teal"]),
            ("STIX 2.1", "STIX 2.1 threat intelligence bundle",         "stix", True,    C["indigo"]),
            ("PDF",      "Professional PDF incident report",             "pdf",  PDF_OK,  C["gold"]),
            ("DOCX",     "Microsoft Word document report",               "docx", DOCX_OK, C["emerald"]),
        ]

        for name, desc, fmt, avail, col in formats:
            outer, card = self._card(scroll, accent_color=col if avail else C["t3"])
            outer.pack(fill="x", padx=4, pady=4)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=20, pady=16)
            inner.grid_columnconfigure(1, weight=1)

            tf = ctk.CTkFrame(inner, fg_color="transparent")
            tf.grid(row=0, column=0, sticky="w")
            ctk.CTkLabel(tf, text=f"{SYM['diamond']}  {name}", font=(F, 15, "bold"),
                         text_color=C["t1"] if avail else C["t3"]).pack(anchor="w")
            status = desc if avail else f"{desc}  (install optional dep)"
            ctk.CTkLabel(tf, text=status, font=(F, 11),
                         text_color=C["t2"] if avail else C["t3"]).pack(anchor="w")

            ctk.CTkButton(
                inner, text=f"{SYM['arrow']}  Export", width=110, height=38,
                font=(F, 12, "bold"), corner_radius=8,
                fg_color=col if avail else C["bg3"],
                hover_color=C["bg2"] if not avail else None,
                text_color="#000" if avail else C["t3"],
                state="normal" if avail else "disabled",
                command=lambda fmt_=fmt: self._export(fmt_)
            ).grid(row=0, column=2, sticky="e")

        return f

    def _export(self, fmt):
        if not self.results:
            messagebox.showinfo("Info", "Analyze a file first.")
            return
        ext = {"json": ".json", "csv": ".csv", "stix": ".json", "pdf": ".pdf", "docx": ".docx"}
        fp = filedialog.asksaveasfilename(
            defaultextension=ext.get(fmt, ".json"),
            initialfile=f"threatscope_report{ext.get(fmt, '.json')}")
        if not fp:
            return
        try:
            fns = {"json": export_json, "csv": export_csv, "stix": export_stix}
            if fmt == "pdf" and PDF_OK:
                fns["pdf"] = export_pdf
            if fmt == "docx" and DOCX_OK:
                fns["docx"] = export_docx
            fns[fmt](self.results, fp)
            messagebox.showinfo("Export Complete",
                                f"{SYM['check']} Report saved to:\n{fp}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))


# ════════════════════════════════════════════════════════════════
# Entry Point
# ════════════════════════════════════════════════════════════════
def main():
    app = ThreatScopeGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
