import io
import csv
import json
import zipfile
import difflib
import streamlit as st
from agent.graph import build_graph
from agent.models import SeverityLevel
from agent.report import generate_pdf
from agent.sarif_exporter import export_sarif
from agent.dependency_scanner import scan_requirements
from agent.history import save_scan, load_all, clear_history

st.set_page_config(
    page_title="OWASP Security Audit Agent",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

*, *::before, *::after { box-sizing: border-box; }
html, body, .main, [data-testid="stAppViewContainer"] {
    background: #09090B !important;
    font-family: 'Inter', sans-serif !important;
    color: #FAFAFA !important;
}
.block-container { padding: 1.4rem 1.8rem 2rem !important; max-width: 1500px !important; }

/* SIDEBAR */
section[data-testid="stSidebar"] { background: #111113 !important; border-right: 1px solid #1F1F23 !important; }
section[data-testid="stSidebar"] > div { padding: 1.2rem 0.9rem !important; }
.brand-box { display:flex;align-items:center;gap:0.7rem;padding:0.75rem 0.85rem;background:linear-gradient(135deg,#1A1A2E,#16213E);border:1px solid #2D2D3A;border-radius:12px;margin-bottom:1.4rem; }
.brand-logo { width:36px;height:36px;background:linear-gradient(135deg,#6366F1,#8B5CF6);border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;box-shadow:0 0 14px #6366F140; }
.brand-title { font-size:0.8rem;font-weight:700;color:#F4F4F5;letter-spacing:-0.2px; }
.brand-sub { font-size:0.62rem;color:#71717A;font-family:'JetBrains Mono',monospace; }
.sec-head { font-size:0.59rem;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:rgba(255,255,255,0.3);margin:1.3rem 0 0.55rem 0.1rem; }
.model-box { background:#18181B;border:1px solid #27272A;border-radius:10px;padding:0.75rem 0.85rem;margin-bottom:0.5rem; }
.model-row { display:flex;justify-content:space-between;align-items:center;padding:0.16rem 0; }
.mk { font-size:0.69rem;color:#71717A; }
.mv { font-size:0.69rem;color:#D4D4D8;font-family:'JetBrains Mono',monospace;font-weight:500; }
.checker-row { display:flex;align-items:center;gap:0.5rem;padding:0.26rem 0.45rem;border-radius:7px; }
.checker-row:hover { background:#1C1C1F; }
.c-glow { width:7px;height:7px;border-radius:50%;flex-shrink:0; }
.c-code { font-family:'JetBrains Mono',monospace;font-size:0.63rem;font-weight:600;color:#6366F1;width:28px;flex-shrink:0; }
.c-name { font-size:0.7rem;color:#A1A1AA; }
.flow-box { background:#18181B;border:1px solid #27272A;border-radius:10px;padding:0.8rem 0.95rem;font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#71717A;line-height:2; }
.fn { color:#818CF8;font-weight:600; }

/* HERO */
.hero { position:relative;overflow:hidden;background:linear-gradient(135deg,#13131A,#1A1A2E 50%,#13131A);border:1px solid #2D2D3A;border-radius:16px;padding:1.6rem 1.8rem;margin-bottom:1.2rem; }
.hero::before { content:'';position:absolute;top:-60px;right:-60px;width:220px;height:220px;background:radial-gradient(circle,#6366F130,transparent 70%);pointer-events:none; }
.hero-inner { position:relative;z-index:1;display:flex;align-items:center;gap:1.3rem; }
.hero-icon { width:52px;height:52px;flex-shrink:0;background:linear-gradient(135deg,#4F46E5,#7C3AED);border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;box-shadow:0 0 24px #6366F145; }
.hero-title { font-size:1.35rem;font-weight:800;color:#FAFAFA;letter-spacing:-0.5px;margin-bottom:0.2rem; }
.hero-sub { font-size:0.78rem;color:#A1A1AA;margin-bottom:0.7rem;line-height:1.5; }
.chip-row { display:flex;gap:0.38rem;flex-wrap:wrap; }
.chip { padding:0.18rem 0.62rem;border-radius:20px;font-size:0.64rem;font-weight:600;border:1px solid; }
.ch-v { background:#1E1B4B;color:#818CF8;border-color:#3730A3; }
.ch-b { background:#0C1A40;color:#60A5FA;border-color:#1D4ED8; }
.ch-g { background:#052E16;color:#4ADE80;border-color:#166534; }
.ch-z { background:#18181B;color:#71717A;border-color:#27272A; }
.ch-r { background:#1C0A0A;color:#F87171;border-color:#7F1D1D; }

/* PANEL */
.panel-lbl { font-size:0.61rem;font-weight:700;text-transform:uppercase;letter-spacing:1.8px;color:#71717A;margin-bottom:0.5rem; }

/* TEXTAREA */
.stTextArea textarea { background:#111113 !important;color:#E4E4E7 !important;border:1px solid #27272A !important;border-radius:10px !important;font-family:'JetBrains Mono',monospace !important;font-size:0.8rem !important;line-height:1.7 !important; }
.stTextArea textarea:focus { border-color:#6366F1 !important;box-shadow:0 0 0 3px #6366F115 !important; }
.stTextArea textarea::placeholder { color:#3F3F46 !important; }

/* FILE UPLOADER */
[data-testid="stFileUploaderDropzone"] { background:#111113 !important;border:1.5px dashed #27272A !important;border-radius:10px !important; }

/* BUTTON */
.stButton > button { background:linear-gradient(135deg,#4F46E5,#7C3AED) !important;color:#fff !important;border:none !important;border-radius:10px !important;font-weight:700 !important;font-size:0.88rem !important;padding:0.6rem !important;box-shadow:0 4px 16px #6366F130 !important;transition:all 0.2s !important; }
.stButton > button:hover { background:linear-gradient(135deg,#4338CA,#6D28D9) !important;transform:translateY(-1px) !important;box-shadow:0 6px 20px #6366F145 !important; }

/* METRICS */
.m-grid { display:grid;grid-template-columns:repeat(4,1fr);gap:0.6rem;margin-bottom:0.9rem; }
.m-card { background:#18181B;border:1px solid #27272A;border-radius:11px;padding:0.8rem 0.9rem;position:relative;overflow:hidden; }
.m-card::before { content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:11px 11px 0 0; }
.mc-c::before { background:linear-gradient(90deg,#EF4444,#F87171); }
.mc-h::before { background:linear-gradient(90deg,#F97316,#FB923C); }
.mc-m::before { background:linear-gradient(90deg,#EAB308,#FDE047); }
.mc-l::before { background:linear-gradient(90deg,#22C55E,#4ADE80); }
.m-num { font-size:1.9rem;font-weight:800;line-height:1;margin-bottom:0.18rem; }
.m-lbl { font-size:0.61rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#71717A; }
.mc-c .m-num{color:#F87171;} .mc-h .m-num{color:#FB923C;} .mc-m .m-num{color:#FDE047;} .mc-l .m-num{color:#4ADE80;}

/* ESCALATION BANNER */
.escalation-banner { background:linear-gradient(135deg,#1C0A0A,#2D0A0A);border:1px solid #7F1D1D;border-radius:10px;padding:0.85rem 1.1rem;margin-bottom:0.8rem;display:flex;align-items:flex-start;gap:0.7rem; }
.eb-icon { font-size:1.3rem;flex-shrink:0; }
.eb-title { font-size:0.82rem;font-weight:700;color:#F87171;margin-bottom:0.2rem; }
.eb-msg { font-size:0.76rem;color:#FCA5A5;line-height:1.5; }

/* VERIFICATION BANNER */
.verify-ok { background:#0D1F14;border:1px solid #166534;border-radius:9px;padding:0.65rem 1rem;margin-bottom:0.7rem;font-size:0.8rem;color:#4ADE80;display:flex;align-items:center;gap:0.5rem; }
.verify-warn { background:#1A1500;border:1px solid #713F12;border-radius:9px;padding:0.65rem 1rem;margin-bottom:0.7rem;font-size:0.8rem;color:#F59E0B;display:flex;align-items:center;gap:0.5rem; }

/* TABS */
.stTabs [data-baseweb="tab-list"] { background:#18181B !important;border-radius:10px !important;padding:3px !important;gap:2px !important;border:1px solid #27272A !important; }
.stTabs [data-baseweb="tab"] { background:transparent !important;color:#52525B !important;border-radius:7px !important;font-size:0.78rem !important;font-weight:500 !important;padding:0.36rem 0.85rem !important; }
.stTabs [aria-selected="true"] { background:#1E1B4B !important;color:#818CF8 !important;font-weight:700 !important;box-shadow:0 0 0 1px #3730A3 !important; }
.stTabs [data-baseweb="tab-panel"] { padding-top:0.85rem !important; }

/* AI CARD */
.ai-card { background:linear-gradient(135deg,#13131A,#1A1A2E);border:1px solid #2D2D3A;border-radius:12px;padding:1.1rem 1.3rem; }
.ai-head { display:flex;align-items:center;gap:0.6rem;margin-bottom:0.85rem;padding-bottom:0.75rem;border-bottom:1px solid #27272A; }
.ai-ava { width:29px;height:29px;background:linear-gradient(135deg,#4F46E5,#7C3AED);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:0.72rem;color:#fff;font-weight:800;box-shadow:0 0 10px #6366F130; }
.ai-name { font-size:0.78rem;font-weight:600;color:#E4E4E7; }
.ai-role { font-size:0.63rem;color:#71717A; }
.ai-body { font-size:0.83rem;color:#D4D4D8;line-height:1.85; }

/* FINDING CARDS */
.fcard { background:#18181B;border:1px solid #27272A;border-radius:12px;padding:0.9rem 1.1rem;margin-bottom:0.5rem;position:relative;overflow:hidden;transition:border-color 0.2s; }
.fcard:hover { border-color:#3F3F46; }
.fcard::before { content:'';position:absolute;left:0;top:0;bottom:0;width:3px; }
.fc-c::before{background:linear-gradient(180deg,#EF4444,#F87171);}
.fc-h::before{background:linear-gradient(180deg,#F97316,#FB923C);}
.fc-m::before{background:linear-gradient(180deg,#EAB308,#FDE047);}
.fc-l::before{background:linear-gradient(180deg,#22C55E,#4ADE80);}
.fcard-top { display:flex;align-items:flex-start;justify-content:space-between;gap:0.5rem;margin-bottom:0.42rem; }
.fcard-title { font-size:0.86rem;font-weight:600;color:#F4F4F5;flex:1;line-height:1.4; }
.badge-row { display:flex;gap:0.28rem;flex-wrap:wrap;justify-content:flex-end;flex-shrink:0; }
.badge { padding:0.12rem 0.45rem;border-radius:5px;font-size:0.6rem;font-weight:700;letter-spacing:0.3px;font-family:'JetBrains Mono',monospace;border:1px solid; }
.bc{background:#1C0A0A;color:#F87171;border-color:#7F1D1D;} .bh{background:#1C0E06;color:#FB923C;border-color:#7C2D12;} .bm{background:#1C1606;color:#FDE047;border-color:#713F12;} .bl{background:#071811;color:#4ADE80;border-color:#14532D;} .bow{background:#1E1B4B;color:#818CF8;border-color:#3730A3;} .bln{background:#18181B;color:#71717A;border-color:#27272A;}
.fcard-desc { font-size:0.78rem;color:#A1A1AA;line-height:1.65;margin-bottom:0.48rem; }
.fcard-code { background:#111113;border:1px solid #27272A;border-radius:6px;padding:0.32rem 0.62rem;font-family:'JetBrains Mono',monospace;font-size:0.71rem;color:#F97316;margin-bottom:0.45rem;word-break:break-all; }
.fcard-rec { display:flex;align-items:flex-start;gap:0.4rem;background:#0D1F14;border:1px solid #166534;border-radius:7px;padding:0.42rem 0.68rem;font-size:0.76rem;color:#4ADE80;line-height:1.55; }

/* FIX / DIFF */
.fix-ok { display:flex;align-items:center;gap:0.55rem;background:#0D1F14;border:1px solid #166534;border-radius:9px;padding:0.65rem 0.95rem;margin-bottom:0.7rem;font-size:0.8rem;color:#4ADE80;font-weight:500; }
.manual-box { background:#1A1500;border:1px solid #713F12;border-radius:10px;padding:0.85rem 0.95rem;margin-bottom:0.8rem; }
.manual-title { font-size:0.75rem;font-weight:700;color:#F59E0B;margin-bottom:0.5rem; }
.manual-row { display:flex;align-items:flex-start;gap:0.55rem;padding:0.32rem 0;border-bottom:1px solid #292209;font-size:0.74rem; }
.manual-row:last-child{border-bottom:none;}
.mr-name{color:#D97706;font-weight:600;min-width:160px;} .mr-fix{color:#92400E;font-family:'JetBrains Mono',monospace;font-size:0.68rem;}

/* HISTORY */
.hist-card { background:#18181B;border:1px solid #27272A;border-radius:10px;padding:0.75rem 0.9rem;margin-bottom:0.45rem;display:flex;align-items:center;gap:0.9rem; }
.hist-ts { font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#52525B;flex-shrink:0;min-width:130px; }
.hist-fname { font-size:0.78rem;font-weight:600;color:#E4E4E7;flex:1; }
.hist-badges { display:flex;gap:0.3rem; }
.hb { padding:0.1rem 0.4rem;border-radius:4px;font-size:0.61rem;font-weight:700;font-family:'JetBrains Mono',monospace; }
.hb-c{background:#1C0A0A;color:#F87171;} .hb-h{background:#1C0E06;color:#FB923C;} .hb-m{background:#1C1606;color:#FDE047;} .hb-l{background:#071811;color:#4ADE80;}

/* DEP */
.dep-card { background:#18181B;border:1px solid #27272A;border-radius:10px;padding:0.8rem 0.95rem;margin-bottom:0.5rem;position:relative;overflow:hidden; }
.dep-card::before { content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:#F97316; }
.dep-pkg { font-size:0.88rem;font-weight:600;color:#F4F4F5;margin-bottom:0.25rem; }
.dep-meta { font-size:0.72rem;color:#71717A;font-family:'JetBrains Mono',monospace;margin-bottom:0.4rem;display:flex;gap:0.8rem; }
.dep-desc { font-size:0.78rem;color:#A1A1AA;margin-bottom:0.4rem;line-height:1.55; }
.dep-fix { background:#0D1F14;border:1px solid #166534;border-radius:6px;padding:0.35rem 0.65rem;font-size:0.75rem;color:#4ADE80; }

/* CICD */
.cicd-info { background:#18181B;border:1px solid #27272A;border-radius:10px;padding:0.85rem 1rem;margin-bottom:0.8rem;font-size:0.8rem;color:#A1A1AA;line-height:1.7; }

/* HTIL */
.htil-box { background:linear-gradient(135deg,#1A1A2E,#13131A);border:1px solid #3730A3;border-radius:12px;padding:1.1rem 1.2rem;margin-bottom:0.8rem; }
.htil-title { font-size:0.9rem;font-weight:700;color:#818CF8;margin-bottom:0.4rem; }
.htil-desc { font-size:0.78rem;color:#A1A1AA;margin-bottom:0.8rem;line-height:1.6; }

/* EMPTY */
.empty { display:flex;flex-direction:column;align-items:center;justify-content:center;padding:3rem 1rem;text-align:center; }
.empty-glow { width:72px;height:72px;background:linear-gradient(135deg,#4F46E5,#7C3AED);border-radius:18px;display:flex;align-items:center;justify-content:center;font-size:2rem;margin-bottom:1rem;box-shadow:0 0 28px #6366F140; }
.empty-t { font-size:0.96rem;font-weight:700;color:#E4E4E7;margin-bottom:0.38rem; }
.empty-s { font-size:0.77rem;color:#71717A;line-height:1.75; }
.empty-s b { color:#818CF8; }

::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-track{background:#09090B;}
::-webkit-scrollbar-thumb{background:#27272A;border-radius:4px;}
[data-testid="stSpinner"] p{color:#52525B !important;font-size:0.8rem !important;}
.stAlert{border-radius:10px !important;}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown(
        '<div class="brand-box">'
        '<div class="brand-logo">&#128737;</div>'
        '<div><div class="brand-title">Security Audit Agent</div>'
        '<div class="brand-sub">v2.0 &middot; OWASP Top 10:2025</div></div>'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown('<div class="sec-head">Model Config</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="model-box">'
        '<div class="model-row"><span class="mk">Model</span><span class="mv">llama-3.1-8b</span></div>'
        '<div class="model-row"><span class="mk">Provider</span><span class="mv">Groq API</span></div>'
        '<div class="model-row"><span class="mk">Temperature</span><span class="mv">0.0</span></div>'
        '<div class="model-row"><span class="mk">Fixer</span><span class="mv">rule-based</span></div>'
        '<div class="model-row"><span class="mk">Max fix loops</span><span class="mv">2</span></div>'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown('<div class="sec-head">Active Checkers (10)</div>', unsafe_allow_html=True)
    CHECKERS = [
        ("#EF4444","A01","Broken Access Control"),
        ("#EF4444","A02","Security Misconfiguration"),
        ("#F97316","A03","Supply Chain Failures"),
        ("#F97316","A04","Cryptographic Failures"),
        ("#EF4444","A05","Injection"),
        ("#EAB308","A06","Insecure Design"),
        ("#F97316","A07","Authentication Failures"),
        ("#EF4444","A08","Data Integrity Failures"),
        ("#F97316","A09","Logging Failures"),
        ("#EAB308","A10","Exceptional Conditions"),
    ]
    for color, code, name in CHECKERS:
        st.markdown(
            f'<div class="checker-row">'
            f'<div class="c-glow" style="background:{color};box-shadow:0 0 5px {color}80"></div>'
            f'<span class="c-code">{code}</span><span class="c-name">{name}</span></div>',
            unsafe_allow_html=True
        )

    st.markdown('<div class="sec-head">Agent Workflow</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="flow-box">'
        '<span class="fn">&#9654; START</span><br>'
        '&nbsp;&nbsp;&#8595;<br>'
        '<span class="fn">&#9672; run_checkers</span><br>'
        '&nbsp;&nbsp;&#8595; [conditional edge]<br>'
        '<span class="fn">&#9672; escalate_alert?</span><br>'
        '&nbsp;&nbsp;&#8595;<br>'
        '<span class="fn">&#9672; llm_analysis</span><br>'
        '&nbsp;&nbsp;&#8595;<br>'
        '<span class="fn">&#9672; auto_fix</span><br>'
        '&nbsp;&nbsp;&#8595;<br>'
        '<span class="fn">&#9672; verify_fixes</span><br>'
        '&nbsp;&nbsp;&#8595; [loop edge max 2x]<br>'
        '<span class="fn">&#9632; END</span>'
        '</div>',
        unsafe_allow_html=True
    )

# ══════════════════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════════════════
st.markdown(
    '<div class="hero"><div class="hero-inner">'
    '<div class="hero-icon">&#128272;</div>'
    '<div>'
    '<div class="hero-title">OWASP Security Audit Agent</div>'
    '<div class="hero-sub">Agentic AI framework &mdash; OWASP Top 10:2025 &bull; LangGraph conditional edges &bull; Fix verification loop &bull; Human-in-the-loop</div>'
    '<div class="chip-row">'
    '<span class="chip ch-v">OWASP Top 10 &middot; 2025</span>'
    '<span class="chip ch-b">LangGraph</span>'
    '<span class="chip ch-g">Verify Loop</span>'
    '<span class="chip ch-r">Escalation</span>'
    '<span class="chip ch-z">Groq &middot; Llama 3.1</span>'
    '</div></div></div></div>',
    unsafe_allow_html=True
)

# ══════════════════════════════════════════════════════════════════════════
# MAIN TABS (top-level navigation)
# ══════════════════════════════════════════════════════════════════════════
main_tab1, main_tab2, main_tab3 = st.tabs([
    "⚡ Code Audit",
    "📦 Dependency Scanner",
    "🕓 Scan History"
])

# ══════════════════════════════════════════════════════════════════════════
# TAB 1 — CODE AUDIT
# ══════════════════════════════════════════════════════════════════════════
with main_tab1:
    col_in, col_out = st.columns([1, 1], gap="large")

    with col_in:
        st.markdown('<div class="panel-lbl">Source Code</div>', unsafe_allow_html=True)

        upload_type = st.radio(
            "Upload mode",
            ["Single .py file", "ZIP (multi-file)"],
            horizontal=True,
            label_visibility="collapsed"
        )

        multi_files = {}
        if upload_type == "ZIP (multi-file)":
            zip_upload = st.file_uploader("Upload ZIP", type=["zip"], label_visibility="collapsed")
            if zip_upload:
                with zipfile.ZipFile(zip_upload) as zf:
                    py_files = [n for n in zf.namelist() if n.endswith(".py") and not n.startswith("__")]
                    for name in py_files[:10]:  # max 10 file
                        multi_files[name] = zf.read(name).decode("utf-8", errors="replace")
                if multi_files:
                    st.success(f"✅ {len(multi_files)} file .py ditemukan dalam ZIP")
                    selected_file = st.selectbox("Pilih file untuk diaudit:", list(multi_files.keys()))
                    code_input = multi_files[selected_file]
                    filename   = selected_file.split("/")[-1]
                    st.code(code_input[:2000], language="python")
                else:
                    st.warning("Tidak ada file .py dalam ZIP.")
                    code_input, filename = "", "input.py"
            else:
                code_input, filename = "", "input.py"
        else:
            uploaded = st.file_uploader("Upload .py", type=["py"], label_visibility="collapsed")
            if uploaded:
                code_input = uploaded.read().decode("utf-8")
                filename   = uploaded.name
                st.code(code_input, language="python")
            else:
                filename   = "input.py"
                code_input = st.text_area(
                    "code", height=360,
                    placeholder="# Paste kode Python kamu di sini...\n# Agent akan mendeteksi kerentanan OWASP Top 10:2025",
                    label_visibility="collapsed"
                )

        # Human-in-the-loop toggle
        st.markdown('<div class="panel-lbl" style="margin-top:0.8rem">Human-in-the-Loop</div>', unsafe_allow_html=True)
        fix_approved = st.toggle(
            "Approve auto-fix sebelum diterapkan",
            value=True,
            help="Jika aktif, kamu harus approve dulu sebelum agent menerapkan perbaikan kode"
        )

        st.button("⚡  Jalankan Audit", type="primary", use_container_width=True, key="run_btn")

    with col_out:
        st.markdown('<div class="panel-lbl">Audit Results</div>', unsafe_allow_html=True)

        if st.session_state.get("run_btn"):
            if not code_input.strip():
                st.warning("Masukkan kode Python terlebih dahulu.")
            else:
                with st.spinner("Agent sedang menganalisis kode..."):
                    graph  = build_graph()
                    result = graph.invoke({
                        "code":                  code_input,
                        "filename":              filename,
                        "findings":              [],
                        "summary":               "",
                        "fixed_code":            "",
                        "fix_iterations":        0,
                        "verification_findings": [],
                        "verified":              False,
                        "escalated":             False,
                        "escalation_message":    "",
                        "fix_approved":          fix_approved,
                    })

                # Simpan ke session_state
                st.session_state["last_result"] = result
                st.session_state.pop("pdf_bytes", None)
                st.session_state.pop("pdf_filename", None)

                # Simpan ke history
                save_scan(filename, result["findings"], result["summary"])

        if "last_result" in st.session_state:
            r  = st.session_state["last_result"]
            findings   = r["findings"]
            summary    = r["summary"]
            fixed_code = r.get("fixed_code", "")
            fname      = r.get("filename", filename)
            escalated  = r.get("escalated", False)
            esc_msg    = r.get("escalation_message", "")
            vf         = r.get("verification_findings", [])
            verified   = r.get("verified", False)
            iterations = r.get("fix_iterations", 0)
            code_orig  = r.get("code", code_input)

            # Escalation banner
            if escalated:
                st.markdown(
                    f'<div class="escalation-banner">'
                    f'<div class="eb-icon">&#128680;</div>'
                    f'<div><div class="eb-title">ESKALASI KEAMANAN AKTIF</div>'
                    f'<div class="eb-msg">{esc_msg}</div></div></div>',
                    unsafe_allow_html=True
                )

            # Verification result banner
            if verified and fixed_code:
                remaining = len(vf)
                still_crit = sum(1 for f in vf if f.severity == SeverityLevel.CRITICAL)
                if remaining == 0:
                    st.markdown(
                        f'<div class="verify-ok">&#9989; Verifikasi: semua kerentanan berhasil diperbaiki setelah {iterations} iterasi fix</div>',
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        f'<div class="verify-warn">&#9888; Verifikasi: masih ada {remaining} kerentanan tersisa ({still_crit} critical) setelah {iterations} iterasi — membutuhkan perbaikan manual</div>',
                        unsafe_allow_html=True
                    )

            crit = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
            high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
            med  = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
            low  = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

            st.markdown(
                f'<div class="m-grid">'
                f'<div class="m-card mc-c"><div class="m-num">{crit}</div><div class="m-lbl">Critical</div></div>'
                f'<div class="m-card mc-h"><div class="m-num">{high}</div><div class="m-lbl">High</div></div>'
                f'<div class="m-card mc-m"><div class="m-num">{med}</div><div class="m-lbl">Medium</div></div>'
                f'<div class="m-card mc-l"><div class="m-num">{low}</div><div class="m-lbl">Low</div></div>'
                f'</div>',
                unsafe_allow_html=True
            )

            t1, t2, t3, t4, t5 = st.tabs([
                "✦ AI Summary",
                f"⚠ Findings  {len(findings)}",
                "⚙ Auto Fix & Diff",
                "↗ Export",
                "📄 PDF Report"
            ])

            # ── Tab 1: AI Summary ──
            with t1:
                st.markdown(
                    '<div class="ai-card">'
                    '<div class="ai-head">'
                    '<div class="ai-ava">AI</div>'
                    '<div><div class="ai-name">Security Audit Agent</div>'
                    '<div class="ai-role">Groq &middot; Llama 3.1 &middot; LangGraph</div></div></div>'
                    f'<div class="ai-body">{summary}</div></div>',
                    unsafe_allow_html=True
                )

                # Severity chart
                if findings:
                    st.markdown("<br>", unsafe_allow_html=True)
                    st.markdown('<div class="panel-lbl">Distribusi Severity</div>', unsafe_allow_html=True)
                    chart_data = {"Critical": crit, "High": high, "Medium": med, "Low": low}
                    st.bar_chart(chart_data, color="#6366F1", height=180)

                    st.markdown('<div class="panel-lbl">Distribusi OWASP Category</div>', unsafe_allow_html=True)
                    from collections import Counter
                    cat_counts = Counter(f.owasp_category.value.split(":")[0] for f in findings)
                    st.bar_chart(dict(cat_counts), color="#8B5CF6", height=200)

            # ── Tab 2: Findings ──
            with t2:
                if not findings:
                    st.success("✅ Tidak ditemukan kerentanan — kode aman!")
                else:
                    SMAP = {
                        SeverityLevel.CRITICAL: ("fc-c","bc","CRITICAL"),
                        SeverityLevel.HIGH:     ("fc-h","bh","HIGH"),
                        SeverityLevel.MEDIUM:   ("fc-m","bm","MEDIUM"),
                        SeverityLevel.LOW:      ("fc-l","bl","LOW"),
                    }
                    for f in findings:
                        fc, sb, slbl = SMAP.get(f.severity, ("fc-l","bl","LOW"))
                        code_snip = f'<div class="fcard-code">{f.vulnerable_code}</div>' if f.vulnerable_code else ""
                        owasp_short = f.owasp_category.value.split(":")[0]
                        st.markdown(
                            f'<div class="fcard {fc}">'
                            f'<div class="fcard-top">'
                            f'<div class="fcard-title">{f.title}</div>'
                            f'<div class="badge-row"><span class="badge {sb}">{slbl}</span>'
                            f'<span class="badge bow">{owasp_short}</span>'
                            f'<span class="badge bln">L{f.line_number}</span></div></div>'
                            f'<div class="fcard-desc">{f.description}</div>'
                            f'{code_snip}'
                            f'<div class="fcard-rec">&#128161; {f.recommendation}</div></div>',
                            unsafe_allow_html=True
                        )

            # ── Tab 3: Auto Fix & Diff ──
            with t3:
                if not fix_approved and "last_result" in st.session_state:
                    st.markdown(
                        '<div class="htil-box">'
                        '<div class="htil-title">&#128100; Human-in-the-Loop — Menunggu Approval</div>'
                        '<div class="htil-desc">Auto-fix belum diterapkan. Toggle "Approve auto-fix" di panel kiri untuk mengaktifkan, lalu jalankan audit ulang.</div>'
                        '</div>',
                        unsafe_allow_html=True
                    )
                elif fixed_code and fixed_code != code_orig:
                    st.markdown('<div class="fix-ok">&#9989; Rule-based auto-fix diterapkan</div>', unsafe_allow_html=True)

                    st.markdown(
                        '<div class="manual-box">'
                        '<div class="manual-title">&#9888; Perlu perbaikan manual</div>'
                        '<div class="manual-row"><span class="mr-name">SQL Injection</span><span class="mr-fix">cursor.execute(q, (param,))</span></div>'
                        '<div class="manual-row"><span class="mr-name">Password comparison</span><span class="mr-fix">bcrypt.checkpw(inp, hash)</span></div>'
                        '<div class="manual-row"><span class="mr-name">Password di log</span><span class="mr-fix">logging.info("user=%s", user)</span></div>'
                        '<div class="manual-row"><span class="mr-name">eval() dinamis</span><span class="mr-fix">ast.literal_eval()</span></div>'
                        '</div>',
                        unsafe_allow_html=True
                    )

                    diff_tab, code_tab = st.tabs(["📊 Diff View", "📝 Fixed Code"])

                    with diff_tab:
                        diff = list(difflib.unified_diff(
                            code_orig.splitlines(keepends=True),
                            fixed_code.splitlines(keepends=True),
                            fromfile="original.py",
                            tofile="fixed.py",
                            n=3
                        ))
                        if diff:
                            st.code("".join(diff), language="diff")
                        else:
                            st.info("Tidak ada perubahan yang terdeteksi.")

                    with code_tab:
                        st.code(fixed_code, language="python")
                        st.download_button(
                            "&#8681; Download Fixed Code", data=fixed_code,
                            file_name=f"fixed_{fname}", mime="text/x-python",
                            use_container_width=True
                        )
                else:
                    st.info("Tidak ada perbaikan otomatis yang diperlukan.")

            # ── Tab 4: Export ──
            with t4:
                ex1, ex2 = st.columns(2)

                with ex1:
                    st.markdown('<div class="panel-lbl">Data Export</div>', unsafe_allow_html=True)

                    # JSON Export
                    json_data = json.dumps([{
                        "title": f.title,
                        "severity": f.severity.value,
                        "owasp_category": f.owasp_category.value,
                        "line_number": f.line_number,
                        "description": f.description,
                        "recommendation": f.recommendation,
                        "vulnerable_code": f.vulnerable_code or ""
                    } for f in findings], indent=2, ensure_ascii=False)

                    st.download_button(
                        "&#8681; Export JSON", data=json_data,
                        file_name=f"findings_{fname}.json", mime="application/json",
                        use_container_width=True
                    )

                    # CSV Export
                    csv_buf = io.StringIO()
                    writer = csv.DictWriter(csv_buf, fieldnames=["title","severity","owasp_category","line_number","description","recommendation","vulnerable_code"])
                    writer.writeheader()
                    for f in findings:
                        writer.writerow({
                            "title": f.title, "severity": f.severity.value,
                            "owasp_category": f.owasp_category.value,
                            "line_number": f.line_number, "description": f.description,
                            "recommendation": f.recommendation,
                            "vulnerable_code": f.vulnerable_code or ""
                        })
                    st.download_button(
                        "&#8681; Export CSV", data=csv_buf.getvalue(),
                        file_name=f"findings_{fname}.csv", mime="text/csv",
                        use_container_width=True
                    )

                    # SARIF Export
                    sarif_data = export_sarif(fname, findings)
                    st.download_button(
                        "&#8681; Export SARIF (GitHub Security)", data=sarif_data,
                        file_name=f"findings_{fname}.sarif", mime="application/json",
                        use_container_width=True
                    )

                with ex2:
                    st.markdown('<div class="panel-lbl">CI/CD Config Generator</div>', unsafe_allow_html=True)
                    st.markdown(
                        '<div class="cicd-info">'
                        'Generate GitHub Actions workflow yang menjalankan audit ini otomatis setiap kali ada push ke repository.'
                        '</div>',
                        unsafe_allow_html=True
                    )

                    cicd_yaml = f"""# .github/workflows/security-audit.yml
# OWASP Security Audit Agent — Auto-generated
name: Security Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install langchain langgraph langchain-groq
          pip install pydantic fpdf2 python-dotenv

      - name: Run OWASP Security Audit
        env:
          GROQ_API_KEY: ${{{{ secrets.GROQ_API_KEY }}}}
        run: |
          python -c "
          from agent.graph import build_graph
          from agent.models import SeverityLevel
          import sys, glob

          graph = build_graph()
          failed = False

          for py_file in glob.glob('**/*.py', recursive=True):
              with open(py_file) as f:
                  code = f.read()
              result = graph.invoke({{
                  'code': code, 'filename': py_file,
                  'findings': [], 'summary': '', 'fixed_code': '',
                  'fix_iterations': 0, 'verification_findings': [],
                  'verified': False, 'escalated': False,
                  'escalation_message': '', 'fix_approved': False,
              }})
              crits = [f for f in result['findings'] if f.severity == SeverityLevel.CRITICAL]
              if crits:
                  print(f'CRITICAL in {{py_file}}: {{len(crits)}} findings')
                  failed = True
          sys.exit(1 if failed else 0)
          "

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: findings.sarif
"""
                    st.download_button(
                        "&#8681; Download github-actions.yml",
                        data=cicd_yaml,
                        file_name="security-audit.yml",
                        mime="text/yaml",
                        use_container_width=True
                    )
                    st.code(cicd_yaml[:800] + "\n...", language="yaml")

            # ── Tab 5: PDF ──
            with t5:
                st.markdown(
                    '<div style="background:linear-gradient(135deg,#13131A,#1A1A2E);border:1px solid #2D2D3A;border-radius:14px;padding:1.8rem;text-align:center;">'
                    '<div style="font-size:2.5rem;margin-bottom:0.7rem">&#128196;</div>'
                    '<div style="font-size:0.98rem;font-weight:700;color:#F4F4F5;margin-bottom:0.35rem">Export PDF Report</div>'
                    '<div style="font-size:0.78rem;color:#A1A1AA;margin-bottom:1.4rem;line-height:1.7">Cover page &bull; Executive Summary &bull; Detail Findings &bull; Fixed Code</div>'
                    '</div>',
                    unsafe_allow_html=True
                )
                st.markdown("<br>", unsafe_allow_html=True)

                if st.button("&#128196; Generate PDF Report", use_container_width=True):
                    with st.spinner("Generating PDF..."):
                        pdf_b = generate_pdf(fname, findings, summary, fixed_code)
                    st.session_state["pdf_bytes"]    = pdf_b
                    st.session_state["pdf_filename"] = f"audit_{fname.replace('.py','')}.pdf"

                if "pdf_bytes" in st.session_state:
                    st.download_button(
                        "&#8681; Download PDF",
                        data=st.session_state["pdf_bytes"],
                        file_name=st.session_state["pdf_filename"],
                        mime="application/pdf",
                        use_container_width=True
                    )
                    st.success("✅ PDF siap didownload!")
        else:
            st.markdown(
                '<div class="empty">'
                '<div class="empty-glow">&#128269;</div>'
                '<div class="empty-t">Belum ada hasil audit</div>'
                '<div class="empty-s">Paste kode Python di panel kiri<br>lalu klik <b>Jalankan Audit</b></div>'
                '</div>',
                unsafe_allow_html=True
            )

# ══════════════════════════════════════════════════════════════════════════
# TAB 2 — DEPENDENCY SCANNER
# ══════════════════════════════════════════════════════════════════════════
with main_tab2:
    st.markdown('<div class="panel-lbl">Upload requirements.txt</div>', unsafe_allow_html=True)
    req_file = st.file_uploader("Upload requirements.txt", type=["txt"], label_visibility="collapsed", key="req_upload")

    if req_file:
        req_content = req_file.read().decode("utf-8")
        col_req1, col_req2 = st.columns([1, 1], gap="large")

        with col_req1:
            st.markdown('<div class="panel-lbl">File Content</div>', unsafe_allow_html=True)
            st.code(req_content, language="text")

        with col_req2:
            st.markdown('<div class="panel-lbl">Vulnerability Scan Results</div>', unsafe_allow_html=True)
            dep_findings = scan_requirements(req_content)

            if not dep_findings:
                st.success("✅ Tidak ada dependency yang diketahui rentan ditemukan.")
            else:
                st.error(f"⚠ Ditemukan {len(dep_findings)} dependency rentan!")
                for df in dep_findings:
                    st.markdown(
                        f'<div class="dep-card">'
                        f'<div class="dep-pkg">{df.package} v{df.installed_version}</div>'
                        f'<div class="dep-meta">'
                        f'<span>CVE: {df.cve}</span>'
                        f'<span>Safe: &gt;= {df.safe_version}</span>'
                        f'<span>{df.severity}</span>'
                        f'</div>'
                        f'<div class="dep-desc">{df.description}</div>'
                        f'<div class="dep-fix">&#128161; {df.fix}</div>'
                        f'</div>',
                        unsafe_allow_html=True
                    )
    else:
        st.markdown(
            '<div class="empty">'
            '<div class="empty-glow">&#128230;</div>'
            '<div class="empty-t">Upload requirements.txt</div>'
            '<div class="empty-s">Agent akan mendeteksi library Python<br>yang memiliki <b>CVE diketahui</b></div>'
            '</div>',
            unsafe_allow_html=True
        )

# ══════════════════════════════════════════════════════════════════════════
# TAB 3 — SCAN HISTORY
# ══════════════════════════════════════════════════════════════════════════
with main_tab3:
    history = load_all()

    if not history:
        st.markdown(
            '<div class="empty">'
            '<div class="empty-glow">&#128337;</div>'
            '<div class="empty-t">Belum ada riwayat scan</div>'
            '<div class="empty-s">Riwayat akan muncul setelah kamu menjalankan audit</div>'
            '</div>',
            unsafe_allow_html=True
        )
    else:
        col_h1, col_h2 = st.columns([3, 1])
        with col_h1:
            st.markdown(f'<div class="panel-lbl">{len(history)} Scan Tersimpan</div>', unsafe_allow_html=True)
        with col_h2:
            if st.button("🗑 Hapus History", use_container_width=True):
                clear_history()
                st.rerun()

        for entry in reversed(history):
            st.markdown(
                f'<div class="hist-card">'
                f'<span class="hist-ts">{entry["timestamp"]}</span>'
                f'<span class="hist-fname">{entry["filename"]}</span>'
                f'<div class="hist-badges">'
                f'<span class="hb hb-c">{entry["critical"]}C</span>'
                f'<span class="hb hb-h">{entry["high"]}H</span>'
                f'<span class="hb hb-m">{entry["medium"]}M</span>'
                f'<span class="hb hb-l">{entry["low"]}L</span>'
                f'</div></div>',
                unsafe_allow_html=True
            )

        # Trend chart
        if len(history) > 1:
            st.markdown('<div class="panel-lbl" style="margin-top:1rem">Trend Total Findings</div>', unsafe_allow_html=True)
            trend = {f"{e['timestamp'][-8:]} {e['filename'][:12]}": e["total"] for e in history[-10:]}
            st.line_chart(trend, color="#6366F1", height=160)
