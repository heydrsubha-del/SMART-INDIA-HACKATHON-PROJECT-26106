"""ALGORITHMISTIC - "Aurora SOC" visual layer.

Drop-in redesign for the top banner and every module/section header.
It only restyles existing class names (.topbar-*, .part-banner, .sec-head,
.num-head, .dossier-head), so no logic in app.py is touched.

Usage (already wired in the patched app.py):
    from redesign_ui import inject_redesign
    inject_redesign()          # call AFTER the main <style> blocks
"""
import streamlit as st

AURORA_CSS = r"""
<style>
/* =====================================================================
   AURORA SOC  -  multi-colour, glass, mobile-first
   ===================================================================== */
@property --ang {syntax:"<angle>"; inherits:false; initial-value:0deg;}
@keyframes aoSpin   {to {--ang:360deg;}}
@keyframes aoDrift  {0%,100% {transform:translate3d(0,0,0) scale(1);} 50% {transform:translate3d(3%,-6%,0) scale(1.12);}}
@keyframes aoPulse  {0%,100% {box-shadow:0 0 0 0 color-mix(in srgb,var(--c,#34d399) 55%,transparent);} 70% {box-shadow:0 0 0 7px transparent;}}
@keyframes aoSheen  {0% {transform:translateX(-120%);} 60%,100% {transform:translateX(220%);}}

.stApp {
  --ao-cyan:#22d3ee; --ao-violet:#a78bfa; --ao-pink:#f472b6; --ao-amber:#fbbf24;
  --ao-green:#34d399; --ao-blue:#60a5fa; --ao-orange:#fb923c; --ao-rose:#fb7185;
  --ao-ring:conic-gradient(from var(--ang),#22d3ee,#a78bfa,#f472b6,#fbbf24,#34d399,#22d3ee);
}

/* ============================ TOP BANNER ============================ */
.stApp .topbar-shell {
  isolation:isolate; position:relative; overflow:hidden;
  display:grid; grid-template-columns:minmax(0,1fr) auto; align-items:center; gap:22px 28px;
  padding:30px 34px; margin:10px 0 22px; border:0; border-radius:26px;
  background:
    radial-gradient(60% 120% at 0% 0%,   rgba(34,211,238,.20), transparent 60%),
    radial-gradient(50% 110% at 55% 120%, rgba(244,114,182,.17), transparent 62%),
    radial-gradient(45% 100% at 100% 0%, rgba(167,139,250,.24), transparent 60%),
    linear-gradient(160deg,#0e1526 0%,#0a0f1c 100%);
  box-shadow:0 24px 60px -18px rgba(0,0,0,.65), 0 0 60px -20px rgba(167,139,250,.35), inset 0 1px 0 rgba(255,255,255,.07);
}
/* animated rainbow hairline border */
.stApp .topbar-shell::before {
  content:""; position:absolute; inset:0; border-radius:inherit; padding:1.5px; z-index:3; pointer-events:none;
  background:var(--ao-ring); animation:aoSpin 9s linear infinite;
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor; mask:linear-gradient(#000 0 0) content-box exclude,linear-gradient(#000 0 0);
  opacity:.85;
}
/* network graphic stays, but tinted + faded so text always wins */
.stApp .topbar-shell::after {
  opacity:.55; mix-blend-mode:screen; z-index:0;
  -webkit-mask-image:linear-gradient(90deg,transparent 30%,#000 100%);
  mask-image:linear-gradient(90deg,transparent 30%,#000 100%);
}
.stApp .topbar-brand, .stApp .topbar-status-wrap {position:relative; z-index:2;}
.stApp .topbar-brand {display:flex; align-items:center; gap:22px; min-width:0;}

/* logo with spinning aurora ring */
.stApp .topbar-logo {
  position:relative; width:78px; height:78px; flex:0 0 78px; padding:9px; border-radius:22px;
  background:radial-gradient(circle at 35% 30%,rgba(167,139,250,.35),rgba(10,15,28,.9) 70%);
  box-shadow:0 10px 30px rgba(0,0,0,.5), 0 0 34px -4px rgba(34,211,238,.45);
}
.stApp .topbar-logo::before {
  content:""; position:absolute; inset:-2px; border-radius:24px; padding:2px; pointer-events:none;
  background:var(--ao-ring); animation:aoSpin 5s linear infinite;
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor; mask:linear-gradient(#000 0 0) content-box exclude,linear-gradient(#000 0 0);
}
.stApp .topbar-logo img {border-radius:14px; filter:drop-shadow(0 0 10px rgba(34,211,238,.5));}

.stApp .topbar-kicker {
  display:inline-flex; align-items:center; gap:10px; margin-bottom:8px;
  font:800 11px/1 ui-monospace,"JetBrains Mono",Consolas,monospace; letter-spacing:.24em; text-transform:uppercase;
  background:linear-gradient(90deg,var(--ao-amber),var(--ao-pink)); -webkit-background-clip:text; background-clip:text; color:transparent;
}
.stApp .topbar-kicker::before {content:""; width:22px; height:2px; border-radius:2px; background:linear-gradient(90deg,var(--ao-amber),var(--ao-pink));}
.stApp .topbar-title {
  font:900 clamp(21px,3.1vw,36px)/1.14 Inter,"Segoe UI",system-ui,sans-serif; letter-spacing:-.02em;
  background:linear-gradient(95deg,#ffffff 0%,#c7f3ff 38%,#d9ccff 70%,#ffd3ec 100%);
  -webkit-background-clip:text; background-clip:text; color:transparent; text-shadow:none;
  text-wrap:balance;
}

/* sub-capabilities as colour-coded chips (replaces one long dotted line) */
.stApp .topbar-subtitle {margin-top:14px; display:flex; flex-wrap:wrap; gap:8px; font-size:12px;}
.stApp .tb-chip {
  --c:var(--ao-cyan); position:relative; display:inline-flex; align-items:center; gap:7px;
  padding:6px 12px; border-radius:999px; white-space:nowrap;
  font:600 11.5px/1 Inter,"Segoe UI",sans-serif; letter-spacing:.01em; color:#e6eefc;
  background:color-mix(in srgb,var(--c) 11%,rgba(255,255,255,.02));
  border:1px solid color-mix(in srgb,var(--c) 38%,transparent);
  box-shadow:0 0 18px -8px var(--c);
  transition:transform .18s ease, box-shadow .18s ease, background .18s ease;
}
.stApp .tb-chip::before {content:""; width:6px; height:6px; border-radius:50%; background:var(--c); box-shadow:0 0 8px var(--c);}
.stApp .tb-chip:hover {transform:translateY(-2px); box-shadow:0 8px 22px -8px var(--c); background:color-mix(in srgb,var(--c) 20%,transparent);}
.stApp .tb-chip:nth-child(1){--c:#22d3ee;} .stApp .tb-chip:nth-child(2){--c:#a78bfa;}
.stApp .tb-chip:nth-child(3){--c:#f472b6;} .stApp .tb-chip:nth-child(4){--c:#fbbf24;}
.stApp .tb-chip:nth-child(5){--c:#34d399;} .stApp .tb-chip:nth-child(6){--c:#60a5fa;}

/* status column */
.stApp .topbar-status-wrap {display:flex; flex-direction:column; align-items:flex-end; gap:10px; min-width:0; max-width:100%;}
.stApp .topbar-actions {margin:0; max-width:100%;}
.stApp .topbar-account-chip {
  display:inline-flex; align-items:center; gap:11px; max-width:100%; padding:7px 16px 7px 8px; border-radius:999px;
  background:linear-gradient(135deg,rgba(255,255,255,.08),rgba(255,255,255,.02));
  border:1px solid rgba(167,139,250,.35); backdrop-filter:blur(10px); -webkit-backdrop-filter:blur(10px);
  box-shadow:0 8px 24px -10px rgba(167,139,250,.6);
}
.stApp .topbar-account-avatar {
  width:30px; height:30px; flex:0 0 30px; border-radius:50%; display:grid; place-items:center;
  font:800 13px/1 Inter,sans-serif; color:#0a0f1c;
  background:conic-gradient(from 200deg,#22d3ee,#a78bfa,#f472b6,#fbbf24,#22d3ee);
  box-shadow:0 0 14px rgba(244,114,182,.5);
}
.stApp .topbar-account-email {min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font:600 13px/1 Inter,sans-serif; color:#eef4ff;}
.stApp .topbar-status-pill {
  --c:#34d399; position:relative; overflow:hidden; display:inline-flex; align-items:center; gap:9px;
  padding:8px 16px; border-radius:999px; font:700 12px/1 Inter,sans-serif;
  background:color-mix(in srgb,var(--c) 13%,rgba(8,14,26,.6)); border:1px solid color-mix(in srgb,var(--c) 45%,transparent);
  box-shadow:0 0 26px -8px var(--c);
}
.stApp .topbar-status-pill::after {
  content:""; position:absolute; inset:0; width:40%;
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.22),transparent); animation:aoSheen 4.5s ease-in-out infinite;
}
.stApp .topbar-status-dot {width:8px; height:8px; background:var(--c); animation:aoPulse 2s ease-out infinite; box-shadow:0 0 10px var(--c);}
.stApp .topbar-status-online {color:#bff7de; font-weight:700;}
.stApp .topbar-status-time {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.14em; color:#7f93b4;}

/* ===================== MODULE / PART BANNERS ======================= */
.stApp .part-banner-batch, .stApp .sec-batch {--tone:#22d3ee;}
.stApp .part-banner-single, .stApp .sec-single, .stApp .dossier-head {--tone:#fb923c;}
.stApp .part-banner-ai, .stApp .sec-ai {--tone:#a78bfa;}
.stApp .part-banner-intel, .stApp .sec-intel {--tone:#34d399;}
.stApp .part-banner-rose, .stApp .sec-rose {--tone:#fb7185;}
.stApp .part-banner-sky, .stApp .sec-sky {--tone:#60a5fa;}
.stApp .part-banner-gold, .stApp .sec-gold {--tone:#fbbf24;}
.stApp .part-banner-teal, .stApp .sec-teal {--tone:#2dd4bf;}
.stApp .part-banner-plum, .stApp .sec-plum {--tone:#e879f9;}
.stApp .part-banner-lime, .stApp .sec-lime {--tone:#a3e635;}

.stApp .part-banner, .stApp .dossier-head {
  --tone2:color-mix(in srgb,var(--tone) 45%,#f472b6);
  isolation:isolate; position:relative; overflow:hidden; border:0; border-radius:20px;
  padding:20px 26px 20px 32px; margin:10px 0 20px;
  background:
    radial-gradient(70% 160% at 0% 0%, color-mix(in srgb,var(--tone) 24%,transparent), transparent 62%),
    radial-gradient(40% 140% at 100% 100%, color-mix(in srgb,var(--tone2) 20%,transparent), transparent 70%),
    linear-gradient(180deg,rgba(18,25,42,.96),rgba(10,15,27,.96));
  box-shadow:0 18px 40px -22px color-mix(in srgb,var(--tone) 70%,#000), inset 0 1px 0 rgba(255,255,255,.06);
  transition:transform .25s ease, box-shadow .25s ease;
}
.stApp .part-banner:hover {transform:translateY(-2px); box-shadow:0 26px 50px -22px color-mix(in srgb,var(--tone) 85%,#000), inset 0 1px 0 rgba(255,255,255,.08);}
/* gradient hairline border (tone -> tone2) */
.stApp .part-banner::before, .stApp .dossier-head::before {
  content:""; position:absolute; inset:0; left:0; top:0; bottom:0; width:auto; border-radius:inherit; padding:1px; z-index:2; pointer-events:none;
  background:linear-gradient(135deg,var(--tone),transparent 38%,transparent 62%,var(--tone2));
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor; mask:linear-gradient(#000 0 0) content-box exclude,linear-gradient(#000 0 0);
}
/* glowing rail + tech-grid texture on the right */
.stApp .part-banner::after, .stApp .dossier-head::after {
  content:""; position:absolute; inset:0; z-index:0; pointer-events:none;
  background:
    linear-gradient(180deg,transparent 18%,var(--tone) 50%,transparent 82%) left/3px 100% no-repeat,
    linear-gradient(color-mix(in srgb,var(--tone) 14%,transparent) 1px,transparent 1px) 0 0/22px 22px,
    linear-gradient(90deg,color-mix(in srgb,var(--tone) 14%,transparent) 1px,transparent 1px) 0 0/22px 22px;
  -webkit-mask:linear-gradient(90deg,#000 0,transparent 4px,transparent 55%,#000 100%);
  mask:linear-gradient(90deg,#000 0,transparent 4px,transparent 55%,#000 100%);
  opacity:.9;
}
.stApp .part-banner > * {position:relative; z-index:1;}

.stApp .part-banner .pb-step {
  color:var(--tone) !important; font:800 10.5px/1 ui-monospace,"JetBrains Mono",Consolas,monospace !important;
  letter-spacing:.22em !important; text-shadow:0 0 14px color-mix(in srgb,var(--tone) 60%,transparent);
}
.stApp .part-banner .pb-step::before {width:24px; height:2px; border-radius:2px; opacity:1; background:linear-gradient(90deg,var(--tone),var(--tone2));}
.stApp .part-banner .pb-title {
  font:850 clamp(19px,2.4vw,26px)/1.2 Inter,"Segoe UI",sans-serif; letter-spacing:-.015em;
  background:linear-gradient(95deg,#fff 30%,color-mix(in srgb,var(--tone) 55%,#fff));
  -webkit-background-clip:text; background-clip:text; color:transparent;
}
.stApp .part-banner .pb-sub {color:#9fb0c9; font-size:13px; line-height:1.55;}
.stApp .part-banner .pb-scope {
  --c:var(--tone); gap:10px; padding:8px 14px !important; border-radius:999px;
  font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.15em; color:#e8f1ff !important;
  background:color-mix(in srgb,var(--c) 12%,rgba(8,14,26,.55)) !important;
  border:1px solid color-mix(in srgb,var(--c) 45%,transparent) !important;
  box-shadow:0 0 24px -8px var(--c); backdrop-filter:blur(8px); -webkit-backdrop-filter:blur(8px);
  max-width:100%; overflow-wrap:anywhere;
}
.stApp .part-banner .pb-scope::before {background:var(--c); box-shadow:0 0 10px var(--c); animation:aoPulse 2.2s ease-out infinite;}

/* ======================== SLIM SECTION HEADS ======================= */
.stApp .sec-head {padding:2px 0 2px 18px !important;}
.stApp .sec-head::before {width:4px; border-radius:4px; background:linear-gradient(180deg,var(--tone),color-mix(in srgb,var(--tone) 45%,#f472b6)); box-shadow:0 0 16px color-mix(in srgb,var(--tone) 70%,transparent);}
.stApp .sec-head .sh-title {font:800 17px/1.3 Inter,"Segoe UI",sans-serif;}

/* numbered dossier headers */
.stApp .num-head .nh-num {
  background:linear-gradient(135deg,color-mix(in srgb,var(--tone) 85%,#fff),color-mix(in srgb,var(--tone) 55%,#f472b6)) !important;
  color:#0a0f1c !important; border:0 !important; border-radius:12px !important;
  box-shadow:0 8px 22px -8px var(--tone); font-weight:900;
}
.stApp .num-head .nh-rule {background:linear-gradient(90deg,var(--tone),transparent) !important; height:1px; opacity:.6;}

/* ============================= TABLET ============================== */
@media (max-width:900px) {
  .stApp .topbar-shell {grid-template-columns:minmax(0,1fr); padding:24px 22px; border-radius:22px;}
  .stApp .topbar-status-wrap {flex-direction:row; flex-wrap:wrap; align-items:center; justify-content:flex-start; gap:10px 12px;}
  .stApp .topbar-actions {order:1; flex:1 1 auto; min-width:0;}
  .stApp .topbar-status-pill {order:2;}
  .stApp .topbar-status-time {order:3; flex-basis:100%;}
}

/* ============================== PHONE ============================== */
@media (max-width:600px) {
  .stApp .block-container {padding-left:.75rem !important; padding-right:.75rem !important;}
  .stApp .topbar-shell {padding:18px 16px 16px; gap:16px; margin:6px 0 16px; border-radius:20px;}
  .stApp .topbar-brand {align-items:flex-start; gap:14px;}
  .stApp .topbar-logo {width:56px; height:56px; flex-basis:56px; padding:6px; border-radius:16px;}
  .stApp .topbar-logo::before {border-radius:18px;}
  .stApp .topbar-kicker {font-size:9.5px; letter-spacing:.17em; gap:7px; margin-bottom:6px; flex-wrap:wrap; line-height:1.3;}
  .stApp .topbar-kicker::before {width:14px;}
  .stApp .topbar-title {font-size:19px; line-height:1.18;}
  /* chips become a single swipeable row instead of a tall wall of text */
  .stApp .topbar-subtitle {
    flex-wrap:nowrap; overflow-x:auto; margin:14px -16px 0; padding:2px 16px 6px; gap:7px;
    scrollbar-width:none; -webkit-overflow-scrolling:touch; scroll-snap-type:x proximity;
    -webkit-mask:linear-gradient(90deg,transparent,#000 14px,#000 calc(100% - 22px),transparent);
    mask:linear-gradient(90deg,transparent,#000 14px,#000 calc(100% - 22px),transparent);
  }
  .stApp .topbar-subtitle::-webkit-scrollbar {display:none;}
  .stApp .tb-chip {flex:0 0 auto; scroll-snap-align:start; padding:6px 11px; font-size:11px;}
  .stApp .topbar-status-wrap {display:grid; grid-template-columns:minmax(0,1fr) auto; gap:9px;}
  .stApp .topbar-actions {grid-column:1/2;}
  .stApp .topbar-status-pill {grid-column:2/3; padding:8px 12px; font-size:11px;}
  .stApp .topbar-status-time {grid-column:1/-1; text-align:left; font-size:9.5px;}
  .stApp .topbar-account-chip {padding:6px 12px 6px 6px; gap:9px; width:100%;}
  .stApp .topbar-account-avatar {width:26px; height:26px; flex-basis:26px; font-size:12px;}
  .stApp .topbar-account-email {font-size:12px;}

  .stApp .part-banner, .stApp .dossier-head {padding:16px 16px 16px 20px; border-radius:16px; margin:8px 0 14px; gap:12px;}
  .stApp .part-banner .pb-main {flex:1 1 100%;}
  .stApp .part-banner .pb-title {font-size:19px;}
  .stApp .part-banner .pb-sub {font-size:12.5px;}
  .stApp .part-banner .pb-scope {font-size:9.5px; padding:7px 11px !important; letter-spacing:.11em;}
  .stApp .sec-head .sh-title {font-size:15.5px;}
  .stApp .num-head .nh-num {border-radius:10px !important;}
}
@media (max-width:360px) {
  .stApp .topbar-title {font-size:17px;}
  .stApp .topbar-logo {display:none;}
}
@media (prefers-reduced-motion:reduce) {
  .stApp .topbar-shell::before, .stApp .topbar-logo::before, .stApp .topbar-status-pill::after,
  .stApp .topbar-status-dot, .stApp .part-banner .pb-scope::before {animation:none !important;}
  .stApp .part-banner, .stApp .tb-chip {transition:none;}
}
</style>
"""


def inject_redesign():
    """Inject the Aurora SOC stylesheet. Call after the app's main CSS."""
    st.markdown(AURORA_CSS, unsafe_allow_html=True)


# Capability chips for the top banner (label list -> HTML).
TOPBAR_CHIPS = (
    "Evidence acquisition",
    "Header authentication",
    "IOC intelligence",
    "Origin tracing",
    "Campaign correlation",
    "Local AI assessment",
)


def topbar_chips_html():
    return "".join(f'<span class="tb-chip">{c}</span>' for c in TOPBAR_CHIPS)
