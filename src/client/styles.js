/**
 * Shadow-DOM stylesheet for the protected viewer.
 */

export const SHADOW_CSS = `
  :host { display:block; }
  * { box-sizing: border-box; }
  .wrap {
    position:relative; width:100%; height:100%; overflow:hidden;
    background:#0b0e14; isolation:isolate;
    -webkit-touch-callout:none; -webkit-user-select:none; user-select:none;
    -webkit-user-drag:none;
  }
  .wrap.loading { background: linear-gradient(110deg,#12161f 30%,#1c2333 45%,#12161f 60%);
    background-size:200% 100%; animation: archx-shimmer 1.4s linear infinite; }
  @keyframes archx-shimmer { to { background-position:-200% 0; } }
  canvas.main, .tiles { position:absolute; inset:0; width:100%; height:100%; display:block; }
  .tiles { display:grid; }
  .tiles canvas { width:100%; height:100%; display:block; }
  .shield { position:absolute; inset:0; z-index:3; background:transparent; }
  .trace { position:absolute; inset:-20%; z-index:2; pointer-events:none; overflow:hidden; opacity:0; }
  .wrap.trace-on:not(.loading) .trace { opacity:1; }
  .wrap.blackout .trace { opacity:0 !important; }
  .trace.temporal::before { content:""; position:absolute; inset:0;
    background:repeating-linear-gradient(90deg, rgba(255,255,255,.028) 0 1px, transparent 1px 5px);
    animation:archx-trace-phase 1.4s linear infinite; }
  .trace-inner { position:absolute; inset:0; display:flex; flex-direction:column;
    justify-content:space-around; align-items:center; white-space:nowrap;
    color:rgba(255,255,255,var(--trace-opacity,.08));
    text-shadow:0 1px 2px rgba(0,0,0,.18);
    font:700 14px/1.2 system-ui,sans-serif; letter-spacing:.04em;
    transform:rotate(-17deg); transform-origin:center;
    animation:archx-trace-drift 14s ease-in-out infinite alternate; }
  @keyframes archx-trace-drift {
    from { transform:rotate(-17deg) translate(-1.5%,-1%); }
    to { transform:rotate(-17deg) translate(1.5%,1%); }
  }
  @keyframes archx-trace-phase { to { background-position:15px 0; } }
  @media (prefers-reduced-motion: reduce) {
    .trace-inner, .trace.temporal::before { animation:none; }
  }
  .risk { position:absolute; inset:0; z-index:4; pointer-events:none; opacity:0; transition:opacity .18s;
    backdrop-filter: blur(18px) brightness(.25) saturate(0); background:rgba(0,0,0,.55); }
  .wrap.risk-on .risk { opacity:1; }
  .wrap.risk-on canvas.main, .wrap.risk-on .tiles { filter: blur(22px) brightness(.2) saturate(0); }
  .wrap.blackout canvas.main, .wrap.blackout .tiles { opacity:0 !important; }
  .wrap.blackout { background:#000 !important; }
  .err { position:absolute; inset:0; display:none; place-items:center; color:#8b94a7;
    font:13px/1.5 system-ui,sans-serif; text-align:center; padding:16px; z-index:5; }
  .wrap.error .err { display:grid; }
  .badge { position:absolute; right:8px; bottom:8px; z-index:2; pointer-events:none;
    font:600 10px/1 system-ui,sans-serif; letter-spacing:.08em; color:rgba(255,255,255,.85);
    background:rgba(5,8,15,.55); padding:5px 7px; border-radius:99px; display:none; }
  .wrap.show-badge .badge { display:block; }
  @media print {
    .wrap { background:#000 !important; }
    canvas.main, .tiles { opacity:0 !important; visibility:hidden !important; }
  }
`;

/* ================================================================== */
/* ProtectedImage                                                      */
/* ================================================================== */
