/* global React */
const { useState } = React;

function TopBar({ review, summary, manifest, layers, onToggleLayer, live, onToggleLive }) {
  return (
    <div className="topbar">
      <div className="brand">
        <div className="brand-mark">
          <svg viewBox="0 0 20 20" fill="none">
            <rect x="1" y="1" width="8" height="8" stroke="#2dd4bf" strokeWidth="1.2"/>
            <rect x="11" y="1" width="8" height="8" stroke="#2dd4bf" strokeWidth="1.2"/>
            <rect x="1" y="11" width="8" height="8" stroke="#2dd4bf" strokeWidth="1.2"/>
            <rect x="11" y="11" width="8" height="8" stroke="#2dd4bf" strokeWidth="1.2"/>
            <circle cx="10" cy="10" r="2" fill="#2dd4bf"/>
          </svg>
        </div>
        <span className="brand-title">Chio · Evidence Console</span>
        <span className="brand-sep" />
        <span className="brand-sub">v0.1 · bundle-review</span>
      </div>

      <div className="meta">
        <VerdictPill verdict={review.verdict} />
        <div className="meta-item">
          <span className="meta-k">run</span>
          <span className="meta-v">{summary.run_id}</span>
        </div>
        <div className="meta-item">
          <span className="meta-k">started</span>
          <span className="meta-v">{summary.started_at}</span>
        </div>
        <div className="meta-item">
          <span className="meta-k">wall</span>
          <span className="meta-v">{(summary.wall_time_ms / 1000).toFixed(1)}s</span>
        </div>
        <div className="meta-item">
          <span className="meta-k">bundle</span>
          <span className="meta-v" title={manifest.bundle_sha}>{manifest.bundle_sha.slice(0, 22)}…</span>
        </div>
        <div className="meta-item">
          <span className="meta-k">files</span>
          <span className="meta-v">{manifest.file_count}</span>
        </div>
      </div>

      <div className="layer-toggles">
        <button aria-pressed={layers.graph} onClick={() => onToggleLayer("graph")}>Graph</button>
        <button aria-pressed={layers.explorer} onClick={() => onToggleLayer("explorer")}>Explorer</button>
        <button aria-pressed={layers.narrative} onClick={() => onToggleLayer("narrative")}>Narrative</button>
      </div>

      <div className="topbar-actions">
        <button className={"btn-ghost" + (live ? " live" : "")} onClick={onToggleLive}>
          {live ? "Live" : "Review"}
        </button>
        <button className="btn-ghost" title="download bundle (placeholder)">
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" style={{opacity:0.8}}>
            <path d="M5 1v6M2 5l3 3 3-3M1 9h8" stroke="currentColor" strokeWidth="1"/>
          </svg>
          bundle.tar
        </button>
      </div>
    </div>
  );
}

function VerdictPill({ verdict }) {
  const fail = verdict !== "PASS";
  return (
    <div className={"verdict-pill" + (fail ? " fail" : "")}>
      <span className="dot" />
      <span>{verdict}</span>
    </div>
  );
}

window.TopBar = TopBar;
