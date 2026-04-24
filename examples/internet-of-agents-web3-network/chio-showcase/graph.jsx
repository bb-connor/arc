/* global React */
const { useMemo, useState: useStateG, useEffect: useEffectG, useRef: useRefG } = React;

// Quadrant layout coords (viewBox 1000x700)
const QUAD = {
  tl: { x: 40,  y: 40,  w: 460, h: 300 },
  tr: { x: 500, y: 40,  w: 460, h: 300 },
  br: { x: 500, y: 360, w: 460, h: 300 },
  bl: { x: 40,  y: 360, w: 460, h: 300 },
};

// Positions for nodes relative to quadrant
const NODE_POS = {
  // Atlas (tl)
  "atlas.treasury":    { x: 110, y: 140 },
  "atlas.procurement": { x: 260, y: 180 },
  "atlas.approver":    { x: 130, y: 260 },
  "atlas.mkt-broker":  { x: 400, y: 180 },
  "atlas.mcp.review":  { x: 490, y: 100 },
  // ProofWorks (tr)
  "proofworks.provider":         { x: 620, y: 180 },
  "proofworks.delegator":        { x: 760, y: 240 },
  "proofworks.subcontract-desk": { x: 900, y: 260 },
  "proofworks.mcp.review":       { x: 510, y: 300 },
  // CipherWorks (br)
  "cipherworks.subcontractor": { x: 780, y: 510 },
  "cipherworks.attestor":      { x: 900, y: 440 },
  // Meridian (bl)
  "meridian.settlement":       { x: 210, y: 480 },
  "meridian.settlement-desk":  { x: 370, y: 470 },
  "meridian.auditor":          { x: 110, y: 580 },
  "meridian.mcp.web3":         { x: 490, y: 600 },
};

function Graph({ bundle, selectedEdgeId, onPickEdge, onPickArtifact, highlightEdges, pulseBatch, denialFlash, degraded }) {
  const { orgs, edges } = bundle;
  const [hoverEdge, setHoverEdge] = useStateG(null);
  const [hoverPos, setHoverPos] = useStateG({ x: 0, y: 0 });

  return (
    <div className="graph-wrap">
      <svg className="graph-svg" viewBox="0 0 1000 700" preserveAspectRatio="xMidYMid meet">
        <defs>
          <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
            <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="0.5"/>
          </pattern>
          <marker id="arrow-teal" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0 0 L10 5 L0 10 z" fill="#2dd4bf"/>
          </marker>
          <marker id="arrow-grey" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
            <path d="M0 0 L10 5 L0 10 z" fill="#3a4454"/>
          </marker>
          <filter id="glow"><feGaussianBlur stdDeviation="2"/></filter>
        </defs>

        <rect width="1000" height="700" fill="url(#grid)"/>

        {/* Quadrants */}
        {Object.values(orgs).map((o) => {
          const q = QUAD[o.quadrant];
          return (
            <g key={o.id}>
              <rect className="quad-box" x={q.x} y={q.y} width={q.w} height={q.h}/>
              <text className="quad-label" x={q.x + 14} y={q.y + 22}>{o.name.toUpperCase()}</text>
              <text className="quad-role" x={q.x + 14} y={q.y + 36}>{o.role}</text>
              <text className="quad-url" x={q.x + 14} y={q.y + q.h - 12}>{o.trustControlUrl.replace("https://", "")}</text>
              {/* corner tick */}
              <path d={`M${q.x} ${q.y+8} L${q.x} ${q.y} L${q.x+8} ${q.y}`} stroke={o.color} strokeWidth="1.5" fill="none" opacity="0.6"/>
              <path d={`M${q.x+q.w-8} ${q.y} L${q.x+q.w} ${q.y} L${q.x+q.w} ${q.y+8}`} stroke={o.color} strokeWidth="1.5" fill="none" opacity="0.6"/>
            </g>
          );
        })}

        {/* Edges */}
        {edges.map((e) => {
          const from = NODE_POS[e.from];
          const to = NODE_POS[e.to];
          if (!from || !to) return null;
          const d = edgePath(from, to, e.kind);
          const isFlash = e.kind === "denial" && denialFlash.includes(e.id);
          const isHighlight = highlightEdges && highlightEdges.includes(e.id);
          return (
            <g key={e.id}>
              <path
                id={`edge-${e.id}`}
                className={`edge ${e.kind}${isFlash ? " flash" : ""}${isHighlight ? " highlight" : ""}`}
                d={d}
                markerEnd={e.kind === "mediated" || e.kind === "delegation" ? "url(#arrow-teal)" : (e.kind === "intra" ? "url(#arrow-grey)" : null)}
                onMouseEnter={(ev) => { setHoverEdge(e); setHoverPos({x: ev.clientX, y: ev.clientY}); }}
                onMouseMove={(ev) => setHoverPos({x: ev.clientX, y: ev.clientY})}
                onMouseLeave={() => setHoverEdge(null)}
                onClick={() => onPickEdge && onPickEdge(e)}
                style={{ pointerEvents: e.kind === "denial" && !isFlash ? "none" : "auto" }}
              />
              {(e.kind === "mediated" || e.kind === "delegation") && (
                <text className="edge-label" x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 4}>
                  {e.label}
                </text>
              )}
            </g>
          );
        })}

        {/* Token pulses */}
        {pulseBatch.map((p) => (
          <Pulse key={p.key} edgeId={p.edgeId} kind={p.kind} label={p.label} duration={p.duration} onDone={p.onDone} />
        ))}

        {/* Denial burns */}
        {denialFlash.map((eid) => {
          const e = edges.find((x) => x.id === eid);
          if (!e) return null;
          const to = NODE_POS[e.to];
          const from = NODE_POS[e.from];
          const bx = from.x + (to.x - from.x) * 0.4;
          const by = from.y + (to.y - from.y) * 0.4;
          return <circle key={eid + "-burn"} className="burn" cx={bx} cy={by} r="2"/>;
        })}

        {/* Nodes */}
        {Object.values(orgs).flatMap((o) => [
          ...o.workloads.map((w) => {
            const p = NODE_POS[w.id]; if (!p) return null;
            const isDeg = degraded && degraded.includes(w.id);
            return (
              <g key={w.id} className={"workload-node" + (isDeg ? " degraded" : "")} transform={`translate(${p.x},${p.y})`}>
                <circle className="ring" r="13" />
                <circle className="core" r="4" />
                <text className="label" x="18" y="4">{w.name}</text>
              </g>
            );
          }),
          ...o.sidecars.map((s) => {
            const p = NODE_POS[s.id]; if (!p) return null;
            const isDeg = degraded && degraded.includes(s.id);
            return (
              <g key={s.id} className={"sidecar-node" + (isDeg ? " degraded" : "")} transform={`translate(${p.x},${p.y})`}>
                <polygon className="hex" points={hexPoints(14)} />
                <text className="hex-label" y="3">CHIO</text>
                <text className="name" x="0" y="30" textAnchor="middle">{s.name}</text>
              </g>
            );
          }),
          ...o.mcp.map((m) => {
            const p = NODE_POS[m.id]; if (!p) return null;
            return (
              <g key={m.id} className="mcp-node" transform={`translate(${p.x},${p.y})`}>
                <rect x="-22" y="-8" width="44" height="16" transform="rotate(45)"/>
                <text y="3" textAnchor="middle">MCP</text>
                <text y="24" textAnchor="middle" style={{fontSize:8, fill:"#a78bfa"}}>{m.name}</text>
              </g>
            );
          }),
        ])}
      </svg>

      {/* Legend */}
      <div className="graph-hud">
        <div className="graph-legend">
          <span className="sw teal">mediated</span>
          <span className="sw dash teal">delegation</span>
          <span className="sw grey">intra-org</span>
          <span className="sw red dash">denial</span>
        </div>
        <div className="graph-legend">
          <span>chio/topology.json · 4 orgs · 9 workloads · 3 sidecars</span>
        </div>
      </div>

      {hoverEdge && (
        <div className="edge-popover" style={{ left: hoverPos.x + 14, top: hoverPos.y + 14, position: "fixed" }}>
          <h5>{hoverEdge.kind} edge</h5>
          <div className="kv">
            <span className="k">from</span><span className="v">{hoverEdge.from}</span>
            <span className="k">to</span><span className="v">{hoverEdge.to}</span>
            <span className="k">label</span><span className="v">{hoverEdge.label}</span>
            {hoverEdge.scope && <><span className="k">scope</span><span className="v">{hoverEdge.scope}</span></>}
            {hoverEdge.ttl && <><span className="k">ttl</span><span className="v">{hoverEdge.ttl}</span></>}
            {hoverEdge.reason && <><span className="k">rule</span><span className="v" style={{color:"#f43f5e"}}>{hoverEdge.reason}</span></>}
          </div>
        </div>
      )}
    </div>
  );
}

function Pulse({ edgeId, kind, label, duration = 2200, onDone }) {
  const ref = useRefG(null);
  useEffectG(() => {
    const t = setTimeout(() => onDone && onDone(), duration + 200);
    return () => clearTimeout(t);
  }, []);
  const path = `#edge-${edgeId}`;
  return (
    <g>
      <circle ref={ref} r={kind === "x402" ? 5 : 4} className={"pulse-token " + (kind || "")}>
        <animateMotion dur={`${duration}ms`} repeatCount="1" rotate="auto">
          <mpath href={path}/>
        </animateMotion>
      </circle>
      {label && (
        <text className="pulse-label">
          <animateMotion dur={`${duration}ms`} repeatCount="1">
            <mpath href={path}/>
          </animateMotion>
          <tspan dy="-10">{label}</tspan>
        </text>
      )}
    </g>
  );
}

function hexPoints(r) {
  const pts = [];
  for (let i = 0; i < 6; i++) {
    const a = (Math.PI / 3) * i + Math.PI / 6;
    pts.push((r * Math.cos(a)).toFixed(2) + "," + (r * Math.sin(a)).toFixed(2));
  }
  return pts.join(" ");
}

function edgePath(a, b, kind) {
  // slight curve for mediated/delegation, straight for intra
  const dx = b.x - a.x, dy = b.y - a.y;
  if (kind === "intra") {
    return `M${a.x} ${a.y} L${b.x} ${b.y}`;
  }
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  // curvature perpendicular to line
  const len = Math.sqrt(dx*dx + dy*dy);
  const nx = -dy / len, ny = dx / len;
  const curv = Math.min(60, len * 0.15);
  const cx = mx + nx * curv;
  const cy = my + ny * curv;
  return `M${a.x} ${a.y} Q${cx} ${cy} ${b.x} ${b.y}`;
}

window.Graph = Graph;
