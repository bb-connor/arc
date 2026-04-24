"use client";

import { useEffect, useRef, useState } from "react";

import { NODE_POS, QUAD, edgePath, hexPoints } from "@/lib/topology";
import { mergeTopology } from "@/lib/orgs";
import type { Edge, PulseSpec, Topology } from "@/lib/types";

interface GraphProps {
  topology: Topology;
  onPickEdge?: (e: Edge) => void;
  highlightEdges?: string[];
  pulseBatch: PulseSpec[];
  denialFlash: string[];
  degraded: string[];
}

export function Graph({
  topology,
  onPickEdge,
  highlightEdges,
  pulseBatch,
  denialFlash,
  degraded,
}: GraphProps): JSX.Element {
  const { orgs, edges } = mergeTopology(topology);
  const [hoverEdge, setHoverEdge] = useState<Edge | null>(null);
  const [hoverPos, setHoverPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const warnedRef = useRef<Set<string>>(new Set());
  const warnMissing = (id: string): void => {
    if (!warnedRef.current.has(id)) {
      warnedRef.current.add(id);
      console.warn(`graph: no layout for node ${id}`);
    }
  };

  return (
    <div className="graph-wrap" data-testid="graph">
      <svg className="graph-svg" viewBox="0 0 1000 700" preserveAspectRatio="xMidYMid meet">
        <defs>
          <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
            <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="0.5" />
          </pattern>
          <marker id="arrow-teal" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0 0 L10 5 L0 10 z" fill="#2dd4bf" />
          </marker>
          <marker id="arrow-grey" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
            <path d="M0 0 L10 5 L0 10 z" fill="#3a4454" />
          </marker>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" />
          </filter>
        </defs>

        <rect width="1000" height="700" fill="url(#grid)" />

        {Object.values(orgs).map((o) => {
          const q = QUAD[o.quadrant];
          return (
            <g key={o.id}>
              <rect className="quad-box" x={q.x} y={q.y} width={q.w} height={q.h} />
              <text className="quad-label" x={q.x + 14} y={q.y + 22}>
                {o.name.toUpperCase()}
              </text>
              <text className="quad-role" x={q.x + 14} y={q.y + 36}>
                {o.role}
              </text>
              <text className="quad-url" x={q.x + 14} y={q.y + q.h - 12}>
                {o.trustControlUrl.replace("https://", "")}
              </text>
              <path
                d={`M${q.x} ${q.y + 8} L${q.x} ${q.y} L${q.x + 8} ${q.y}`}
                stroke={o.color}
                strokeWidth="1.5"
                fill="none"
                opacity="0.6"
              />
              <path
                d={`M${q.x + q.w - 8} ${q.y} L${q.x + q.w} ${q.y} L${q.x + q.w} ${q.y + 8}`}
                stroke={o.color}
                strokeWidth="1.5"
                fill="none"
                opacity="0.6"
              />
            </g>
          );
        })}

        {edges.map((e) => {
          const from = NODE_POS[e.from];
          const to = NODE_POS[e.to];
          if (!from) warnMissing(e.from);
          if (!to) warnMissing(e.to);
          if (!from || !to) return null;
          const d = edgePath(from, to, e.kind);
          const isFlash = e.kind === "denial" && denialFlash.includes(e.id);
          const isHighlight = Boolean(highlightEdges?.includes(e.id));
          const marker =
            e.kind === "mediated" || e.kind === "delegation"
              ? "url(#arrow-teal)"
              : e.kind === "intra"
                ? "url(#arrow-grey)"
                : undefined;
          return (
            <g key={e.id}>
              <path
                id={`edge-${e.id}`}
                className={`edge ${e.kind}${isFlash ? " flash" : ""}${isHighlight ? " highlight" : ""}`}
                d={d}
                markerEnd={marker}
                onMouseEnter={(ev) => {
                  setHoverEdge(e);
                  setHoverPos({ x: ev.clientX, y: ev.clientY });
                }}
                onMouseMove={(ev) => setHoverPos({ x: ev.clientX, y: ev.clientY })}
                onMouseLeave={() => setHoverEdge(null)}
                onClick={() => onPickEdge?.(e)}
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

        {pulseBatch.map((p) => (
          <Pulse
            key={p.key}
            edgeId={p.edgeId}
            kind={p.kind}
            label={p.label}
            duration={p.duration}
            onDone={p.onDone}
          />
        ))}

        {denialFlash.map((eid) => {
          const e = edges.find((x) => x.id === eid);
          if (!e) return null;
          const to = NODE_POS[e.to];
          const from = NODE_POS[e.from];
          if (!to || !from) return null;
          const bx = from.x + (to.x - from.x) * 0.4;
          const by = from.y + (to.y - from.y) * 0.4;
          return <circle key={`${eid}-burn`} className="burn" cx={bx} cy={by} r="2" />;
        })}

        {Object.values(orgs).flatMap((o) => [
          ...o.workloads.map((w) => {
            const p = NODE_POS[w.id];
            if (!p) {
              warnMissing(w.id);
              return null;
            }
            const isDeg = degraded.includes(w.id);
            return (
              <g
                key={w.id}
                className={`workload-node${isDeg ? " degraded" : ""}`}
                transform={`translate(${p.x},${p.y})`}
              >
                <circle className="ring" r="13" />
                <circle className="core" r="4" />
                <text className="label" x="18" y="4">
                  {w.name}
                </text>
              </g>
            );
          }),
          ...o.sidecars.map((s) => {
            const p = NODE_POS[s.id];
            if (!p) {
              warnMissing(s.id);
              return null;
            }
            const isDeg = degraded.includes(s.id);
            return (
              <g
                key={s.id}
                className={`sidecar-node${isDeg ? " degraded" : ""}`}
                transform={`translate(${p.x},${p.y})`}
              >
                <polygon className="hex" points={hexPoints(14)} />
                <text className="hex-label" y="3">
                  CHIO
                </text>
                <text className="name" x="0" y="30" textAnchor="middle">
                  {s.name}
                </text>
              </g>
            );
          }),
          ...o.mcp.map((m) => {
            const p = NODE_POS[m.id];
            if (!p) {
              warnMissing(m.id);
              return null;
            }
            return (
              <g key={m.id} className="mcp-node" transform={`translate(${p.x},${p.y})`}>
                <rect x="-22" y="-8" width="44" height="16" transform="rotate(45)" />
                <text y="3" textAnchor="middle">
                  MCP
                </text>
                <text y="24" textAnchor="middle" style={{ fontSize: 8, fill: "#a78bfa" }}>
                  {m.name}
                </text>
              </g>
            );
          }),
        ])}
      </svg>

      <div className="graph-hud">
        <div className="graph-legend">
          <span className="sw teal">mediated</span>
          <span className="sw dash teal">delegation</span>
          <span className="sw grey">intra-org</span>
          <span className="sw red dash">denial</span>
        </div>
        <div className="graph-legend">
          <span>
            chio/topology.json - {Object.keys(orgs).length} orgs -{" "}
            {Object.values(orgs).reduce((sum, o) => sum + o.workloads.length, 0)} workloads -{" "}
            {Object.values(orgs).reduce((sum, o) => sum + o.sidecars.length, 0)} sidecars
          </span>
        </div>
      </div>

      {hoverEdge ? (
        <div
          className="edge-popover"
          style={{ left: hoverPos.x + 14, top: hoverPos.y + 14, position: "fixed" }}
        >
          <h5>{hoverEdge.kind} edge</h5>
          <div className="kv">
            <span className="k">from</span>
            <span className="v">{hoverEdge.from}</span>
            <span className="k">to</span>
            <span className="v">{hoverEdge.to}</span>
            <span className="k">label</span>
            <span className="v">{hoverEdge.label}</span>
            {hoverEdge.scope ? (
              <>
                <span className="k">scope</span>
                <span className="v">{hoverEdge.scope}</span>
              </>
            ) : null}
            {hoverEdge.ttl ? (
              <>
                <span className="k">ttl</span>
                <span className="v">{hoverEdge.ttl}</span>
              </>
            ) : null}
            {hoverEdge.reason ? (
              <>
                <span className="k">rule</span>
                <span className="v" style={{ color: "#f43f5e" }}>
                  {hoverEdge.reason}
                </span>
              </>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

interface PulseProps {
  edgeId: string;
  kind: string;
  label: string;
  duration: number;
  onDone: () => void;
}

function Pulse({ edgeId, kind, label, duration, onDone }: PulseProps): JSX.Element {
  const ref = useRef<SVGCircleElement | null>(null);
  useEffect(() => {
    const t = setTimeout(() => onDone(), duration + 200);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const href = `#edge-${edgeId}`;
  return (
    <g>
      <circle ref={ref} r={kind === "x402" ? 5 : 4} className={`pulse-token ${kind}`}>
        <animateMotion dur={`${duration}ms`} repeatCount="1" rotate="auto">
          <mpath href={href} />
        </animateMotion>
      </circle>
      {label ? (
        <text className="pulse-label">
          <animateMotion dur={`${duration}ms`} repeatCount="1">
            <mpath href={href} />
          </animateMotion>
          <tspan dy="-10">{label}</tspan>
        </text>
      ) : null}
    </g>
  );
}
