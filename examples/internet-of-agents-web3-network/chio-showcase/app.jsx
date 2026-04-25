/* global React, TopBar, Graph, Explorer, Narrative, Chrome, TweaksPanel, TweakSection, TweakToggle, TweakRadio, TweakSlider, TweakColor, useTweaks, TweakButton */
const { useState, useEffect, useMemo, useRef, useCallback } = React;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "theme": "dark",
  "density": "comfortable",
  "accent": "teal",
  "showNarrative": false,
  "liveMode": false
}/*EDITMODE-END*/;

function App() {
  const bundle = window.BUNDLE;
  const tweaks = (typeof useTweaks === "function") ? useTweaks(TWEAK_DEFAULTS) : [TWEAK_DEFAULTS, ()=>{}];
  const [T, setTweak] = tweaks;
  const setT = (patch) => {
    for (const k of Object.keys(patch)) setTweak(k, patch[k]);
  };

  const [layers, setLayers] = useState({ graph: true, explorer: true, narrative: T.showNarrative });
  useEffect(() => { setLayers((L) => ({ ...L, narrative: T.showNarrative })); }, [T.showNarrative]);

  const [live, setLive] = useState(T.liveMode);
  useEffect(() => { setLive(T.liveMode); }, [T.liveMode]);

  const [selectedPath, setSelectedPath] = useState("summary.json");
  const [filter, setFilter] = useState("");
  const [activeBeat, setActiveBeat] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [highlightEdges, setHighlightEdges] = useState([]);
  const [pulseBatch, setPulseBatch] = useState([]);
  const [denialFlash, setDenialFlash] = useState([]);
  const [degraded, setDegraded] = useState([]);

  const pulseIdRef = useRef(0);
  const addPulse = useCallback((edgeId, kind, label, duration = 2000) => {
    const id = ++pulseIdRef.current;
    setPulseBatch((b) => [...b, {
      key: id, edgeId, kind, label, duration,
      onDone: () => setPulseBatch((bb) => bb.filter((x) => x.key !== id)),
    }]);
  }, []);

  // Ambient traffic
  useEffect(() => {
    if (!layers.graph) return;
    const ambientEdges = ["e5", "e2", "e7", "e8"];
    const id = setInterval(() => {
      const e = ambientEdges[Math.floor(Math.random() * ambientEdges.length)];
      addPulse(e, "", "cap", 2600);
    }, 1700);
    return () => clearInterval(id);
  }, [layers.graph, addPulse]);

  // Narrative playback
  useEffect(() => {
    if (!playing) return;
    const beat = bundle.beats[activeBeat];
    // apply beat effects
    applyBeatEffects(beat);
    if (beat.pause) { setPlaying(false); return; }
    const id = setTimeout(() => {
      setActiveBeat((i) => Math.min(bundle.beats.length - 1, i + 1));
    }, 3200);
    return () => clearTimeout(id);
  }, [playing, activeBeat]);

  // When beat changes (manually or during playback), highlight
  useEffect(() => {
    const beat = bundle.beats[activeBeat];
    if (!beat) return;
    setHighlightEdges(beat.edges || []);
    if (beat.artifacts && beat.artifacts[0]) setSelectedPath(beat.artifacts[0]);
    applyBeatEffects(beat);
  }, [activeBeat]);

  function applyBeatEffects(beat) {
    if (!beat) return;
    // denial beat: flash edges
    if (beat.pause && beat.edges && beat.edges.length) {
      setDenialFlash(beat.edges);
      beat.edges.forEach((eid) => addPulse(eid, "denial", "deny", 1000));
      setTimeout(() => setDenialFlash([]), 2200);
    }
    // attestation wobble
    if (beat.n === 7) {
      setDegraded(["proofworks.provider", "proofworks.subcontract-desk"]);
      setTimeout(() => setDegraded([]), 2800);
    }
    // payment x402
    if (beat.n === 9) addPulse("e7", "x402", "x402", 2200);
    if (beat.n === 8) addPulse("e7", "passport", "approve", 2200);
    if (beat.n === 6) addPulse("e6", "", "scope", 2400);
    if (beat.n === 5) addPulse("e5", "", "award", 2400);
    if (beat.n === 2) addPulse("e5", "", "rfq", 2400);
    if (beat.n === 11) { addPulse("e8", "", "read", 1800); addPulse("e9", "", "attest", 2200); }
  }

  const onPickEdge = (e) => {
    // filter explorer tape
    setHighlightEdges([e.id]);
    if (e.kind === "mediated") setSelectedPath("chio/receipts/api-sidecar/market-broker-rfq-lorem.json");
    else if (e.kind === "delegation") setSelectedPath("chio/capabilities/subcontract-cipherworks-lorem.json");
    else if (e.kind === "denial") setSelectedPath("adversarial/forged-passport.json");
    else setSelectedPath("chio/topology.json");
  };

  const toggleLayer = (k) => setLayers((L) => {
    const next = { ...L, [k]: !L[k] };
    // can't turn off both main panes
    if (!next.graph && !next.explorer) return L;
    if (k === "narrative") setT({ showNarrative: next.narrative });
    return next;
  });

  // Keyboard shortcuts
  useEffect(() => {
    const onKey = (e) => {
      if (e.target.tagName === "INPUT") return;
      if (e.key === "[") setActiveBeat((i) => Math.max(0, i - 1));
      else if (e.key === "]") setActiveBeat((i) => Math.min(bundle.beats.length - 1, i + 1));
      else if (e.key === "g") toggleLayer("graph");
      else if (e.key === "x") toggleLayer("explorer");
      else if (e.key === "n") toggleLayer("narrative");
      else if (e.key === "/") {
        e.preventDefault();
        document.querySelector(".tree-filter input")?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const mainClass = "main" + (!layers.graph ? " explorer-only" : "") + (!layers.explorer ? " graph-only" : "");

  return (
    <div className="app">
      <TopBar
        review={bundle.reviewResult}
        summary={bundle.summary}
        manifest={bundle.manifest}
        layers={layers}
        onToggleLayer={toggleLayer}
        live={live}
        onToggleLive={() => { setLive(!live); setT({ liveMode: !live }); }}
      />

      <div className={mainClass}>
        {layers.graph && (
          <div className="pane">
            <div className="pane-header">
              <span>graph · anchored four-quadrant topology</span>
              <span className="muted">chio/topology.json</span>
            </div>
            <div style={{height:"calc(100% - 28px)"}}>
              <Graph
                bundle={bundle}
                onPickEdge={onPickEdge}
                highlightEdges={highlightEdges}
                pulseBatch={pulseBatch}
                denialFlash={denialFlash}
                degraded={degraded}
              />
            </div>
            <Chrome summary={bundle.summary}/>
            <div className="hint">[ / ] narrative beat · g graph · x explorer · / filter</div>
          </div>
        )}
        {layers.explorer && (
          <div className="pane">
            <div className="pane-header">
              <span>explorer · verify any claim against raw artifact</span>
              <span className="muted">offline · in-browser hash check</span>
            </div>
            <div style={{height:"calc(100% - 28px)"}}>
              <Explorer
                bundle={bundle}
                selectedPath={selectedPath}
                onSelectPath={setSelectedPath}
                filter={filter}
                onFilter={setFilter}
              />
            </div>
          </div>
        )}
      </div>

      {layers.narrative && (
        <Narrative
          beats={bundle.beats}
          activeIdx={activeBeat}
          onPick={(i) => { setActiveBeat(i); }}
          playing={playing}
          onTogglePlay={() => setPlaying((p) => !p)}
        />
      )}

      {/* Tweaks */}
      {TweaksPanel && (
        <TweaksPanel title="Tweaks">
          <TweakSection label="Presentation">
            <TweakToggle label="Narrative overlay" value={T.showNarrative} onChange={(v) => setTweak("showNarrative", v)}/>
            <TweakToggle label="Live mode" value={T.liveMode} onChange={(v) => setTweak("liveMode", v)}/>
          </TweakSection>
          <TweakSection label="Actions">
            <TweakButton label="Trigger adversarial denial" onClick={() => {
              setDenialFlash(["d1", "d2"]);
              addPulse("d1", "denial", "forged-passport", 1000);
              addPulse("d2", "denial", "over-budget", 1000);
              setTimeout(() => setDenialFlash([]), 2200);
              setSelectedPath("adversarial/forged-passport.json");
            }}/>
            <TweakButton label="Simulate attestation wobble" onClick={() => {
              setDegraded(["proofworks.provider", "proofworks.subcontract-desk"]);
              setTimeout(() => setDegraded([]), 3000);
              setSelectedPath("identity/runtime-degradation/proofworks-wobble-lorem.json");
            }}/>
            <TweakButton label="Jump to bundle manifest" onClick={() => setSelectedPath("bundle-manifest.json")}/>
          </TweakSection>
        </TweaksPanel>
      )}
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
