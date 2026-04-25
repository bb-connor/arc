/* global React */
const { useEffect: useEffectN, useState: useStateN, useRef: useRefN } = React;

function Narrative({ beats, activeIdx, onPick, playing, onTogglePlay, pausedAt }) {
  const beat = beats[activeIdx];
  return (
    <div className="narrative">
      <div className="narr-head">
        <span>Narrative · 12-beat storyboard · sourced from artifacts</span>
        <div className="ctrls">
          <button onClick={() => onPick(Math.max(0, activeIdx - 1))}>[ prev</button>
          <button onClick={onTogglePlay}>{playing ? "❚❚ pause" : "▶ play"}</button>
          <button onClick={() => onPick(Math.min(beats.length - 1, activeIdx + 1))}>next ]</button>
        </div>
      </div>
      <div className="beats">
        {beats.map((b, i) => (
          <button
            key={b.n}
            className={"beat" + (i === activeIdx ? " active" : "") + (i < activeIdx ? " played" : "") + (b.pause ? " pause-beat" : "")}
            onClick={() => onPick(i)}
          >
            <span className="bn">{String(b.n).padStart(2, "0")}{b.pause ? " · AUTOPAUSE" : ""}</span>
            <span className="bt">{b.title}</span>
          </button>
        ))}
      </div>
      {beat && (
        <div className="beat-caption">
          {beat.caption}
          {beat.artifacts.map((a, i) => <span key={i} className="ref">{a}</span>)}
        </div>
      )}
    </div>
  );
}

window.Narrative = Narrative;
