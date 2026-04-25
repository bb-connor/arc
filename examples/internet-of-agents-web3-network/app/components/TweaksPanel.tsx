"use client";

import { useState } from "react";

export interface TweaksState {
  showNarrative: boolean;
  liveMode: boolean;
}

interface TweaksPanelProps {
  state: TweaksState;
  onChange: (next: Partial<TweaksState>) => void;
  onTriggerDenial: () => void;
  onSimulateWobble: () => void;
  onJumpManifest: () => void;
}

export function TweaksPanel({
  state,
  onChange,
  onTriggerDenial,
  onSimulateWobble,
  onJumpManifest,
}: TweaksPanelProps): JSX.Element | null {
  const [open, setOpen] = useState<boolean>(true);
  return (
    <div className="mini-tweaks" role="region" aria-label="Dev tweaks">
      <div className="mt-head" onClick={() => setOpen((v) => !v)}>
        <span>Tweaks</span>
        <span>{open ? "▾" : "▸"}</span>
      </div>
      {open ? (
        <div className="mt-body">
          <div className="mt-row">
            <span>Narrative overlay</span>
            <button
              type="button"
              className="mt-toggle"
              data-on={state.showNarrative ? "1" : "0"}
              onClick={() => onChange({ showNarrative: !state.showNarrative })}
            >
              {state.showNarrative ? "on" : "off"}
            </button>
          </div>
          <div className="mt-row">
            <span>Live mode</span>
            <button
              type="button"
              className="mt-toggle"
              data-on={state.liveMode ? "1" : "0"}
              onClick={() => onChange({ liveMode: !state.liveMode })}
            >
              {state.liveMode ? "on" : "off"}
            </button>
          </div>
          <button type="button" className="mt-btn" onClick={onTriggerDenial}>
            Trigger adversarial denial
          </button>
          <button type="button" className="mt-btn" onClick={onSimulateWobble}>
            Simulate attestation wobble
          </button>
          <button type="button" className="mt-btn" onClick={onJumpManifest}>
            Jump to bundle manifest
          </button>
        </div>
      ) : null}
    </div>
  );
}
