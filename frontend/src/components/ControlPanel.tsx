import { useState } from "react";
import { api } from "../services/api";

const ATTACKS: Array<{ id: string; label: string }> = [
  { id: "gps_spoofing", label: "GPS Spoofing" },
  { id: "mavlink_anomaly", label: "MAVLink Anomaly" },
  { id: "command_injection", label: "Command Injection" },
  { id: "telemetry_manipulation", label: "Telemetry Manipulation" },
  { id: "dos", label: "Denial of Service" },
  { id: "firmware_integrity", label: "Firmware Tamper" },
];

export function ControlPanel({ activeAttack, controls, environment }: {
  activeAttack: string | null;
  controls: boolean; // SIM only (lib/source.ts envView)
  environment: string;
}) {
  const [busy, setBusy] = useState(false);

  if (!controls) {
    return (
      <div className="panel" data-testid="controls-readonly">
        <header>
          <span className="panel-title">Console Controls</span>
          <span className="panel-note">read-only source</span>
        </header>
        <div className="empty">
          This server monitors a <b>{environment}</b> source. Start / stop / reset and attack injection
          are simulation-only — the backend refuses them (HTTP 409) — and the IDS never transmits to the
          vehicle.
        </div>
      </div>
    );
  }

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await fn();
    } finally {
      setBusy(false);
    }
  };

  const activeLabel = activeAttack
    ? ATTACKS.find((a) => a.id === activeAttack)?.label ?? activeAttack.replace(/_/g, " ")
    : null;

  return (
    <div className="panel">
      <header>
        <span className="panel-title">Console Controls</span>
        <span className="panel-note">safe simulation</span>
      </header>

      <div className="ctl-group">
        <div className="ctl-label">Simulation</div>
        <div className="ctl-row">
          <button className="primary" disabled={busy} onClick={() => run(api.start)}>Start</button>
          <button disabled={busy} onClick={() => run(api.stop)}>Stop</button>
          <button className="ghost-danger" disabled={busy} onClick={() => run(api.reset)}>Reset</button>
        </div>
      </div>

      <div className="ctl-group">
        <div className="ctl-label">Attack Injection</div>
        <div className="attack-grid">
          {ATTACKS.map((a) => (
            <button
              key={a.id}
              className={`attack${activeAttack === a.id ? " active" : ""}`}
              disabled={busy}
              onClick={() => run(() => api.attack(a.id))}
            >
              <span className="a-name">{a.label}</span>
            </button>
          ))}
        </div>

        {activeLabel ? (
          <div className="active-banner">
            <span className="dot" />
            <span>Active — <b>{activeLabel}</b></span>
            <button
              style={{ marginLeft: "auto" }}
              disabled={busy}
              onClick={() => run(() => api.attack("none"))}
            >
              Clear
            </button>
          </div>
        ) : (
          <div className="clear-row">
            <button disabled>No attack injected</button>
          </div>
        )}
      </div>
    </div>
  );
}
