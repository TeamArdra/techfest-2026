import { useState } from "react";
import { api } from "../services/api";

interface SubModeDef {
  id: string;
  label: string;
  note: string;
}

const ATTACKS: Array<{ id: string; label: string; subModes: SubModeDef[] }> = [
  {
    id: "gps_spoofing",
    label: "GPS Spoofing",
    subModes: [
      { id: "gradual_drift", label: "Gradual Drift", note: "Continuous vector offset" },
      { id: "sudden_offset", label: "Sudden Offset", note: "Instantaneous 120m jump" },
      { id: "replay_freeze", label: "Replay Freeze", note: "Stale coordinates under motion" },
    ],
  },
  {
    id: "mavlink_anomaly",
    label: "MAVLink Anomaly",
    subModes: [
      { id: "seq_scramble", label: "Seq Scramble", note: "Packet counter jumps" },
      { id: "rate_spike", label: "Rate Spike", note: "5x burst packet rate" },
      { id: "rogue_sysid", label: "Rogue SysID", note: "Hostile sender SysID 42" },
      { id: "packet_loss", label: "RF Packet Drop", note: "Sequence gap burst injection" },
    ],
  },
  {
    id: "command_injection",
    label: "Command Injection",
    subModes: [
      { id: "rogue_command", label: "Rogue Command", note: "Unauthorized GCS command" },
      { id: "mode_flip", label: "Mode Hijack", note: "Forced switch to LAND" },
      { id: "arm_disarm_burst", label: "Arm/Disarm Burst", note: "Rapid arm toggle flood" },
      { id: "gcs_replay", label: "Captured GCS Replay", note: "Valid SysID 255 cadence burst" },
    ],
  },
  {
    id: "telemetry_manipulation",
    label: "Telemetry Manipulation",
    subModes: [
      { id: "altitude_bias", label: "Altitude Bias", note: "+35m baro/GPS split" },
      { id: "speed_mismatch", label: "Speed Mismatch", note: "+9 m/s groundspeed bias" },
      { id: "battery_jump", label: "Battery Jump", note: "Erratic voltage swings" },
      { id: "frozen_attitude", label: "Frozen Attitude", note: "Stale AHRS bank/pitch" },
    ],
  },
  {
    id: "dos",
    label: "Denial of Service",
    subModes: [
      { id: "flood", label: "Packet Flood", note: "12x channel saturation" },
      { id: "gnss_jamming", label: "GNSS Jamming", note: "RF denial, fix lost" },
      { id: "blackout", label: "Link Blackout", note: "90% packet drop" },
      { id: "latency", label: "Burst Latency Jitter", note: "Intermittent heartbeat starvation" },
    ],
  },
  {
    id: "firmware_integrity",
    label: "Firmware Tamper",
    subModes: [
      { id: "default", label: "Binary Tamper", note: "SHA-256 manifest mismatch" },
    ],
  },
];

const DRIFT_PRESETS = [
  { val: 0.2, label: "0.2 m/s (Ultra-Stealth CUSUM)" },
  { val: 0.8, label: "0.8 m/s (Subtle)" },
  { val: 2.5, label: "2.5 m/s (Moderate)" },
  { val: 6.0, label: "6.0 m/s (Standard)" },
];

export function ControlPanel({ activeAttack, controls, environment }: {
  activeAttack: string | null;
  controls: boolean; // SIM only (lib/source.ts envView)
  environment: string;
}) {
  const [busy, setBusy] = useState(false);
  const [selectedAttack, setSelectedAttack] = useState<string>("gps_spoofing");
  const [selectedSubMode, setSelectedSubMode] = useState<string>("gradual_drift");
  const [driftRate, setDriftRate] = useState<number>(6.0);

  if (!controls) {
    return (
      <div className="panel" data-testid="controls-readonly">
        <header>
          <span className="panel-title">Console Controls</span>
          <span className="panel-note">read-only source</span>
        </header>
        <div className="empty">
          This server monitors a <b>{environment}</b> source. Start / stop / reset and attack injection
          are simulation-only — the backend refuses them (HTTP 409). In PASSIVE and ADVISORY the IDS does not
          transmit to the vehicle; ACTIVE IPS sends counter-commands.
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

  const currentAtkDef = ATTACKS.find((a) => a.id === selectedAttack) ?? ATTACKS[0];

  const handleSelectAttack = (atkId: string) => {
    setSelectedAttack(atkId);
    const def = ATTACKS.find((a) => a.id === atkId);
    if (def && def.subModes.length > 0) {
      setSelectedSubMode(def.subModes[0].id);
    }
  };

  const handleInject = () => {
    const rate = selectedAttack === "gps_spoofing" && selectedSubMode === "gradual_drift" ? driftRate : undefined;
    run(() => api.attack(selectedAttack, selectedSubMode, rate));
  };

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
        <div className="ctl-label">Attack Vector (6 Classes)</div>
        <div className="attack-grid">
          {ATTACKS.map((a) => (
            <button
              key={a.id}
              className={`attack${selectedAttack === a.id ? " active" : ""}`}
              disabled={busy}
              onClick={() => handleSelectAttack(a.id)}
            >
              <span className="a-name">{a.label}</span>
            </button>
          ))}
        </div>

        {/* Tactical Sub-Mode Picker */}
        {currentAtkDef.subModes.length > 0 && (
          <div style={{ marginTop: 8, padding: "8px 10px", background: "rgba(0,0,0,0.2)", borderRadius: 6 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--muted)", marginBottom: 6 }}>
              <span>TACTICAL SUB-MODE</span>
              <span style={{ color: "var(--accent)" }}>{currentAtkDef.subModes.find((m) => m.id === selectedSubMode)?.note}</span>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {currentAtkDef.subModes.map((sm) => (
                <button
                  key={sm.id}
                  disabled={busy}
                  style={{
                    fontSize: 11,
                    padding: "4px 8px",
                    borderRadius: 4,
                    background: selectedSubMode === sm.id ? "var(--accent)" : "rgba(255,255,255,0.06)",
                    color: selectedSubMode === sm.id ? "#0a0f15" : "var(--fg)",
                    fontWeight: selectedSubMode === sm.id ? 700 : 400,
                    border: "none",
                    cursor: "pointer",
                  }}
                  onClick={() => setSelectedSubMode(sm.id)}
                >
                  {sm.label}
                </button>
              ))}
            </div>

            {/* Subtle Drift Preset (for gradual drift) */}
            {selectedAttack === "gps_spoofing" && selectedSubMode === "gradual_drift" && (
              <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 6, fontSize: 11 }}>
                <span style={{ color: "var(--muted)" }}>Sensitivity:</span>
                {DRIFT_PRESETS.map((p) => (
                  <button
                    key={p.val}
                    disabled={busy}
                    style={{
                      fontSize: 10,
                      padding: "2px 6px",
                      borderRadius: 3,
                      background: driftRate === p.val ? "var(--ok)" : "rgba(255,255,255,0.05)",
                      color: driftRate === p.val ? "#0a0f15" : "var(--muted)",
                      fontWeight: driftRate === p.val ? 700 : 400,
                      border: "none",
                      cursor: "pointer",
                    }}
                    onClick={() => setDriftRate(p.val)}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            )}

            <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
              <button
                className="primary"
                style={{ flex: 1, padding: "6px 12px", fontSize: 12, fontWeight: 700 }}
                disabled={busy}
                onClick={handleInject}
              >
                Inject {currentAtkDef.label} [{currentAtkDef.subModes.find((m) => m.id === selectedSubMode)?.label}]
              </button>
            </div>
          </div>
        )}

        {activeAttack ? (
          <div className="active-banner" style={{ marginTop: 10 }}>
            <span className="dot" />
            <span>Active Attack: <b>{activeAttack.replace(/_/g, " ").toUpperCase()}</b></span>
            <button
              style={{ marginLeft: "auto" }}
              disabled={busy}
              onClick={() => run(() => api.attack("none"))}
            >
              Clear Attack
            </button>
          </div>
        ) : (
          <div className="clear-row" style={{ marginTop: 8 }}>
            <button disabled>No attack currently active</button>
          </div>
        )}
      </div>
    </div>
  );
}
