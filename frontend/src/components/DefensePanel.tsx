import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { DefenseMode, MitigationActionItem, MitigationInfo, Telemetry, Threat } from "../types";

interface Props {
  mode: DefenseMode;
  mitigation: MitigationInfo | null;
  threat: Threat | null;
  telemetry: Telemetry | null;
  topology?: string;
  topologyReasons?: string[];
}

const MODES: Array<{ id: DefenseMode; label: string; desc: string }> = [
  { id: "passive", label: "PASSIVE", desc: "IDS only · zero bytes transmitted · Stage-2 compliant" },
  { id: "advisory", label: "ADVISORY", desc: "HUD STATUSTEXT alerts · zero control actuation" },
  { id: "active-ips", label: "ACTIVE IPS", desc: "Inline sanitization + autonomous counter-actuation" },
];

function getStatesForMode(mode: DefenseMode) {
  if (mode === "passive") {
    return [
      { id: "NOMINAL", label: "NOMINAL", color: "var(--ok)", desc: "Clean flight baseline · Passive stream audit" },
      { id: "AUTO_MITIGATING", label: "INTRUSION DETECTED", color: "var(--warn)", desc: "Anomaly isolated & parameterized · 0 bytes transmitted" },
      { id: "SAFE_HOLD", label: "SUSTAINED ANOMALY", color: "#f97316", desc: "Continuous attack >30s · High-priority IDS alert" },
      { id: "GCS_TAKEOVER", label: "CRITICAL INTEGRITY ALERT", color: "var(--crit)", desc: "In-flight firmware/safety breach · Operator attention" },
    ];
  }
  if (mode === "advisory") {
    return [
      { id: "NOMINAL", label: "NOMINAL", color: "var(--ok)", desc: "Clean flight baseline · HUD advisory standby" },
      { id: "AUTO_MITIGATING", label: "ADVISORY ALERTING", color: "var(--warn)", desc: "Transmitting MAVLink STATUSTEXT warnings to pilot HUD" },
      { id: "SAFE_HOLD", label: "HOLD RECOMMENDED", color: "#f97316", desc: "Sustained attack >30s · Recommend pilot switch to ALT_HOLD" },
      { id: "GCS_TAKEOVER", label: "PILOT TAKEOVER URGENT", color: "var(--crit)", desc: "Critical integrity breach · Immediate manual control advised" },
    ];
  }
  return [
    { id: "NOMINAL", label: "NOMINAL", color: "var(--ok)", desc: "Clean flight baseline · Golden tracking" },
    { id: "AUTO_MITIGATING", label: "AUTO MITIGATING", color: "var(--warn)", desc: "Autonomous closed-loop counter-action" },
    { id: "SAFE_HOLD", label: "SAFE HOLD", color: "#f97316", desc: "Multi-sensor conflict · Loitering on baro/attitude" },
    { id: "GCS_TAKEOVER", label: "GCS TAKEOVER", color: "var(--crit)", desc: "Safety margin breached · Pilot control required" },
  ];
}

function fmtNum(val: number | null | undefined, digits = 1, fallback = "0.0"): string {
  if (typeof val !== "number" || isNaN(val)) return fallback;
  return val.toFixed(digits);
}

function getPilotAdvisory(subMode: string): string {
  if (subMode.startsWith("gps_spoofing")) {
    return "Ignore primary GPS guidance; cross-check baro & switch to ALT_HOLD";
  }
  if (subMode.startsWith("command_injection")) {
    return "Hostile command injected on link; verify GCS link ID and lock controls";
  }
  if (subMode.startsWith("telemetry_manipulation")) {
    return "Sensor bias detected; verify airspeed sensor and baro before altitude changes";
  }
  if (subMode.startsWith("dos")) {
    return "RF link under contention / flood; prepare for Return-To-Launch (RTL)";
  }
  if (subMode.startsWith("mavlink_anomaly")) {
    return "MAVLink sequence or CRC anomaly detected; verify RF telemetry modem";
  }
  if (subMode.startsWith("firmware_integrity")) {
    return "CRITICAL: Firmware signature mismatch; land vehicle immediately";
  }
  return "Monitor flight parameters; standby for pilot action";
}

export function DefensePanel({ mode, mitigation, threat, telemetry, topology, topologyReasons }: Props) {
  const [busy, setBusy] = useState(false);
  const [overrideMsg, setOverrideMsg] = useState<string | null>(null);
  const [optimisticMode, setOptimisticMode] = useState<DefenseMode | null>(null);

  const activeMode = optimisticMode ?? mode ?? "passive";

  useEffect(() => {
    if (optimisticMode && mode === optimisticMode) {
      setOptimisticMode(null);
    }
  }, [mode, optimisticMode]);

  const stateId = mitigation?.state || "NOMINAL";
  const subMode = mitigation?.sub_mode || "NONE";
  const cleanStreak = mitigation?.clean_streak ?? 0;
  const targetTicks = mitigation?.recovery_target_ticks ?? 25;
  const recoveryPct = Math.min(100, Math.round((cleanStreak / Math.max(1, targetTicks)) * 100));

  // Null-safe accessors across flat and nested schemas
  const inputs = mitigation?.inputs;
  const outputs = mitigation?.outputs;
  const params = mitigation?.params;
  const actions: MitigationActionItem[] = mitigation?.actions ?? [];

  const quarantined: number[] = Array.isArray(outputs?.quarantined_sysids)
    ? outputs!.quarantined_sysids
    : Array.isArray(mitigation?.quarantined_sysids)
    ? mitigation!.quarantined_sysids
    : [];

  const rogueSysids: number[] = Array.isArray(outputs?.rogue_sysids)
    ? outputs!.rogue_sysids
    : Array.isArray(params?.rogue_sysids)
    ? params!.rogue_sysids
    : [];

  const northOffset = outputs?.north_offset_m ?? params?.north_offset_m ?? 0;
  const eastOffset = outputs?.east_offset_m ?? params?.east_offset_m ?? 0;
  const driftRate = outputs?.drift_rate_ms ?? params?.drift_rate_ms ?? 0;
  const altBias = outputs?.alt_bias_m ?? params?.alt_bias_m ?? 0;
  const speedBias = outputs?.speed_bias_ms ?? params?.speed_bias_ms ?? 0;
  const batteryBias = outputs?.battery_bias_v ?? params?.battery_bias_v ?? 0;
  const latOffsetDeg = params?.lat_offset_deg ?? 0;
  const targetRestoreMode = outputs?.target_restore_mode ?? params?.target_restore_mode ?? null;
  const counterFramesSent = outputs?.counter_frames_sent ?? mitigation?.counter_frames_sent ?? 0;

  const ekfSwitched = outputs?.ekf_switched ?? mitigation?.ekf_switched ?? false;
  const sanitizeGps = outputs?.sanitize_gps ?? mitigation?.sanitize_gps ?? false;
  const sanitizeAlt = outputs?.sanitize_alt ?? mitigation?.sanitize_alt ?? false;
  const lastCommand = outputs?.last_command_sent ?? mitigation?.last_command_sent ?? null;

  const trustedLat = inputs?.trusted_lat ?? params?.trusted_lat;
  const trustedLon = inputs?.trusted_lon ?? params?.trusted_lon;
  const trustedMode = inputs?.trusted_mode ?? params?.trusted_mode;

  // Real-time Resistance Posture Computation
  const isAttackActive = Boolean(threat?.threat);
  let resClass = "res-nominal";
  let resTitle = "NOMINAL FLIGHT BASELINE";
  let resDesc = "Golden flight state anchor is continually tracking nominal telemetry. Closed-loop IPS is armed and ready.";
  let resBadge = "ARMED";

  if (activeMode === "active-ips") {
    if (isAttackActive) {
      resClass = "res-resisting";
      resTitle = "AUTONOMOUS RESISTANCE ACTIVE (INJECTION NEUTRALIZED)";
      resDesc = `Closed-loop IPS is actively resisting ${threat?.attack_type ?? "intrusion"}. False offsets are stripped by fast-path sanitizer and counter-actuation is holding flight integrity.`;
      resBadge = "NEUTRALIZING";
    } else {
      resClass = "res-nominal";
      resTitle = "ACTIVE IPS ARMED — NOMINAL TRACKING";
      resDesc = "Autonomous inline sanitization and counter-command actuation are live and protecting flight systems.";
      resBadge = "ACTIVE PROTECT";
    }
  } else if (activeMode === "passive") {
    if (isAttackActive) {
      resClass = "res-passive";
      resTitle = "PASSIVE MONITORING — ATTACK DETECTED (COUNTER-ACTION OFF)";
      resDesc = `IDS detected ${threat?.attack_type ?? "attack"}, but operational posture is set to PASSIVE (0 bytes sent). Click 'ACTIVE IPS' above to engage autonomous resistance.`;
      resBadge = "PASSIVE ONLY";
    } else {
      resClass = "res-nominal";
      resTitle = "PASSIVE IDS MONITORING";
      resDesc = "Passive intrusion detection stream active. Stage-2 zero-transmission baseline maintained.";
      resBadge = "IDS READY";
    }
  } else if (activeMode === "advisory") {
    if (isAttackActive) {
      resClass = "res-advisory";
      resTitle = "ADVISORY ALERTING — GCS HUD NOTIFICATION";
      resDesc = `Transmitting STATUSTEXT warnings to GCS HUD for ${threat?.attack_type ?? "attack"}. Control surfaces and sensor sanitization remain un-actuated.`;
      resBadge = "ADVISORY";
    }
  }

  const handleModeChange = async (newMode: DefenseMode) => {
    if (newMode === activeMode || busy) return;
    setOptimisticMode(newMode);
    setBusy(true);
    setOverrideMsg(null);
    try {
      await api.setDefenseMode(newMode);
    } catch (err) {
      setOptimisticMode(null);
      setOverrideMsg(`Failed to switch mode: ${err}`);
    } finally {
      setBusy(false);
    }
  };

  const handleOverride = async (action: "safe_hold" | "reset_quarantine" | "ack_takeover") => {
    if (busy) return;
    setBusy(true);
    setOverrideMsg(null);
    try {
      const res = await api.defenseOverride(action);
      setOverrideMsg(res.mitigation?.summary || `Action ${action} executed`);
    } catch (err) {
      setOverrideMsg(`Override failed: ${err}`);
    } finally {
      setBusy(false);
    }
  };

  const isMitigating = stateId !== "NOMINAL";
  const ladderStates = getStatesForMode(activeMode);

  // Recovery monitor title
  const recoveryTitle =
    activeMode === "passive"
      ? "IDS THREAT CLEARANCE MONITOR"
      : activeMode === "advisory"
      ? "ADVISORY CLEARANCE MONITOR"
      : "QUARANTINE & IPS RECOVERY MONITOR";

  return (
    <section className="panel def-panel" data-testid="defense-panel">
      <div className="panel-head">
        <div className="title-row">
          <h3>HYBRID AUTONOMOUS DEFENSE & RECOVERY</h3>
          <span className={`pill def-mode-pill def-pill-${activeMode}`}>
            {activeMode.toUpperCase()}
          </span>
        </div>
        <div className="panel-sub">
          {activeMode === "passive"
            ? "Passive cyber-physical intrusion detection system (IDS) · zero bytes transmitted"
            : activeMode === "advisory"
            ? "Pilot-in-the-loop advisory alerting system · MAVLink STATUSTEXT dispatch"
            : "Closed-loop cyber-physical intrusion prevention (IPS) and sensor recovery engine"}
        </div>
      </div>

      {/* 0. Real-time Resistance Monitor Banner */}
      <div className={`resistance-banner ${resClass}`}>
        <div className="res-header">
          <div>
            <div className="res-title">{resTitle}</div>
            <div className="res-desc">{resDesc}</div>
          </div>
        </div>
        <div className="res-badge">{resBadge}</div>
      </div>

      {/* 0.1 Hardware & Routing Topology Card */}
      <div style={{
        marginTop: 8,
        padding: "8px 12px",
        borderRadius: 6,
        background: "rgba(10,15,21,0.65)",
        border: "1px solid rgba(255,255,255,0.08)",
        display: "flex",
        flexDirection: "column",
        gap: 4,
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 700, color: "var(--muted)", letterSpacing: "0.06em" }}>
              DEPLOYED TOPOLOGY
            </span>
            <span style={{
              fontSize: 10.5,
              fontWeight: 700,
              padding: "2px 7px",
              borderRadius: 4,
              background: topology === "a" ? "rgba(59,130,246,0.18)" : "rgba(34,197,94,0.18)",
              color: topology === "a" ? "#60a5fa" : "var(--ok)",
              border: `1px solid ${topology === "a" ? "rgba(59,130,246,0.3)" : "rgba(34,197,94,0.3)"}`,
            }}>
              {topology === "a"
                ? "TOPOLOGY A · SIDECAR ACTUATOR"
                : topology === "a+b"
                ? "TOPOLOGY A+B · HYBRID ROUTING"
                : topology === "ids"
                ? "TOPOLOGY IDS · PASSTHROUGH ONLY"
                : "TOPOLOGY B · INLINE SANITIZER BRIDGE"}
            </span>
          </div>
          <span style={{ fontSize: 10, color: "var(--muted)", fontFamily: "var(--mono)" }}>
            {topology === "a"
              ? "MAVLinkActuator Counter-Commands"
              : "FrameSanitizer Inline Filter + Actuator"}
          </span>
        </div>
        <div style={{ fontSize: 11, color: "#9ca3af", lineHeight: 1.4 }}>
          {topology === "a"
            ? "Sidecar configuration on secondary TELEM port: FC executes rogue frames briefly (0.4s reaction window) before counter-command overrides return vehicle to survey mission."
            : topology === "ids"
            ? "Zero-transmission monitoring mode: Link frames are forwarded without interception or counter-command generation."
            : "Direct inline link between GCS radio and FC: Rogue SysID frames and unauthorized commands are dropped inline before reaching the flight controller (0.0 m detour)."}
        </div>
        {topologyReasons && topologyReasons.length > 0 && (
          <div style={{ fontSize: 10, color: "var(--muted)", fontFamily: "var(--mono)", marginTop: 2 }}>
            {topologyReasons[0]}
          </div>
        )}
      </div>

      {/* 1. Operational Mode Switcher */}
      <div className="def-section">
        <div className="def-section-title">OPERATIONAL POSTURE SELECTOR</div>
        <div className="mode-toggle-group" role="radiogroup" aria-label="Defense Mode Selector">
          {MODES.map((m) => {
            const isSelected = activeMode === m.id;
            return (
              <button
                key={m.id}
                type="button"
                className={`mode-btn ${isSelected ? "active" : ""}`}
                onClick={() => handleModeChange(m.id)}
                disabled={busy}
                aria-checked={isSelected}
                role="radio"
              >
                <div className="mode-label">{m.label}</div>
                <div className="mode-desc">{m.desc}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* 2. 4-State Escalation Ladder (Mode-Adaptive) */}
      <div className="def-section">
        <div className="def-section-title">
          {activeMode === "passive"
            ? "IDS ESCALATION STATE MACHINE"
            : activeMode === "advisory"
            ? "ADVISORY ESCALATION STATE MACHINE"
            : "CLOSED-LOOP IPS ESCALATION LADDER"}
        </div>
        <div className="fsm-ladder">
          {ladderStates.map((s, idx) => {
            const isCurrent = stateId === s.id;
            return (
              <div
                key={s.id}
                className={`fsm-step ${isCurrent ? "current" : ""}`}
                style={{ borderColor: isCurrent ? s.color : undefined }}
              >
                <div className="step-num">{idx + 1}</div>
                <div className="step-body">
                  <div className="step-name" style={{ color: isCurrent ? s.color : undefined }}>
                    {s.label}
                  </div>
                  <div className="step-desc">{s.desc}</div>
                </div>
                {isCurrent && <span className="step-indicator" style={{ backgroundColor: s.color }} />}
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. Recovery Monitor Progress (During active mitigation / clearance) */}
      {isMitigating && (
        <div className="def-section recovery-box">
          <div className="recovery-head">
            <span className="recovery-title">{recoveryTitle}</span>
            <span className="recovery-val mono">
              {cleanStreak} / {targetTicks} ticks ({(cleanStreak * 0.2).toFixed(1)}s / 5.0s clean)
            </span>
          </div>
          <div className="recovery-bar-bg">
            <div className="recovery-bar-fill" style={{ width: `${recoveryPct}%` }} />
          </div>
        </div>
      )}

      {/* 4. Forensics Matrix: Side-by-Side Inputs vs Outputs (Strictly Mode-Segregated) */}
      <div className="def-section">
        <div className="def-section-title">DEFENSE FORENSICS MATRIX</div>
        <div className="forensics-grid">
          {/* Left Column: Attack Inputs & Perturbations (Shared Across All Modes) */}
          <div className="forensics-col input-col">
            <div className="col-header">
              <span className="col-tag">INPUTS</span>
              <span className="col-title">Detected Cyber-Physical Vectors</span>
            </div>
            <div className="forensics-data">
              <div className="data-row">
                <span className="lbl">Active Threat</span>
                <span className="val highlight" style={{ color: threat?.threat ? "var(--crit)" : "var(--ok)" }}>
                  {threat?.threat ? threat.attack_type : "BENIGN"}
                </span>
              </div>
              <div className="data-row">
                <span className="lbl">Tactical Sub-Mode</span>
                <span className="val mono">{subMode}</span>
              </div>
              <div className="data-row">
                <span className="lbl">GPS Pos Divergence</span>
                <span className="val mono">
                  {`N: ${fmtNum(northOffset)}m · E: ${fmtNum(eastOffset)}m`}
                  {driftRate > 0.05 && ` · ${fmtNum(driftRate, 2)}m/s`}
                </span>
              </div>
              <div className="data-row">
                <span className="lbl">Sensor Biases</span>
                <span className="val mono">
                  {altBias !== 0 ? `Alt: ${fmtNum(altBias)}m` : "Alt: 0.0m"}
                  {speedBias !== 0 && ` · Spd: ${fmtNum(speedBias)}m/s`}
                  {batteryBias !== 0 && ` · Bat: ${fmtNum(batteryBias, 2)}V`}
                </span>
              </div>
              <div className="data-row">
                <span className="lbl">Rogue System IDs</span>
                <span className="val mono">
                  {rogueSysids.length > 0 ? `[${rogueSysids.join(", ")}]` : "None"}
                </span>
              </div>
              <div className="data-row">
                <span className="lbl">Packet / Link Guard</span>
                <span
                  className="val mono"
                  style={{
                    color: threat?.integrity_status === "INVALID" ? "var(--crit)" : "var(--ok)",
                  }}
                >
                  {threat?.integrity_status === "INVALID"
                    ? "⚠️ CRC / INTEGRITY VIOLATION"
                    : subMode === "command_injection:gcs_replay"
                    ? "⚠️ REPLAY CADENCE SPIKE"
                    : "X.25 VALID + CADENCE ARMED"}
                </span>
              </div>
            </div>
          </div>

          {/* Right Column: Outputs (Strictly Mode-Dependent) */}
          {activeMode === "passive" ? (
            /* PASSIVE MODE: Zero-Emission IDS Audit */
            <div className="forensics-col output-col">
              <div className="col-header">
                <span className="col-tag">IDS POSTURE</span>
                <span className="col-title">Audit & Zero-Emission Posture</span>
              </div>
              <div className="forensics-data">
                <div className="data-row">
                  <span className="lbl">Transmission Policy</span>
                  <span className="val mono" style={{ color: "var(--ok)", fontWeight: 700 }}>
                    0 BYTES SENT (Strict Passive IDS)
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Wire Tap Posture</span>
                  <span className="val mono">READ-ONLY (Pass-Through Tap)</span>
                </div>
                <div className="data-row">
                  <span className="lbl">Control Actuation</span>
                  <span className="val mono" style={{ color: "var(--muted)" }}>
                    DISABLED (Passive Audit)
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Frame Sanitizer</span>
                  <span className="val mono" style={{ color: "var(--muted)" }}>
                    BYPASSED (Unmodified Stream)
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Baseline Flight Mode</span>
                  <span className="val mono">{trustedMode || telemetry?.flight_mode || "AUTO"}</span>
                </div>
                <div className="data-row">
                  <span className="lbl">Detection Latency</span>
                  <span className="val mono">{fmtNum(threat?.latency_ms, 2)} ms</span>
                </div>
              </div>
            </div>
          ) : activeMode === "advisory" ? (
            /* ADVISORY MODE: HUD STATUSTEXT & Pilot Guidance */
            <div className="forensics-col output-col">
              <div className="col-header">
                <span className="col-tag">HUD ADVISORY</span>
                <span className="col-title">MAVLink STATUSTEXT & Guidance</span>
              </div>
              <div className="forensics-data">
                <div className="data-row">
                  <span className="lbl">HUD Alert Channel</span>
                  <span className="val mono" style={{ color: "var(--ok)" }}>
                    MAVLink STATUSTEXT (Active)
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Alert Frames Emitted</span>
                  <span className="val mono">{counterFramesSent} frames</span>
                </div>
                <div className="data-row">
                  <span className="lbl">Last Advisory Sent</span>
                  <span className="val mono">{lastCommand || "Standby"}</span>
                </div>
                <div className="data-row">
                  <span className="lbl">Control Surfaces</span>
                  <span className="val mono" style={{ color: "var(--muted)" }}>
                    UN-ACTUATED (Pilot in Command)
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Recommended Action</span>
                  <span className="val mono" style={{ color: "var(--warn)", fontSize: "11px" }}>
                    {getPilotAdvisory(subMode)}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Baseline Reference</span>
                  <span className="val mono">
                    {trustedLat != null && trustedLon != null
                      ? `${fmtNum(trustedLat, 4)}, ${fmtNum(trustedLon, 4)}`
                      : "Acquiring..."}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            /* ACTIVE IPS MODE: Full Closed-Loop Counter-Actuation & Sanitization */
            <div className="forensics-col output-col">
              <div className="col-header">
                <span className="col-tag">OUTPUTS</span>
                <span className="col-title">Counter-Actuation & Sanitization</span>
              </div>
              <div className="forensics-data">
                <div className="data-row">
                  <span className="lbl">EKF Navigation Source</span>
                  <span className="val mono" style={{ color: ekfSwitched ? "var(--warn)" : "var(--ok)" }}>
                    {ekfSwitched ? "SOURCE 2 (OptFlow / Non-GPS DR)" : "SOURCE 1 (Primary GPS)"}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Inline Frame Sanitizer</span>
                  <span className="val mono" style={{ color: sanitizeGps || sanitizeAlt ? "var(--warn)" : undefined }}>
                    {sanitizeGps
                      ? `ACTIVE (Δlat=${fmtNum(latOffsetDeg, 5)}°)`
                      : sanitizeAlt
                      ? `ACTIVE (Alt -${fmtNum(altBias)}m)`
                      : speedBias > 0.5
                      ? `ACTIVE (Spd -${fmtNum(speedBias)}m/s)`
                      : batteryBias > 0.1
                      ? `ACTIVE (Batt Clamped)`
                      : "STANDBY"}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Quarantined SysIDs</span>
                  <span className="val mono" style={{ color: quarantined.length > 0 ? "var(--crit)" : undefined }}>
                    {quarantined.length > 0 ? `[${quarantined.join(", ")}] (DROPPED)` : "None"}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Target Restore Mode</span>
                  <span className="val mono" style={{ color: targetRestoreMode ? "var(--ok)" : undefined }}>
                    {targetRestoreMode || trustedMode || "AUTO"}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Last Counter Command</span>
                  <span className="val mono">
                    {lastCommand || "None"}
                    {counterFramesSent > 0 && ` (${counterFramesSent} TX)`}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Sanitized Golden Anchor</span>
                  <span className="val mono">
                    {trustedLat != null && trustedLon != null
                      ? `${fmtNum(trustedLat, 5)}, ${fmtNum(trustedLon, 5)}`
                      : "Acquiring..."}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 5. Real-time Tactical Action Timeline */}
      <div className="def-section">
        <div className="def-section-title">
          {activeMode === "passive"
            ? "IDS AUDIT LOG TIMELINE"
            : activeMode === "advisory"
            ? "ADVISORY ALERT TIMELINE"
            : "TACTICAL MITIGATION ACTION TIMELINE"}
        </div>
        <div className="action-timeline">
          {actions.length === 0 ? (
            <div className="empty-timeline">
              {activeMode === "passive"
                ? "Passive IDS stream active — no intrusions logged yet."
                : activeMode === "advisory"
                ? "Advisory monitor armed — no HUD alerts dispatched yet."
                : "No counter-actions required yet — monitoring flight stream."}
            </div>
          ) : (
            actions.slice().reverse().map((act, i) => (
              <div key={i} className="timeline-item">
                <span className="tl-time mono">{act.t.toFixed(1)}s</span>
                <span className={`tl-tag tl-tag-${act.tag.toLowerCase()}`}>{act.tag}</span>
                <span className="tl-detail">{act.detail}</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* 6. Summary Banner */}
      <div className="def-summary-bar">
        <span className="summary-lbl">
          {activeMode === "passive" ? "IDS STATUS:" : activeMode === "advisory" ? "ADV STATUS:" : "IPS STATUS:"}
        </span>
        <span className="summary-txt">
          {mitigation?.summary || (activeMode === "passive" ? "Passive IDS monitoring" : "Autonomous IPS standby")}
        </span>
      </div>

      {/* 7. Tactical Pilot Overrides (Strictly Mode-Gated) */}
      <div className="def-section overrides-section">
        <div className="def-section-title">
          {activeMode === "passive"
            ? "OPERATOR IDS CONTROLS"
            : activeMode === "advisory"
            ? "PILOT ADVISORY CONTROLS"
            : "PILOT TACTICAL OVERRIDES"}
        </div>

        {activeMode === "passive" ? (
          <div className="passive-overrides-container">
            <div className="passive-notice-card">
              <span className="notice-badge">PASSIVE IDS ONLY</span>
              <span className="notice-text">
                Counter-command actuation and packet quarantine are locked off (0 bytes transmitted). To engage closed-loop resistance or manual tactical hold, select <b>ACTIVE IPS</b> in the Operational Posture Selector above.
              </span>
            </div>
            {isMitigating && (
              <button
                type="button"
                className="override-btn info-btn"
                onClick={() => handleOverride("ack_takeover")}
                disabled={busy}
                style={{ marginTop: "8px" }}
              >
                RESET IDS ALERT LATCH
              </button>
            )}
          </div>
        ) : activeMode === "advisory" ? (
          <div className="override-actions">
            <button
              type="button"
              className="override-btn warn-btn"
              onClick={() => handleOverride("ack_takeover")}
              disabled={busy}
            >
              ACKNOWLEDGE HUD ADVISORY (CLEAR ALERT)
            </button>
          </div>
        ) : (
          <div className="override-actions">
            <button
              type="button"
              className="override-btn warn-btn"
              onClick={() => handleOverride("safe_hold")}
              disabled={busy}
            >
              ENGAGE SAFE HOLD (ALT_HOLD)
            </button>
            <button
              type="button"
              className="override-btn info-btn"
              onClick={() => handleOverride("reset_quarantine")}
              disabled={busy}
            >
              FLUSH QUARANTINED SYSIDS
            </button>
            <button
              type="button"
              className="override-btn success-btn"
              onClick={() => handleOverride("ack_takeover")}
              disabled={busy}
            >
              ACKNOWLEDGE TAKEOVER (RESET NOMINAL)
            </button>
          </div>
        )}

        {overrideMsg && <div className="override-feedback">{overrideMsg}</div>}
      </div>
    </section>
  );
}
