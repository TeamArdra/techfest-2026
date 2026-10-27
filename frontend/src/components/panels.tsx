import type { DefenseMode, MitigationInfo, Telemetry, Threat } from "../types";
import { THREAT_THRESHOLD } from "../lib/constants";
import { classifyEvidence, SOURCE_LABEL, type EvidenceSource } from "../lib/evidence";

const DETECTOR_LABELS: Record<string, string> = {
  protocol_rule: "Protocol / rule",
  physics_consistency: "Physics consistency",
  ml_anomaly: "ML anomaly",
  firmware_integrity: "Firmware integrity",
};

/* ------------------------------------------------------------------ threat */
export function ThreatPanel({ threat }: { threat: Threat | null }) {
  const active = !!threat?.threat;
  const sev = active ? threat!.severity : "NORMAL";
  const score = threat?.threat_score ?? 0;
  const fwInvalid = threat?.integrity_status === "INVALID";

  return (
    <div className={`panel threat lvl-${sev}`}>
      <header>
        <span className="panel-title">Threat State</span>
        <span className="panel-note">current assessment</span>
      </header>

      <div className={`threat-state sev-${sev}`}>{sev}</div>
      {active ? (
        <div className="threat-sub">{threat!.attack_type.replace(/_/g, " ")}</div>
      ) : (
        <div className="threat-sub quiet">No active threat — nominal flight</div>
      )}

      <div className="gauge">
        <div className={`fill bg-${sev}`} style={{ width: `${Math.min(100, score * 100)}%` }} />
        <div className="thresh" style={{ left: `${THREAT_THRESHOLD * 100}%` }} />
      </div>

      <div className="readouts">
        <div className="readout">
          <div className="r-label">Threat score</div>
          <div className="r-value">{score.toFixed(3)}</div>
        </div>
        <div
          className="readout"
          title="Fusion heuristic (weighted detector agreement), not a calibrated probability."
        >
          <div className="r-label">Confidence</div>
          <div className="r-value">
            {(threat?.confidence ?? 0).toFixed(2)}
            <span className="u">heuristic</span>
          </div>
        </div>
        <div
          className="readout"
          title="Compute cost of one fused decision — NOT attack-onset detection latency."
        >
          <div className="r-label">Decision compute</div>
          <div className="r-value">
            {(threat?.latency_ms ?? 0).toFixed(1)}
            <span className="u">ms</span>
          </div>
        </div>
        <div className="readout">
          <div className="r-label">Firmware</div>
          <div className={`r-value ${fwInvalid ? "sev-CRITICAL" : ""}`}>
            {threat?.integrity_status ?? "VALID"}
          </div>
        </div>
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- detectors */
export function DetectorPanel({ threat }: { threat: Threat | null }) {
  const scores = threat?.detector_scores ?? {};
  const keys = Object.keys(DETECTOR_LABELS);
  const max = Math.max(0, ...keys.map((k) => scores[k] ?? 0));

  return (
    <div className="panel">
      <header>
        <span className="panel-title">Detector Contributions</span>
        <span className="panel-note">4 evidence sources</span>
      </header>
      <div className="det-list">
        {keys.map((key) => {
          const v = scores[key] ?? 0;
          const lead = v > 0.1 && v >= max; // the detector driving this assessment
          return (
            <div className={`det${lead ? " lead" : ""}`} key={key}>
              <span className="d-name">{DETECTOR_LABELS[key]}</span>
              <span className="d-score">{v.toFixed(2)}</span>
              <span className="d-track">
                <i style={{ width: `${Math.min(100, v * 100)}%` }} />
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- evidence */
export function EvidencePanel({ threat }: { threat: Threat | null }) {
  const ev = threat?.threat ? threat.evidence : [];

  // Group evidence lines by their (derived) detector source for a forensic read.
  const order: EvidenceSource[] = ["physics", "protocol", "ml", "firmware", "signal"];
  const grouped = new Map<EvidenceSource, string[]>();
  for (const line of ev) {
    const src = classifyEvidence(line);
    const bucket = grouped.get(src);
    if (bucket) bucket.push(line);
    else grouped.set(src, [line]);
  }

  return (
    <div className="panel">
      <header>
        <span className="panel-title">Why this alert?</span>
        <span className="panel-note">detector evidence</span>
      </header>
      {ev.length === 0 ? (
        <div className="empty">
          No anomalies flagged. All four detectors agree telemetry is consistent
          with normal flight.
        </div>
      ) : (
        order
          .filter((s) => grouped.has(s))
          .map((src) => (
            <div className="ev-group" key={src}>
              <div className="ev-src">
                <span className={`tag src-${src}`}>{SOURCE_LABEL[src]}</span>
                <span className="rule" />
              </div>
              <ul className="ev-lines">
                {grouped.get(src)!.map((line, i) => (
                  <li className={`li-${src}`} key={i}>{line}</li>
                ))}
              </ul>
            </div>
          ))
      )}
    </div>
  );
}

/* --------------------------------------------------------------- telemetry */
function n(x: number | null | undefined, d = 1): string {
  return x == null ? "—" : x.toFixed(d);
}

export function TelemetryPanel({
  tele,
  sanitized,
  note,
  defenseMode,
  mitigation,
}: {
  tele: Telemetry | null;
  sanitized?: Telemetry | null;
  note: string;
  defenseMode?: DefenseMode;
  mitigation?: MitigationInfo | null;
}) {
  const isIps = defenseMode === "active-ips";
  const lowBatt = tele?.battery_remaining != null && tele.battery_remaining < 20;

  // In ACTIVE_IPS, check if sanitized telemetry restored perturbed values
  const altDiff = isIps && sanitized?.alt_msl != null && tele?.alt_msl != null && Math.abs(sanitized.alt_msl - tele.alt_msl) > 1.5;
  const speedDiff = isIps && sanitized?.groundspeed != null && tele?.groundspeed != null && Math.abs(sanitized.groundspeed - tele.groundspeed) > 1.5;
  const battDiff = isIps && sanitized?.battery_voltage != null && tele?.battery_voltage != null && Math.abs(sanitized.battery_voltage - tele.battery_voltage) > 0.5;
  const modeDiff = isIps && sanitized?.flight_mode && tele?.flight_mode && sanitized.flight_mode !== tele.flight_mode;

  // In PASSIVE / ADVISORY, warn if known perturbations exist without claiming sanitization
  const altWarn = !isIps && Boolean(mitigation?.outputs?.alt_bias_m && Math.abs(mitigation.outputs.alt_bias_m) > 1.5);
  const speedWarn = !isIps && Boolean(mitigation?.outputs?.speed_bias_ms && Math.abs(mitigation.outputs.speed_bias_ms) > 1.5);
  const battWarn = !isIps && Boolean(mitigation?.outputs?.battery_bias_v && Math.abs(mitigation.outputs.battery_bias_v) > 0.5);
  const modeWarn = !isIps && Boolean(mitigation?.params?.target_restore_mode && tele?.flight_mode && mitigation.params.target_restore_mode !== tele.flight_mode);

  const cells: Array<{ label: string; value: string; unit?: string; warn?: boolean; restored?: string; anomalyNotice?: string }> = [
    {
      label: "Altitude",
      value: n(tele?.rel_alt, 1),
      unit: "m",
      warn: altDiff || altWarn,
      restored: altDiff ? `${n(sanitized?.rel_alt ?? sanitized?.alt_msl, 1)} m` : undefined,
      anomalyNotice: altWarn ? "⚠️ Anomaly (Unsanitized)" : undefined,
    },
    {
      label: "Ground speed",
      value: n(tele?.groundspeed, 1),
      unit: "m/s",
      warn: speedDiff || speedWarn,
      restored: speedDiff ? `${n(sanitized?.groundspeed, 1)} m/s` : undefined,
      anomalyNotice: speedWarn ? "⚠️ Anomaly (Unsanitized)" : undefined,
    },
    { label: "Heading", value: tele?.heading == null ? "—" : n(tele.heading, 0).padStart(3, "0"), unit: "°" },
    { label: "Battery", value: n(tele?.battery_remaining, 0), unit: "%", warn: lowBatt },
    {
      label: "Voltage",
      value: n(tele?.battery_voltage, 2),
      unit: "V",
      warn: battDiff || battWarn,
      restored: battDiff ? `${n(sanitized?.battery_voltage, 2)} V` : undefined,
      anomalyNotice: battWarn ? "⚠️ Anomaly (Unsanitized)" : undefined,
    },
    { label: "GPS sats", value: tele?.satellites != null ? String(tele.satellites) : "—" },
    {
      label: "Flight mode",
      value: tele?.flight_mode ?? "—",
      warn: Boolean(modeDiff || modeWarn),
      restored: modeDiff ? String(sanitized?.flight_mode) : undefined,
      anomalyNotice: modeWarn ? "⚠️ Hijacked (Unsanitized)" : undefined,
    },
    { label: "Armed", value: tele?.armed == null ? "—" : tele.armed ? "YES" : "NO" },
  ];

  return (
    <div className="panel">
      <header>
        <span className="panel-title">Vehicle Telemetry</span>
        <span className="panel-note">{note}</span>
      </header>
      <div className="tele">
        {cells.map((c) => (
          <div className="t-cell" key={c.label}>
            <div className="t-label">{c.label}</div>
            <div className={`t-value${c.warn ? " warn" : ""}`}>
              {c.value}
              {c.unit && <span className="u">{c.unit}</span>}
              {c.restored && (
                <span
                  style={{
                    display: "block",
                    fontSize: "10.5px",
                    color: "var(--ok, #4ade80)",
                    fontWeight: 600,
                    marginTop: "2px",
                  }}
                  title="Autonomous IPS restored value"
                >
                  🛡️ Sanitized: {c.restored}
                </span>
              )}
              {c.anomalyNotice && (
                <span
                  style={{
                    display: "block",
                    fontSize: "10.5px",
                    color: "var(--warn, #facc15)",
                    fontWeight: 600,
                    marginTop: "2px",
                  }}
                  title="Observed telemetry is perturbed by active attack (passive IDS / advisory observation)"
                >
                  {c.anomalyNotice}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
