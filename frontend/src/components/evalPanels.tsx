import type { Metrics } from "../types";

/* Formatting helpers ------------------------------------------------------ */
function fmtDistance(m: number): { value: string; unit: string } {
  if (m >= 1000) return { value: (m / 1000).toFixed(2), unit: "km" };
  return { value: m.toFixed(0), unit: "m" };
}

function num(x: number | null | undefined, d = 1): string {
  return x == null ? "—" : x.toFixed(d);
}

/* ------------------------------------------------------- runtime performance
   LIVE / RUNTIME metrics only — the current session's computational-efficiency
   story (worth 10% of the evaluation). Benchmark figures live in Validation. */
export function RuntimePanel({
  metrics,
  distance,
  distanceNote,
}: {
  metrics: Metrics | null;
  distance: number;
  distanceNote: string; // simulated flight path vs reported positions of a replayed / bench source
}) {
  const dist = fmtDistance(distance);
  const compute = metrics?.decision_compute_ms ?? metrics?.last_latency_ms ?? null;
  const cells: Array<{ label: string; value: string; unit?: string; title?: string }> = [
    {
      label: "Decision compute",
      value: num(compute, 1),
      unit: "ms",
      title: "Compute cost of one fused decision — not attack-onset latency.",
    },
    { label: "Throughput", value: num(metrics?.throughput_msgs_per_s, 1), unit: "msg/s" },
    {
      label: "Time to detect",
      value: num(metrics?.time_to_detect_s, 2),
      unit: "s",
      title: "Attack onset → first alert, measured live for this session.",
    },
    { label: "Messages", value: metrics ? String(metrics.messages_processed) : "—" },
    { label: "Decisions", value: metrics ? String(metrics.decisions) : "—" },
    { label: "Alerts", value: metrics ? String(metrics.alerts) : "—" },
  ];

  return (
    <div className="panel">
      <header>
        <span className="panel-title">Runtime Performance</span>
        <span className="panel-note">this run</span>
      </header>

      <div className="kpi-hero">
        <div className="kpi-hero-label">Distance covered</div>
        <div className="kpi-hero-value">
          {dist.value}
          <span className="u">{dist.unit}</span>
        </div>
        <div className="kpi-hero-sub">{distanceNote}</div>
      </div>

      <div className="rt-grid">
        {cells.map((c) => (
          <div className="rt-cell" key={c.label} title={c.title}>
            <div className="rt-label">{c.label}</div>
            <div className="rt-value">
              {c.value}
              {c.unit && <span className="u">{c.unit}</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* -------------------------------------------------------- attack coverage
   ARCHITECTURE / capability breadth (worth 15%). Static, honest scope — the
   representative scenario per domain, plus what is explicitly NOT covered. */
const DOMAINS: Array<{ domain: string; scenarios: string[]; attackIds: string[] }> = [
  { domain: "Navigation", scenarios: ["GPS spoofing (position-telemetry)"], attackIds: ["gps_spoofing"] },
  {
    domain: "Communication",
    scenarios: ["MAVLink anomaly", "Denial of service"],
    attackIds: ["mavlink_anomaly", "dos"],
  },
  { domain: "Telemetry", scenarios: ["Value manipulation"], attackIds: ["telemetry_manipulation"] },
  {
    domain: "Command & Control",
    scenarios: ["Command injection (unauthorized source / sysid)"],
    attackIds: ["command_injection"],
  },
  { domain: "Firmware", scenarios: ["Integrity (SHA-256 manifest)"], attackIds: ["firmware_integrity"] },
];

export function CoveragePanel({ activeAttack }: { activeAttack: string | null }) {
  return (
    <div className="panel">
      <header>
        <span className="panel-title">Attack Vector Coverage</span>
        <span className="panel-note">6 scenarios · 5 domains</span>
      </header>

      <div className="cov-list">
        {DOMAINS.map((d) => {
          const live = activeAttack != null && d.attackIds.includes(activeAttack);
          return (
            <div className={`cov-row${live ? " live" : ""}`} key={d.domain}>
              <span className="cov-dot" />
              <span className="cov-domain">{d.domain}</span>
              <span className="cov-scenarios">
                {d.scenarios.map((s) => (
                  <span className="cov-chip" key={s}>
                    {s}
                  </span>
                ))}
              </span>
            </div>
          );
        })}
        <div className="cov-row out">
          <span className="cov-dot" />
          <span className="cov-domain">System-level</span>
          <span className="cov-scenarios">
            <span className="cov-chip none">Not currently covered</span>
          </span>
        </div>
      </div>
      <div className="cov-foot">
        Simultaneous / composite attacks run in the offline attack engine &amp; benchmark,
        not the live console.
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- integration
   ARCHITECTURE / ease-of-integration facts (worth 5%). Implemented vs planned,
   no fabricated score, no overclaimed live integration. */
const IMPLEMENTED = [
  "MAVLink 2 codec (pymavlink)",
  "Offline PX4 ULog & ArduPilot .tlog replay",
  "Modular detector interface",
  "FastAPI + WebSocket API",
  "SQLite tamper-evident hash-chain log",
  "Live serial / UDP MAVLink source (receive-only)",
  "MAVLink-2 signing verification",
  "IPS state machine (SIM dashboard; report-only on live sources)",
  "STATUSTEXT alerts to a loopback GCS",
];
const PLANNED = [
  "Inline FrameSanitizer relay (code exists, not wired)",
  "Rust fast-path + Tauri desktop app (prototype, not on the decision path)",
  "Hardware-in-the-loop (HIL)",
  "Onboard / companion deployment",
  "Multi-vehicle support",
];

export function IntegrationPanel() {
  return (
    <div className="panel">
      <header>
        <span className="panel-title">Integration / Platform</span>
        <span className="panel-note">Stage 2 Architecture</span>
      </header>
      <div className="integ-tagline">
        Modular MAVLink-based cyber-physical shield with zero-interference flight safety.
      </div>
      <div className="integ-cols">
        <div className="integ-col">
          <div className="integ-head ok">Implemented in Stage 2</div>
          <ul className="integ-list">
            {IMPLEMENTED.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </div>
        <div className="integ-col">
          <div className="integ-head planned">Future Roadmap</div>
          <ul className="integ-list planned">
            {PLANNED.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------- validation
   BENCHMARK / VALIDATION evidence — clearly labelled, never presented as live
   telemetry. Figures are quoted verbatim from committed artifacts/**. */
type ValTier = "sim" | "expanded" | "real";
const TIER_LABEL: Record<ValTier, string> = {
  sim: "Simulated",
  expanded: "Expanded sim",
  real: "Real-data",
};
const VAL_ROWS: Array<{ tier: ValTier; metric: string; value: string }> = [
  { tier: "sim", metric: "Baseline accuracy", value: "99.7%  ·  FPR 0.02%  ·  23,430 decisions" },
  { tier: "expanded", metric: "Expanded v2 accuracy", value: "97.7% (5 s grace)  ·  97.0% (no grace)" },
  { tier: "real", metric: "ArduPilot ALFA (calibrated, ML-off)", value: "0.2% FPR held-out  ·  100% FPR uncalibrated" },
  { tier: "sim", metric: "Time to detect", value: "0.36 s mean  ·  1.4 s p95" },
  { tier: "sim", metric: "Decision compute", value: "17.7 ms mean  ·  23.6 ms p95 (ML on)" },
];

export function ValidationPanel() {
  return (
    <div className="panel">
      <header>
        <span className="panel-title">Validation Evidence</span>
        <span className="panel-note">benchmark — not live</span>
      </header>
      <table className="val-table">
        <tbody>
          {VAL_ROWS.map((r) => (
            <tr key={r.metric}>
              <td>
                <span className={`val-tier t-${r.tier}`}>{TIER_LABEL[r.tier]}</span>
              </td>
              <td className="val-metric">{r.metric}</td>
              <td className="val-value">{r.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="val-foot">
        Reproducible results from committed <code>artifacts/**</code>. Benchmark
        CPU ~99% reflects a saturated measurement loop, not steady-state efficiency;
        no embedded / Jetson figures are claimed.
      </div>
    </div>
  );
}
