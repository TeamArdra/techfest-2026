import type { DefenseMode, Environment, MitigationInfo, Telemetry, Threat } from "../types";
import { extentOf, fitExtent, niceScale, projectTrack, toLocal, type LatLon } from "../lib/geo";
import { THREAT_THRESHOLD } from "../lib/constants";

interface Props {
  track: Array<[number, number]>;
  trackThreat?: boolean[];
  rawTrack?: Array<[number, number]>;
  scoreHistory: Array<{ t: number; score: number }>;
  altHistory?: Array<{ t: number; rawAlt: number; effAlt: number; diverging: boolean }>;
  threat: Threat | null;
  telemetry?: Telemetry | null;
  sanitizedTelemetry?: Telemetry | null;
  defenseMode?: DefenseMode;
  mitigation?: MitigationInfo | null;
  attackActive?: string | null;
  topology?: string;
  origin?: LatLon | null; // first valid fix of the run (local-frame origin)
  environment?: Environment | null;
  note: string; // what the positions are (simulated / replayed / bench, not flight) — lib/source.ts
}

function fmtNum(val: number | null | undefined, digits = 1, fallback = "0.0"): string {
  if (typeof val !== "number" || isNaN(val)) return fallback;
  return val.toFixed(digits);
}

// Self-scaling 2D position plot (lat/lon -> metres from the first fix). This is
// an operational local-frame view, not a geographic map — no tiles, no real GPS
// basemap. When ACTIVE IPS is engaged, renders both the solid green IPS-Restored
// Track and the dashed red Rejected/Blocked Ghost Track.
export function MapPanel({
  track,
  trackThreat,
  rawTrack,
  scoreHistory,
  altHistory,
  threat,
  telemetry,
  sanitizedTelemetry,
  defenseMode,
  mitigation,
  attackActive,
  topology,
  origin,
  environment,
  note,
}: Props) {
  const isSim = environment == null || environment === "SIM";
  const W = 680, H = 410, pad = 34;
  const active = !!threat?.threat;
  // protected / ghost / IPS-restored overlays exist only for the simulator
  const isIpsActive = isSim && defenseMode === "active-ips";
  const isSanitizingGps = isIpsActive && !!(mitigation?.sanitize_gps || mitigation?.ekf_switched);
  const isIpsProtecting =
    isIpsActive &&
    (active || (mitigation != null && mitigation.state !== "NOMINAL"));

  const effTele = isIpsActive && sanitizedTelemetry ? sanitizedTelemetry : telemetry;

  const atk = String(attackActive || "").toLowerCase();

  // The red dashed "ghost" track means: the RAW reported position that the IPS rejected.
  // That is only meaningful for attacks that actually corrupt the position channel. DoS
  // floods/blackouts, telemetry manipulation (alt/speed/battery/attitude), sequence/rate
  // anomalies, command injection and firmware tamper do NOT forge GPS, so no ghost is drawn
  // for them -- even if a GPS-sanitizer flag is still latched from an earlier GPS attack.
  // Live (non-sim) sources have no injected-attack name, so fall back to the fused class.
  const isPositionAttack = atk
    ? atk.startsWith("gps_spoofing") || atk.includes("gnss_jamming") || atk.includes("rogue_sysid")
    : threat?.attack_type === "GPS_SPOOFING";

  const trackColor = isIpsProtecting
    ? `var(--ok)`
    : active
      ? `var(--high)`
      : `var(--accent)`;
  const timelineColor = active ? `var(--high)` : `var(--accent)`;

  const getGhostLabel = (): string => {
    if (atk.includes("replay_freeze")) return "FROZEN GPS FIX (BYPASSED)";
    if (atk.includes("sudden_offset")) return "SPOOFED GPS JUMP (REJECTED)";
    if (atk.includes("gradual_drift")) return "SPOOFED GPS DRIFT (REJECTED)";
    if (atk.includes("gnss_jamming")) return "JAMMED GNSS FIX (IGNORED)";
    if (atk.includes("rogue_sysid")) return "ROGUE SYSID 42 POSITION (DROPPED)";
    return "SPOOFED GPS (REJECTED)";
  };

  const topNote =
    topology === "a" ? " [Top-A Sidecar]" : topology === "a+b" ? " [Top-A+B Hybrid]" : " [Top-B Inline]";

  const getProtectedLabel = (): string => {
    if (atk.includes("mode_flip")) return `IPS AUTO 12 m/s (LAND BLOCKED)${topNote}`;
    if (atk.includes("gcs_replay")) return `IPS MISSION (REPLAY BLOCKED)${topNote}`;
    if (atk.includes("rogue_command")) return `IPS SURVEY TRACK (CMD BLOCKED)${topNote}`;
    if (atk.includes("arm_disarm")) return `IPS FLIGHT SUSTAINED (DISARM VETOED)${topNote}`;
    if (atk.includes("rogue_sysid")) return `IPS CLEAN TRACK (SYSID QUARANTINED)${topNote}`;
    if (atk.includes("gnss_jamming")) return `IPS DEAD-RECKONING (GNSS LOST)${topNote}`;
    if (atk.startsWith("gps_spoofing")) return `IPS RESTORED (DEAD-RECKONING)${topNote}`;
    if (atk.startsWith("dos")) return `IPS LINK GUARDED (RATE-LIMITED)${topNote}`;
    if (atk.startsWith("telemetry_manipulation")) return `IPS TELEMETRY SANITIZED${topNote}`;
    if (atk.startsWith("mavlink_anomaly")) return `IPS LINK GUARDED${topNote}`;
    if (atk.startsWith("firmware")) return `IPS INTEGRITY ALERT${topNote}`;
    if (threat?.attack_type === "GPS_SPOOFING") return `IPS RESTORED (DEAD-RECKONING)${topNote}`;
    return `IPS PROTECTED${topNote}`;
  };

  let path = "";
  let threatPath = "";
  let rawPath = "";
  let head: [number, number] | null = null;
  let rawHead: [number, number] | null = null;
  let start: [number, number] | null = null;
  let spanM = 0;
  let hasDivergence = false;

  if (origin && track.length > 0) {
    const pts = projectTrack(track, origin);
    const xs = pts.map((p) => p[0]);
    const ys = pts.map((p) => p[1]);
    let ext = extentOf(pts);

    let rawPts: Array<[number, number]> = [];
    if (isSim && rawTrack && rawTrack.length > 1) {
      rawPts = projectTrack(rawTrack, origin);
      // rawTrack is scoped to the current attack episode (see useLiveData), so compare the
      // two LATEST fixes rather than index-aligning against the full effective history.
      const r = rawPts[rawPts.length - 1];
      const sepM = Math.hypot(r[0] - xs[xs.length - 1], r[1] - ys[ys.length - 1]);
      hasDivergence = isIpsActive && isPositionAttack && (isSanitizingGps || sepM > 2.5);
      if (hasDivergence) {
        // include the ghost, but clamp to +-250 m of the start so the real track never shrinks to a speck
        const clamp = (v: number, c: number) => Math.max(c - 250, Math.min(c + 250, v));
        const all = pts.concat(rawPts.map((q): [number, number] => [clamp(q[0], xs[0]), clamp(q[1], ys[0])]));
        ext = extentOf(all);
      }
    }

    const fit = fitExtent(ext, W, H, pad);
    spanM = Math.min(W - 2 * pad, H - 2 * pad) / fit.pxPerM;
    const sx = fit.sx, sy = fit.sy;
    path = pts.map((_, i) => `${i ? "L" : "M"}${sx(xs[i]).toFixed(1)},${sy(ys[i]).toFixed(1)}`).join(" ");
    if (trackThreat && trackThreat.length === track.length) {
      const segs: string[] = [];
      for (let i = 1; i < track.length; i++) {
        if (trackThreat[i]) {
          const move = trackThreat[i - 1] ? "L" : `M${sx(xs[i - 1]).toFixed(1)},${sy(ys[i - 1]).toFixed(1)} L`;
          segs.push(`${move}${sx(xs[i]).toFixed(1)},${sy(ys[i]).toFixed(1)}`);
        }
      }
      threatPath = segs.join(" ");
    }
    head = [sx(xs[xs.length - 1]), sy(ys[ys.length - 1])];
    const o = toLocal(origin, origin[0], origin[1]);
    start = [sx(o[0]), sy(o[1])];

    if (hasDivergence && rawPts.length > 1) {
      rawPath = rawPts.map((q, i) => `${i ? "L" : "M"}${sx(q[0]).toFixed(1)},${sy(q[1]).toFixed(1)}`).join(" ");
      const lq = rawPts[rawPts.length - 1];
      rawHead = [
        Math.max(pad + 6, Math.min(W - pad - 6, sx(lq[0]))),
        Math.max(pad + 6, Math.min(H - pad - 6, sy(lq[1]))),
      ];
    }
  }
  const noFix = !origin || track.length === 0;

  // scale bar: a clean ~1/4-frame reference in metres
  const scaleM = niceScale(spanM / 4);
  const scalePx = spanM > 0 ? (scaleM / spanM) * (W - 2 * pad) : 0;

  // -------- vertical altitude profile (0-100m) --------
  const AH = 44;
  // SIM keeps the fixed 0-100 m strip; real data auto-scales (rel_alt in metres, floor 10 m)
  const altMax = isSim ? 100 : Math.max(10, Math.ceil(Math.max(0, ...(altHistory ?? []).map((h) => Math.max(h.rawAlt, h.effAlt))) / 10) * 10);
  let rawAltPath = "";
  let effAltPath = "";
  let hasAltDivergence = false;
  if (altHistory && altHistory.length > 1) {
    const nA = altHistory.length;
    const ax = (i: number) => (i / (nA - 1)) * W;
    const ay = (alt: number) => AH - Math.max(0, Math.min(altMax, alt)) * (AH / altMax);
    rawAltPath = "M" + altHistory.map((h, i) => `${ax(i).toFixed(1)},${ay(h.rawAlt).toFixed(1)}`).join(" L");
    effAltPath = "M" + altHistory.map((h, i) => `${ax(i).toFixed(1)},${ay(h.effAlt).toFixed(1)}`).join(" L");
    hasAltDivergence = altHistory.some((h) => h.diverging);
  }

  // -------- timeline (threat score over time) --------
  const SW = 680, SH = 66;
  const thrY = SH - THREAT_THRESHOLD * SH;
  let line = "", area = "";
  let last: { t: number; score: number } | null = null;
  if (scoreHistory.length > 1) {
    const nH = scoreHistory.length;
    const px = (i: number) => (i / (nH - 1)) * SW;
    const py = (s: number) => SH - Math.max(0, Math.min(1, s)) * SH;
    const pts = scoreHistory.map((h, i) => `${px(i).toFixed(1)},${py(h.score).toFixed(1)}`);
    line = "M" + pts.join(" L");
    area = `M0,${SH} L` + pts.join(" L") + ` L${SW},${SH} Z`;
    last = scoreHistory[scoreHistory.length - 1];
  }

  return (
    <div className="panel">
      <header>
        <span className="panel-title">Flight Track</span>
        <span className="panel-note">local frame · {track.length} fixes · {isSim ? "" : `${environment} as received · `}{note}</span>
      </header>

      <div className="map-frame">
        <svg className="map" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
          <defs>
            <clipPath id="map-plot-clip">
              <rect x={pad} y={pad} width={W - 2 * pad} height={H - 2 * pad} />
            </clipPath>
          </defs>
          {/* subtle grid */}
          {[0.2, 0.4, 0.6, 0.8].map((f) => (
            <line key={"v" + f} x1={pad + f * (W - 2 * pad)} y1={pad} x2={pad + f * (W - 2 * pad)} y2={H - pad} stroke="#141c25" strokeWidth="1" />
          ))}
          {[0.2, 0.4, 0.6, 0.8].map((f) => (
            <line key={"h" + f} x1={pad} y1={pad + f * (H - 2 * pad)} x2={W - pad} y2={pad + f * (H - 2 * pad)} stroke="#141c25" strokeWidth="1" />
          ))}
          {/* plot frame */}
          <rect x={pad} y={pad} width={W - 2 * pad} height={H - 2 * pad} fill="none" stroke="#1e2833" strokeWidth="1" />

          <g clipPath="url(#map-plot-clip)">
            {/* rejected spoofed GPS ghost track */}
            {hasDivergence && rawPath && (
              <path
                d={rawPath}
                fill="none"
                stroke="var(--crit)"
                strokeWidth="1.6"
                strokeDasharray="5 4"
                opacity="0.65"
                strokeLinejoin="round"
              />
            )}
            {hasDivergence && rawHead && (
              <g opacity="0.85">
                <circle cx={rawHead[0]} cy={rawHead[1]} r="5" fill="none" stroke="var(--crit)" strokeWidth="1.5" strokeDasharray="2 2" />
                <text
                  x={rawHead[0] > W - 160 ? rawHead[0] - 8 : rawHead[0] + 8}
                  y={rawHead[1] - 6}
                  textAnchor={rawHead[0] > W - 160 ? "end" : "start"}
                  fill="var(--crit)"
                  fontSize="9.5"
                  fontFamily="var(--mono)"
                  fontWeight="700"
                >
                  {getGhostLabel()}
                </text>
              </g>
            )}

            {/* effective / IPS-protected vehicle trajectory: nominal history in accent,
                only the segment flown under threat recoloured on top */}
            {path && (
              <path
                d={path}
                fill="none"
                stroke={threatPath ? "var(--accent)" : trackColor}
                strokeWidth="2.4"
                opacity="0.95"
                strokeLinejoin="round"
              />
            )}
            {threatPath && (
              <path d={threatPath} fill="none" stroke={trackColor} strokeWidth="2.6" opacity="0.98" strokeLinejoin="round" />
            )}
            {/* home / first fix */}
            {start && <rect x={start[0] - 3} y={start[1] - 3} width="6" height="6" fill="none" stroke="var(--muted)" strokeWidth="1.5" />}
            {/* current vehicle position */}
            {head && (
              <g>
                <circle cx={head[0]} cy={head[1]} r="11" fill="none" stroke={trackColor} strokeWidth="1.2" opacity="0.45">
                  {(active || isIpsProtecting) && <animate attributeName="r" values="9;15;9" dur="2s" repeatCount="indefinite" />}
                </circle>
                <circle cx={head[0]} cy={head[1]} r="4.5" fill={trackColor} stroke="#0a0f15" strokeWidth="1.5" />
                {isIpsProtecting && (
                  <text
                    x={head[0] > W - 160 ? head[0] - 10 : head[0] + 10}
                    y={head[1] + 4}
                    textAnchor={head[0] > W - 160 ? "end" : "start"}
                    fill="var(--ok)"
                    fontSize="9.5"
                    fontFamily="var(--mono)"
                    fontWeight="700"
                  >
                    {getProtectedLabel()}
                  </text>
                )}

                {/* Live telemetry pill next to vehicle head */}
                {effTele && (
                  <g transform={`translate(${head[0] > W - 180 ? head[0] - 170 : head[0] + 14}, ${head[1] > H - 50 ? head[1] - 22 : head[1] + 10})`}>
                    <rect
                      x="0"
                      y="0"
                      width="156"
                      height="18"
                      rx="4"
                      fill="rgba(10,15,21,0.88)"
                      stroke={isIpsProtecting ? "var(--ok)" : active ? "var(--high)" : "var(--accent)"}
                      strokeWidth="1"
                    />
                    <text
                      x="6"
                      y="12.5"
                      fill="#e5e7eb"
                      fontSize="9.5"
                      fontFamily="var(--mono)"
                      fontWeight="700"
                    >
                      {`${effTele.flight_mode || "AUTO"} · ${fmtNum(effTele.groundspeed, 1)}m/s · ${fmtNum(effTele.rel_alt, 0)}m`}
                    </text>
                  </g>
                )}
              </g>
            )}
          </g>

          {noFix && (
            <g data-testid="no-fix">
              <text x={W / 2} y={H / 2 - 4} textAnchor="middle" fill="var(--muted)" fontSize="16" fontFamily="var(--mono)" fontWeight="700">NO POSITION FIX</text>
              <text x={W / 2} y={H / 2 + 16} textAnchor="middle" fill="var(--faint)" fontSize="10.5" fontFamily="var(--mono)">waiting for a valid GPS position (null, 0/0 and out-of-range fixes are ignored)</text>
            </g>
          )}

          {/* scale bar */}
          {scalePx > 0 && (
            <g>
              <line x1={pad} y1={H - 16} x2={pad + scalePx} y2={H - 16} stroke="var(--faint)" strokeWidth="1.5" />
              <line x1={pad} y1={H - 19} x2={pad} y2={H - 13} stroke="var(--faint)" strokeWidth="1.5" />
              <line x1={pad + scalePx} y1={H - 19} x2={pad + scalePx} y2={H - 13} stroke="var(--faint)" strokeWidth="1.5" />
              <text x={pad + scalePx + 6} y={H - 12} fill="var(--faint)" fontSize="10" fontFamily="var(--mono)">{scaleM} m</text>
            </g>
          )}

          {/* Legend when IPS is rejecting spoofed GPS */}
          {hasDivergence && (
            <g transform={`translate(${W - pad - 230}, ${H - 26})`}>
              <line x1="0" y1="6" x2="16" y2="6" stroke="var(--ok)" strokeWidth="2.4" />
              <text x="21" y="9" fill="var(--ok)" fontSize="9.5" fontFamily="var(--mono)">IPS Protected Track</text>
              <line x1="126" y1="6" x2="142" y2="6" stroke="var(--crit)" strokeWidth="1.6" strokeDasharray="4 3" />
              <text x="147" y="9" fill="var(--crit)" fontSize="9.5" fontFamily="var(--mono)">Rejected GPS</text>
            </g>
          )}
        </svg>
        <span className="map-corner tl">Local Frame · N↑{isSim ? "" : ` · ${environment}`}</span>
        <span
          className="map-corner tr"
          style={{
            color: isIpsProtecting
              ? "var(--ok)"
              : active
                ? "var(--high)"
                : undefined,
            fontWeight: isIpsProtecting || active ? 700 : undefined,
          }}
        >
          {isIpsProtecting
            ? `🛡️ IPS Protected · ${topology === "a" ? "Topology A (Sidecar)" : "Topology B (Inline)"}`
            : !isSim
              ? `● ${environment} · track as received`
              : active
                ? "● Track under threat (Unprotected)"
                : "● Nominal"}
        </span>
      </div>

      {/* 44px SVG Vertical Altitude Profile Strip (0-100m) */}
      <div className="timeline" style={{ marginBottom: 6 }}>
        <div className="tl-head" style={{ marginBottom: 2 }}>
          <span className="lbl" style={{ fontSize: 11 }}>
            Vertical Altitude Profile (0–{altMax} m{isSim ? "" : ", rel. home"})
          </span>
          <span className="now" style={{ fontSize: 10 }}>
            {isSim ? `eff ${fmtNum(effTele?.rel_alt, 1)}m · raw ${fmtNum(telemetry?.rel_alt, 1)}m` : `rel_alt ${fmtNum(telemetry?.rel_alt, 1, "—")} m`}
          </span>
        </div>
        <svg className="spark" viewBox={`0 0 ${SW} ${AH}`} style={{ height: AH }} preserveAspectRatio="none">
          {/* 60m survey baseline */}
          {isSim && <line x1="0" y1={AH - (60 / 100) * AH} x2={SW} y2={AH - (60 / 100) * AH} stroke="#273240" strokeDasharray="3 3" strokeWidth="1" />}
          {isSim && <text x={SW - 32} y={AH - (60 / 100) * AH - 2} fill="#6b7280" fontSize="8.5" fontFamily="var(--mono)">60m</text>}
          {/* raw alt line */}
          {rawAltPath && (
            <path
              d={rawAltPath}
              fill="none"
              stroke={hasAltDivergence ? "var(--crit)" : "#4b5563"}
              strokeWidth={hasAltDivergence ? "1.8" : "1.2"}
              strokeDasharray={hasAltDivergence ? "4 3" : undefined}
              vectorEffect="non-scaling-stroke"
            />
          )}
          {/* eff alt line */}
          {effAltPath && (
            <path
              d={effAltPath}
              fill="none"
              stroke={isIpsProtecting ? "var(--ok)" : "var(--accent)"}
              strokeWidth="2"
              vectorEffect="non-scaling-stroke"
            />
          )}
        </svg>
      </div>

      {/* threat timeline */}
      <div className="timeline">
        <div className="tl-head">
          <span className="lbl">Threat score · timeline</span>
          <span className="now">
            now {last ? last.score.toFixed(2) : "—"} · thr {THREAT_THRESHOLD.toFixed(2)}
          </span>
        </div>
        <svg className="spark" viewBox={`0 0 ${SW} ${SH}`} preserveAspectRatio="none">
          {area && <path d={area} fill={timelineColor} opacity="0.10" />}
          <line x1="0" y1={thrY} x2={SW} y2={thrY} stroke="var(--muted)" strokeDasharray="5 5" strokeWidth="1" opacity="0.6" />
          {line && <path d={line} fill="none" stroke={timelineColor} strokeWidth="2" vectorEffect="non-scaling-stroke" />}
        </svg>
      </div>
    </div>
  );
}

