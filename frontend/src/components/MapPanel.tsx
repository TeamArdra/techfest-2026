import type { DefenseMode, MitigationInfo, Telemetry, Threat } from "../types";
import { THREAT_THRESHOLD } from "../lib/constants";

interface Props {
  track: Array<[number, number]>;
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
  note,
}: Props) {
  const W = 680, H = 410, pad = 34;
  const active = !!threat?.threat;
  const isIpsActive = defenseMode === "active-ips";
  const isSanitizingGps = isIpsActive && !!(mitigation?.sanitize_gps || mitigation?.ekf_switched);
  const isIpsProtecting =
    isIpsActive &&
    (active || (mitigation != null && mitigation.state !== "NOMINAL"));

  const effTele = isIpsActive && sanitizedTelemetry ? sanitizedTelemetry : telemetry;

  const trackColor = isIpsProtecting
    ? `var(--ok)`
    : active
      ? `var(--high)`
      : `var(--accent)`;
  const timelineColor = active ? `var(--high)` : `var(--accent)`;

  const getGhostLabel = (atk: string | null | undefined): string => {
    const s = String(atk || "").toLowerCase();
    if (s.includes("mode_flip")) return isIpsActive ? "FORCED LAND (BLOCKED)" : "⚠️ HIJACKED LAND";
    if (s.includes("gcs_replay")) return isIpsActive ? "REPLAYED RTL (BLOCKED)" : "⚠️ REPLAYED RTL";
    if (s.includes("rogue_command")) return isIpsActive ? "ROGUE GUIDED (BLOCKED)" : "⚠️ ROGUE GUIDED";
    if (s.includes("arm_disarm")) return isIpsActive ? "DISARM DROP (VETOED)" : "⚠️ DISARM PLUMMET";
    if (s.includes("replay_freeze")) return isIpsActive ? "FROZEN FIX (BYPASSED)" : "⚠️ FROZEN FIX";
    if (s.includes("rogue_sysid")) return isIpsActive ? "ROGUE SYSID 42 (DROPPED)" : "⚠️ ROGUE SYSID 42 OFFSET";
    return isIpsActive ? "SPOOFED GPS (REJECTED)" : "⚠️ ANOMALOUS TRACK";
  };

  const getProtectedLabel = (atk: string | null | undefined): string => {
    const s = String(atk || "").toLowerCase();
    const topNote = topology === "a" ? " [Top-A Detour/Recov]" : " [Top-B Inline]";
    if (s.includes("mode_flip")) return `IPS AUTO 12 m/s (MAINTAINED)${topNote}`;
    if (s.includes("gcs_replay")) return `IPS MISSION (CONTINUED)${topNote}`;
    if (s.includes("rogue_command")) return `IPS SURVEY TRACK${topNote}`;
    if (s.includes("arm_disarm")) return `IPS FLIGHT SUSTAINED${topNote}`;
    if (s.includes("rogue_sysid")) return `IPS CLEAN TRACK${topNote}`;
    return `IPS RESTORED (DR)${topNote}`;
  };

  let path = "";
  let rawPath = "";
  let head: [number, number] | null = null;
  let rawHead: [number, number] | null = null;
  let start: [number, number] | null = null;
  let spanM = 0;
  let hasDivergence = false;

  if (track.length > 1) {
    const lats = track.map((p) => p[0]);
    const lons = track.map((p) => p[1]);
    const lat0 = (Math.min(...lats) + Math.max(...lats)) / 2;
    const mPerLat = 111_320;
    const mPerLon = 111_320 * Math.cos((lat0 * Math.PI) / 180);
    const xs = track.map((p) => (p[1] - lons[0]) * mPerLon);
    const ys = track.map((p) => (p[0] - lats[0]) * mPerLat);

    let minX = Math.min(...xs), maxX = Math.max(...xs);
    let minY = Math.min(...ys), maxY = Math.max(...ys);

    // Compute raw spoofed coordinates in the same local metre frame
    let rawXs: number[] = [];
    let rawYs: number[] = [];
    if (rawTrack && rawTrack.length > 1) {
      rawXs = rawTrack.map((p) => (p[1] - lons[0]) * mPerLon);
      rawYs = rawTrack.map((p) => (p[0] - lats[0]) * mPerLat);
      const lastIdx = Math.min(xs.length - 1, rawXs.length - 1);
      const sepM = Math.hypot(rawXs[rawXs.length - 1] - xs[lastIdx], rawYs[rawYs.length - 1] - ys[lastIdx]);
      hasDivergence = isIpsActive && (isSanitizingGps || sepM > 2.5);

      if (hasDivergence) {
        // Expand viewport modestly (up to +65m margin) so the diverging spoofed ghost track
        // is clearly visible without shrinking the main flight loop into a speck.
        const margin = 65;
        for (let i = 0; i < rawXs.length; i++) {
          minX = Math.min(minX, Math.max(xs[0] - 250, Math.min(minX, rawXs[i]), minX - margin));
          maxX = Math.max(maxX, Math.min(xs[0] + 250, Math.max(maxX, rawXs[i]), maxX + margin));
          minY = Math.min(minY, Math.max(ys[0] - 250, Math.min(minY, rawYs[i]), minY - margin));
          maxY = Math.max(maxY, Math.min(ys[0] + 250, Math.max(maxY, rawYs[i]), maxY + margin));
        }
      }
    }

    const span = Math.max(maxX - minX, maxY - minY, 20);
    spanM = span;
    const sx = (x: number) => pad + ((x - minX) / span) * (W - 2 * pad);
    const sy = (y: number) => H - pad - ((y - minY) / span) * (H - 2 * pad);
    path = track.map((_, i) => `${i ? "L" : "M"}${sx(xs[i]).toFixed(1)},${sy(ys[i]).toFixed(1)}`).join(" ");
    head = [sx(xs[xs.length - 1]), sy(ys[ys.length - 1])];
    start = [sx(xs[0]), sy(ys[0])];

    if (hasDivergence && rawXs.length > 1) {
      rawPath = rawXs.map((_, i) => `${i ? "L" : "M"}${sx(rawXs[i]).toFixed(1)},${sy(rawYs[i]).toFixed(1)}`).join(" ");
      const rx = Math.max(pad + 6, Math.min(W - pad - 6, sx(rawXs[rawXs.length - 1])));
      const ry = Math.max(pad + 6, Math.min(H - pad - 6, sy(rawYs[rawYs.length - 1])));
      rawHead = [rx, ry];
    }
  }

  // scale bar: a clean ~1/4-frame reference in metres
  const scaleM = niceScale(spanM / 4);
  const scalePx = spanM > 0 ? (scaleM / spanM) * (W - 2 * pad) : 0;

  // -------- vertical altitude profile (0-100m) --------
  const AH = 44;
  let rawAltPath = "";
  let effAltPath = "";
  let hasAltDivergence = false;
  if (altHistory && altHistory.length > 1) {
    const nA = altHistory.length;
    const ax = (i: number) => (i / (nA - 1)) * W;
    const ay = (alt: number) => AH - Math.max(0, Math.min(100, alt)) * (AH / 100);
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
        <span className="panel-note">local frame · {track.length} fixes · {note}</span>
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
                  {getGhostLabel(attackActive)}
                </text>
              </g>
            )}

            {/* effective / IPS-protected vehicle trajectory */}
            {path && <path d={path} fill="none" stroke={trackColor} strokeWidth="2.4" opacity="0.95" strokeLinejoin="round" />}
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
                    {getProtectedLabel(attackActive)}
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
              <text x="147" y="9" fill="var(--crit)" fontSize="9.5" fontFamily="var(--mono)">Ghost Track</text>
            </g>
          )}
        </svg>
        <span className="map-corner tl">Local Frame</span>
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
            : active
              ? "● Track under threat (Unprotected)"
              : "● Nominal"}
        </span>
      </div>

      {/* 44px SVG Vertical Altitude Profile Strip (0-100m) */}
      <div className="timeline" style={{ marginBottom: 6 }}>
        <div className="tl-head" style={{ marginBottom: 2 }}>
          <span className="lbl" style={{ fontSize: 11 }}>
            Vertical Altitude Profile (0–100 m)
          </span>
          <span className="now" style={{ fontSize: 10 }}>
            {`eff ${fmtNum(effTele?.rel_alt, 1)}m · raw ${fmtNum(telemetry?.rel_alt, 1)}m`}
          </span>
        </div>
        <svg className="spark" viewBox={`0 0 ${SW} ${AH}`} style={{ height: AH }} preserveAspectRatio="none">
          {/* 60m survey baseline */}
          <line x1="0" y1={AH - (60 / 100) * AH} x2={SW} y2={AH - (60 / 100) * AH} stroke="#273240" strokeDasharray="3 3" strokeWidth="1" />
          <text x={SW - 32} y={AH - (60 / 100) * AH - 2} fill="#6b7280" fontSize="8.5" fontFamily="var(--mono)">60m</text>
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

// round a metre span down to a clean 1/2/5 × 10ⁿ value for the scale bar
function niceScale(x: number): number {
  if (x <= 0) return 0;
  const pow = Math.pow(10, Math.floor(Math.log10(x)));
  const f = x / pow;
  const nice = f >= 5 ? 5 : f >= 2 ? 2 : 1;
  return nice * pow;
}
