import type { Threat } from "../types";
import { THREAT_THRESHOLD } from "../lib/constants";

interface Props {
  track: Array<[number, number]>;
  scoreHistory: Array<{ t: number; score: number }>;
  threat: Threat | null;
  note: string; // what the positions are (simulated / replayed / bench, not flight) — lib/source.ts
}

// Self-scaling 2D position plot (lat/lon -> metres from the first fix). This is
// an operational local-frame view, not a geographic map — no tiles, no real GPS
// basemap. The threat timeline underneath shares the same alert colour so the
// track and the current assessment read as one instrument.
export function MapPanel({ track, scoreHistory, threat, note }: Props) {
  const W = 680, H = 440, pad = 34;
  const active = !!threat?.threat;
  const color = active ? `var(--high)` : `var(--accent)`;

  let path = "";
  let head: [number, number] | null = null;
  let start: [number, number] | null = null;
  let spanM = 0;
  if (track.length > 1) {
    const lats = track.map((p) => p[0]);
    const lons = track.map((p) => p[1]);
    const lat0 = (Math.min(...lats) + Math.max(...lats)) / 2;
    const mPerLat = 111_320;
    const mPerLon = 111_320 * Math.cos((lat0 * Math.PI) / 180);
    const xs = track.map((p) => (p[1] - lons[0]) * mPerLon);
    const ys = track.map((p) => (p[0] - lats[0]) * mPerLat);
    const minX = Math.min(...xs), maxX = Math.max(...xs);
    const minY = Math.min(...ys), maxY = Math.max(...ys);
    const span = Math.max(maxX - minX, maxY - minY, 20);
    spanM = span;
    const sx = (x: number) => pad + ((x - minX) / span) * (W - 2 * pad);
    const sy = (y: number) => H - pad - ((y - minY) / span) * (H - 2 * pad);
    path = track.map((_, i) => `${i ? "L" : "M"}${sx(xs[i]).toFixed(1)},${sy(ys[i]).toFixed(1)}`).join(" ");
    head = [sx(xs[xs.length - 1]), sy(ys[ys.length - 1])];
    start = [sx(xs[0]), sy(ys[0])];
  }

  // scale bar: a clean ~1/4-frame reference in metres
  const scaleM = niceScale(spanM / 4);
  const scalePx = spanM > 0 ? (scaleM / spanM) * (W - 2 * pad) : 0;

  // -------- timeline (threat score over time) --------
  const SW = 680, SH = 78;
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
          {/* subtle grid */}
          {[0.2, 0.4, 0.6, 0.8].map((f) => (
            <line key={"v" + f} x1={pad + f * (W - 2 * pad)} y1={pad} x2={pad + f * (W - 2 * pad)} y2={H - pad} stroke="#141c25" strokeWidth="1" />
          ))}
          {[0.2, 0.4, 0.6, 0.8].map((f) => (
            <line key={"h" + f} x1={pad} y1={pad + f * (H - 2 * pad)} x2={W - pad} y2={pad + f * (H - 2 * pad)} stroke="#141c25" strokeWidth="1" />
          ))}
          {/* plot frame */}
          <rect x={pad} y={pad} width={W - 2 * pad} height={H - 2 * pad} fill="none" stroke="#1e2833" strokeWidth="1" />

          {/* trajectory */}
          {path && <path d={path} fill="none" stroke={color} strokeWidth="2" opacity="0.92" strokeLinejoin="round" />}
          {/* home / first fix */}
          {start && <rect x={start[0] - 3} y={start[1] - 3} width="6" height="6" fill="none" stroke="var(--muted)" strokeWidth="1.5" />}
          {/* current position */}
          {head && (
            <g>
              <circle cx={head[0]} cy={head[1]} r="11" fill="none" stroke={color} strokeWidth="1" opacity="0.35">
                {active && <animate attributeName="r" values="9;15;9" dur="2s" repeatCount="indefinite" />}
              </circle>
              <circle cx={head[0]} cy={head[1]} r="4.5" fill={color} stroke="#0a0f15" strokeWidth="1.5" />
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
        </svg>
        <span className="map-corner tl">Local Frame</span>
        <span className="map-corner tr" style={{ color: active ? "var(--high)" : undefined }}>
          {active ? "● Track under threat" : "● Nominal"}
        </span>
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
          {area && <path d={area} fill={color} opacity="0.10" />}
          <line x1="0" y1={thrY} x2={SW} y2={thrY} stroke="var(--muted)" strokeDasharray="5 5" strokeWidth="1" opacity="0.6" />
          {line && <path d={line} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />}
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
