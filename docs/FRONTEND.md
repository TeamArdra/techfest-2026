# AegisFlight — Frontend

A single-page **Vite + React + TypeScript** dashboard (`frontend/`), no UI or
charting libraries — inline SVG + CSS, so it builds small and self-contained
(~155 kB JS gzip 50 kB). Builds to `frontend/dist`, which the FastAPI backend
serves at `/`.

## Structure
```
frontend/src/
├── main.tsx                 React root
├── App.tsx                  layout: 3-column grid + metrics bar + footer
├── index.css                dark "security-ops" theme (CSS variables)
├── types/index.ts           TS mirrors of backend payloads
├── services/api.ts          REST client + wsUrl()
├── hooks/useLiveData.ts     WebSocket stream + REST polling → state
└── components/
    ├── Header.tsx           title, SIMULATION badge, connection, sim clock, ML
    ├── panels.tsx           ThreatPanel, DetectorPanel, EvidencePanel, TelemetryPanel
    ├── MapPanel.tsx         SVG position track + threat-score sparkline
    ├── AlertsPanel.tsx      event history list
    └── ControlPanel.tsx     start/stop/reset + attack-injection buttons
```

## Data flow
`useLiveData` opens `ws://<host>/ws/telemetry` (auto-reconnect) and updates:
- `telemetry` and `attackActive` every tick (10 Hz),
- `threat`, a `scoreHistory` sparkline buffer, and a `track` buffer on decision
  ticks (5 Hz).
It also polls `/api/events` and `/api/metrics` every 2 s for the event history
and the bottom metrics bar. `ControlPanel` POSTs to `/api/simulation/*`.

## What's backend-derived vs UI-only
- **Backend-derived (live):** all telemetry values, threat state/score/severity,
  attack class, confidence, evidence, detector scores, latency, integrity status,
  alerts, metrics.
- **UI-only:** the self-scaling of the position track (converts lat/lon to a
  local metric frame for display), colour/severity styling, sparkline buffering.
No mock/demo data — every number comes from the backend.

## Components (props → data)
| Component | Props | Source |
|---|---|---|
| `Header` | connected, simTime, mlAvailable | WS + metrics |
| `ThreatPanel` | threat | WS `threat` |
| `DetectorPanel` | threat.detector_scores | WS |
| `EvidencePanel` | threat.evidence | WS |
| `TelemetryPanel` | telemetry | WS |
| `MapPanel` | track, scoreHistory, threat | WS-derived buffers |
| `AlertsPanel` | alerts | `/api/events` |
| `ControlPanel` | activeAttack | posts to `/api/simulation/attack` |

## Dev vs build
- **Build:** `npm run build` (`tsc --noEmit && vite build`) → `dist/`.
- **Dev:** `npm run dev` on :5173; `vite.config.ts` proxies `/api`, `/health`,
  `/ws` to the backend on :8000 (no CORS friction).
- `wsUrl()` derives ws/wss from `location`, so the same code works in dev
  (proxied) and when served by FastAPI (same-origin).

## Simulation labelling
The header shows a persistent **● Simulation** badge and the footer states all
data/attacks are local simulations — simulated attacks must never look like a
real UAV under attack.

## Running against a live link / the desktop app

Start the backend on the CLI default port with the source you want (see `aegis serve --help`), e.g. `aegis serve --port 8000 ...`, then:

- **Browser dev server** (`npm run dev`, :5173) proxies `/api`, `/health`, `/ws` to `VITE_BACKEND_PORT` (default 8000).
- **Backend URL** resolution, first match wins: `window.__AEGIS_BACKEND__`, localStorage `aegis_backend_url`, build-time `VITE_BACKEND_URL`, inside the Tauri desktop app `http://127.0.0.1:8000`, otherwise same-origin. Set or clear it from the header **Settings** button (http/https URLs only; the page reloads to reconnect). The WebSocket scheme follows the URL scheme.
- **Inline IPS bridge**: enter the bridge status URL (e.g. `http://127.0.0.1:<port>`; localStorage `aegis_bridge_url`) in Settings. The dashboard polls `<url>/status` every 2 s and shows an "Inline IPS bridge" panel (hidden when unset, "unreachable" on error).
- For REPLAY/SITL/BENCH sources the flight track shows only the as-received positions (no protected/ghost overlay), ignores invalid fixes (null, NaN, out of range, 0/0, receiver reports no fix) and shows "NO POSITION FIX" until a valid one arrives. The origin is the first valid fix of the run. A "Checks" panel shows mission cross-track, cross-end matches/mismatches and receiver EKF/satellite health.
