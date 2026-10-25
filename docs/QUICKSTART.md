# AegisFlight — Quick Start

From a fresh clone to a running dashboard. Also see `docs/installation.md`.

## Prerequisites
- **Python ≥ 3.11** (developed on 3.13)
- **Node ≥ 18 + npm** (only for the dashboard; the IDS/CLI work without it)
- Git. No GPU required.

## 1. Install (Python)

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```
**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```
This installs runtime deps (numpy, pandas, scipy, scikit-learn, pymavlink,
fastapi, uvicorn, matplotlib, …) and the `aegis` CLI.

## 2. Train the anomaly model (optional but recommended)
```bash
aegis train                 # ~15 s -> models/isoforest.joblib
```
The system runs without it (the ML detector becomes a no-op); training enables
the 4th detector and improves GPS recall/latency.

## 3. Run a session from the CLI
```bash
aegis simulate --attack gps_spoofing      # prints alerts + evidence
aegis simulate --attack dos --db out.sqlite
aegis verify-log out.sqlite               # -> chain: OK
python scripts/run_demo.py                # narrated all-scenarios demo
```

## 4. Benchmark (real metrics + figures)
```bash
aegis benchmark             # -> artifacts/benchmarks/summary.md + artifacts/figures/*.png
```

## 5. Automated Verification & Tests
```bash
python scripts/verify_stage2.py   # runs full 8/8 Stage 2 audit suites in ~40 ms
pytest tests/unit -q             # fast unit subset (hundreds of tests)
pytest                           # full verification suite (650+ tests)
ruff check src tests scripts     # lint (0 errors)
```

## 6. Live GCS Dashboard & Desktop Application
Build the web UI once, then serve via FastAPI (or run the native desktop GCS):
```bash
npm --prefix frontend install
npm --prefix frontend run build

# Start the Stage 2 autonomous defense backend:
aegis serve --defense-mode active-ips   # http://127.0.0.1:8000
```
Open http://127.0.0.1:8000 — the simulation auto-starts with live cyber-physical twin, real-time MAVLink telemetry, altitude profile strip, and autonomous defense HUD.

**Running the Native Tauri Desktop App:**
```bash
cd frontend && cargo tauri dev    # launches native cross-platform Rust GCS
```

**Dev mode (hot-reload web UI):** in two terminals —
```bash
aegis serve --defense-mode active-ips   # backend on :8000
npm --prefix frontend run dev           # UI on :5173 (proxies /api and /ws to :8000)
```

## Expected output
- `aegis simulate --attack gps_spoofing` → `HIGH GPS_SPOOFING` alerts with
  evidence *"position residual > 12 m …"*.
- `aegis benchmark` → accuracy ≈ 0.997, recall ≈ 0.99, FPR ≈ 0.0002.
- Dashboard → live telemetry, threat panel, position track, event history.

## Troubleshooting
See `docs/TROUBLESHOOTING.md`. Common: port 8000 in use → `aegis serve
--port 8137`; model missing → `aegis train`; frontend not served → run the
`npm run build` step.
