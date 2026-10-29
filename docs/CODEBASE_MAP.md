# AegisFlight — Codebase Map

A mental model of the repository and its dependency directions. Import rule of
thumb: **arrows point "downhill" toward `core/`**; nothing in `core/` imports
anything else in the package.

```
aegisflight/
├── core/            # shared vocabulary — types, enums, geo math (NO deps)
├── hal/             # Hardware Abstraction Layer & inline bridge (Stage 2)
├── mitigation/      # autonomous prevention engine & golden state twin (Stage 2)
├── config.py        # typed config: YAML-over-defaults deep-merge
├── simulator/       # deterministic UAV flight -> clean FlightState
├── mavlink/         # genuine MAVLink v2 encode/decode, signing & GCS notifier
├── attacks/         # 20 safe attack scenarios (value/stream/integrity)
├── integrity/       # SHA-256 firmware manifest verifier
├── sources/         # SimulatedTelemetrySource: sim->encode->attack->decode
├── features/        # online FeatureExtractor -> FeatureFrame
├── detectors/       # protocol, physics, anomaly(ML), integrity
├── fusion/          # FusionEngine: DetectorResults -> ThreatAssessment
├── logging/         # SQLite EventStore + SHA-256 hash chain
├── metrics/         # scoring (confusion/PRF/FPR/latency) + resource sampler
├── benchmark/       # session runner, benign dataset, harness, plots
├── pipeline.py      # IDSPipeline: wires extractor->detectors->fusion
├── backend/         # FastAPI app + LiveEngine (REST + WebSocket)
└── cli/             # `aegis` CLI (simulate/benchmark/train/serve/verify-log)

frontend/            # React 18 + TS dashboard + Tauri 2.0 Rust desktop GCS
rust/aegis_fastpath/ # zero-allocation Rust MAVLink frame sanitizer
scripts/             # verify_stage2.py, train_models.py, benchmark.py, run_demo.py
configs/             # simulation.yaml, detector.yaml, attacks.yaml
tests/               # unit / integration / e2e tests (`pytest -q` prints the count)
backend/tests/       # FastAPI API tests
artifacts/           # benchmark results.json/csv/summary.md + figures (committed)
models/              # isoforest.joblib (regenerable; gitignored)
docs/                # comprehensive documentation set
```

## Dependency direction (who imports whom)

| Module | Imports | Imported by |
|---|---|---|
| `core/` | (stdlib only) | everything |
| `hal/` | core, mavlink, mitigation | backend, cli |
| `mitigation/` | core, mavlink | backend, hal, pipeline |
| `config.py` | `pyyaml` | simulator, sources, pipeline, backend, benchmark, cli |
| `simulator/` | core | sources, benchmark |
| `mavlink/` | core, pymavlink | attacks, sources, mitigation, hal |
| `integrity/` | core | attacks, detectors, pipeline |
| `attacks/` | core, mavlink, integrity | sources, backend, benchmark |
| `sources/` | config, core, simulator, mavlink, attacks | pipeline, benchmark, backend |
| `features/` | core, mavlink | detectors, pipeline, benchmark |
| `detectors/` | core, features, mavlink, integrity | pipeline |
| `fusion/` | core | pipeline |
| `logging/` | core | cli, backend, benchmark(e2e) |
| `metrics/` | core, psutil | benchmark |
| `pipeline.py` | config, detectors, features, fusion, integrity, sources | backend, benchmark |
| `benchmark/` | everything above | cli, scripts |
| `backend/` | config, pipeline, sources, attacks, logging, mitigation, hal | cli |
| `cli/` | (lazy) most modules | `aegis` entry point |

## Architectural rules (keep it from becoming spaghetti)

1. **`core/` stays dependency-free.** Types/enums/geo never import sibling
   subsystems. If a type is shared, it belongs in `core/`.
2. **Detectors read only a `FeatureFrame`** (+ the integrity verifier for D4).
   They never touch the simulator, attacks, or ground-truth labels.
3. **Ground truth (`FlightState`, attack `label`) is benchmark-only.** It flows
   through `sources` tagged onto `TelemetryTick` but the pipeline/detectors read
   only `messages`, never `truth_state`/`label`.
4. **The attack↔IDS boundary is the wire** (`MessageEnvelope`) and the
   **filesystem** (firmware dir). Attacks never call detectors and vice-versa.
5. **One place wires the stack:** `pipeline.py`. Backend and benchmark both use
   `IDSPipeline` rather than re-wiring detectors themselves.
