# Stage 2 report draft: withdrawn pending evidence

The previous draft (cherry-picked from teammate commit `5740040`, now `5c59cdd` on this branch; the full text is in
that commit) was withdrawn during the 2026-10-27 integration review. Its headline figures have no generated
artifact behind them, or contradict one:
- Raspberry Pi Zero 2W / Pi 4 CPU, RAM, throughput, power and mass figures (nothing has been measured on a
  companion computer; `docs/ONBOARD_DEPLOYMENT.md`);
- "3.2 ms" compute (the artifact says 17.7 ms mean / 23.6 ms p95 with ML on, `artifacts/benchmarks/summary.md`);
- "4.8 h / 82.4 km" benign exposure, "≤ 0.20 false alarms per hour", "708 tests";
- a calibration file that does not exist (the real source is `artifacts/sitl/calibration/summary.md`);
- prevention results (detour, survival, mitigation rate) that were never measured;
- "ready for flight trials", a demonstration video, and fuzzing claims.

Rebuild the report only from `docs/VALIDATION_EVIDENCE.md` and the artifacts it cites, with the environment tag
(`SIM` / `REPLAY` / `SITL` / `BENCH`) and claim class next to every number. The official template is
`docs/Stage 2_Security of Drones, Objective 2_Report Template.pdf`.
