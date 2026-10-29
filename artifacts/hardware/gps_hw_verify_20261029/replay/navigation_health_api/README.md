# navigation_health_api: the dashboard API on the 2026-10-28 capture (REPLAY of BENCH data)

**Environment:** `REPLAY` of `BENCH` data. **Claim class: none.** Receive-only: the server reads a local file; nothing is sent anywhere.
Same bytes as `../../live_capture/` (`data/hardware/raw/gps_hw_verify_20261029.tlog`, sha256
`c2e3459b15706479323da39813329ad1796948548b29f5d9df4ac55144d48e8f`).

```
.venv/Scripts/aegis.exe serve --source replay --tlog data/hardware/raw/gps_hw_verify_20261029.tlog --replay-speed 10 --port 8123 --db <scratch>.sqlite
curl http://127.0.0.1:8123/api/status ; curl http://127.0.0.1:8123/api/events     # after the link state is "ended"
```
Code: `HEAD` `c849012` plus the uncommitted passive GPS-health change (see `../navigation_health_loopback/README.md` for hashes). Run 2026-10-29,
at 10x replay speed (not original pace).

Files (reduced on purpose: the full `/api/status` carries a telemetry snapshot with the vehicle position, so only `environment`, `sim` and `link`
are kept, and a check confirmed no `lat`/`lon` keys):
- `api_status_link.json`: `environment` REPLAY, `sim` false, `link.state` `ended`, `link.frames` 5130, and `link.gps`: `fix_type` 3, 7 satellites,
  `valid_fix` true, `hdop` 7.99, `ekf_flags` 167 (0xa7), `horizontal_solution` **false**, `gps_healthy` **false**, `quality_flags`
  `["ekf_no_horizontal_solution", "gps_sensor_unhealthy"]`.
- `api_events.json`: `count` 0.

Shows: the API states the vehicle's own health beside "valid fix: true" and persists no alert. Does not show: the cause of the wander or of the
unhealthy bit (not established), the rendered header (covered by a unit test of the wording only), or anything about attacks.
Note: the replay source's tick clock stops when the file ends, so the last state is preserved in `ended`. A live source keeps ticking, and there only
the EKF-derived field goes stale after 2 s; `gps_healthy` and the receiver fields persist until replaced.
