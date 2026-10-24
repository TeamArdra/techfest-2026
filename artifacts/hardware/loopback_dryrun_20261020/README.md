# loopback_dryrun_20261020: bench captures 005/007 through the live serial runner over loopback TCP

**Environment:** `REPLAY` of `BENCH` data. The input is the physical Pixhawk 6X captures 005 (HEARTBEAT only) and 007
(six messages), taken from the telemetry radio on COM7 (see `docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.7). They are replayed at
original pace into the **live**, receive-only runner `scripts/hardware/run_serial_ids.py`. The runner's
`LiveMavlinkSource(origin="start")` starts the monitoring clock when the port opens, before the first frame. Transport is
`socket://127.0.0.1:<port>` with `--allow-url`.
**Not hardware:** no baud rate, USB driver, UART, radio or DTR/RTS line is exercised.
**Claim class:** none. These are benign streams. The run checks the runner's start-up and coverage behaviour and its
receive-only property. It is **not** detection evidence: no attack was made.
Run by aegis-px4-mavlink on 2026-10-20 at 13:40:29 +0530 (08:10:29 UTC). Persisted here by aegis-validation as
byte-identical copies of the session-scratch outputs (checked with `cmp`).

## Provenance
- Code: `HEAD` `83f07c1782c7a19dcc2ec3e5f2261ee848cf5402` **plus the uncommitted working tree** (telemetry-closure sprint).
  - sha256 of `git diff HEAD -- src configs` (Git Bash): `708192a04883a7ad83a5918c81bf752c34e96744f2ff35ab498af81795aa0ad6`.
    It was measured at 13:38:56 and 13:42:15 +0530, before and after the runs started at 13:40:29, with the same value
    both times.
  - The last edits under `src/` were at 13:34:18 (`detectors/protocol.py`) and 13:34:04 (`detectors/physics.py`). The last
    edit under `scripts/` was at 13:32:20 (`scripts/hardware/run_serial_ids.py`). All are before the runs; nothing under
    `src/`, `configs/` or `scripts/` was modified after 13:34:18.
  - sha256 of `git diff HEAD -- src configs scripts`: `cd109aaebc5a2080bd2a9d45e14ca39f0e1d90aabfc21faef8c01899191671f6`
    (measured after the runs).
  - `scripts/hardware/run_serial_ids.py` sha256 `68d063e2ff298ccb830bce9fae8b605251cbfdeec4d87123651b19b2456e4551`
    (uncommitted: docstring change, and `telemetry_coverage` printed on the console).
  - `scripts/hardware/virtual_serial_replay.py` sha256 `652a004fc18e6dd9901d56b04e819544c8dc83713ec6e65e52046cc4f68ea772`
    (tracked, unmodified).
- Config: Stage-1 default `configs/` (`summary.json` `config_dir`). ML off. No firmware verifier.
- Python 3.13.15, pymavlink 2.4.50, numpy 2.5.3, scikit-learn 1.9.1; Windows 11.
- Inputs (local, git-ignored), sha256 re-verified 2026-10-20:
  - `data/hardware/raw/telemetry_radio_005.tlog`: `0f4e2887e4da853b0ffb9aadc56488a0080930d453e245c720a8b063256784b5`
    (60 frames; 59.0 s from first to last frame).
  - `data/hardware/raw/telemetry_radio_007.tlog`: `0a70133114f439aad8e7a45b7e86eb76127cda4efa0674891e8c228025d0e17a`
    (1,620 frames; 59.767 s).
- The five runs ran **concurrently**: all five servers accepted within 0.02 s of 08:10:29 UTC, on ports 47311–47315.
  The host was also running the full test suite and the Stage-1 benchmark at the time. Every run reports `late_ticks` 0
  and `late_frames` 0.

## Regenerate
Driver: `tools/run_one.sh NAME MODE TLOG PORT DELAY SECONDS`, copied verbatim. Its `DR=` line hard-codes the original
session-scratch directory; point it at a fresh directory before use. The `delayed` and `silent` modes call
`delayed_replay.py` from that same `DR` directory (`tools/delayed_replay.py` here).

**The `run_one.sh` invocation lines themselves were not logged.** The parameters below come from the recorded outputs:
- MODE: `repo` runs have a `LISTENING …` / `DONE …` `server.out`; `delayed` and `silent` runs have a `server.json`.
- PORT: `summary.json` `port`.
- DELAY: `server.json` `delay_s`.
- SECONDS: `summary.json` `wall_s`.
- TLOG: identified by frame count (`server.out` `sent=`, `server.json` `frames_total`).

| run | MODE | TLOG | PORT | DELAY | SECONDS |
|---|---|---|---|---|---|
| `007` | `repo` | `data/hardware/raw/telemetry_radio_007.tlog` | 47311 | (unused) | 60 |
| `007_delayed` | `delayed` | `data/hardware/raw/telemetry_radio_007.tlog` | 47312 | 1.5 | 60 |
| `005` | `repo` | `data/hardware/raw/telemetry_radio_005.tlog` | 47313 | (unused) | 60 |
| `005_delayed` | `delayed` | `data/hardware/raw/telemetry_radio_005.tlog` | 47314 | 1.5 | 60 |
| `none` | `silent` | `-` | 47315 | -1 (fixed by the mode) | 10 |

`run_one.sh` executes the following (verbatim from the script; `<DR>` = its output directory):
```
# server, MODE=repo
.venv/Scripts/python.exe scripts/hardware/virtual_serial_replay.py <TLOG> --port <PORT> --speed 1.0 --ready-file <DR>/<NAME>.ready
# server, MODE=delayed
.venv/Scripts/python.exe -I <DR>/delayed_replay.py <TLOG> <PORT> <DELAY> <DR>/<NAME>.ready <DR>/<NAME>.server.json 2
# server, MODE=silent
.venv/Scripts/python.exe -I <DR>/delayed_replay.py - <PORT> -1 <DR>/<NAME>.ready <DR>/<NAME>.server.json <SECONDS+10>
# runner, once the ready file exists
.venv/Scripts/python.exe scripts/hardware/run_serial_ids.py --port socket://127.0.0.1:<PORT> --allow-url --baud 115200 --out-dir <DR>/<NAME> --seconds <SECONDS> --no-reconnect
.venv/Scripts/aegis.exe verify-log <DR>/<NAME>/events.sqlite
```
In this directory, `<NAME>.console.txt` becomes `<run>/console.txt`, `<NAME>.verify.txt` becomes `<run>/verify_log.txt`,
and `<NAME>.server.out` / `<NAME>.server.json` become `<run>/server.out` / `<run>/server.json`. Each console and verify
file ends with the `EXIT=` line that `run_one.sh` appends. The `<NAME>.ready` files hold only the port number and were
not copied. `tools/analyse.py` is the read-only summariser aegis-px4-mavlink used; it is not needed to regenerate.

## Results
Taken from the copied `summary.json` / `alerts.jsonl` files.
- **Every run:** exit 0; `passive_check.passed` true (`bytes_sent` 0, `write_errors` 0); `aegis verify-log` chain OK.
  The chains were re-verified on the copies on 2026-10-20.
- **No run** has a "never received" alert at t ≤ 3.0 s.
- In 007, 007_delayed, 005 and 005_delayed there is no "never received" alert at all.

| run | stream into the runner | frames received | decisions | threat decisions | alerts | alert t (s) | `telemetry_coverage` heartbeat / position / raw; decisions without position | chain |
|---|---|---|---|---|---|---|---|---|
| `007` | capture 007, `virtual_serial_replay.py`, first frame at connect | 1,620 | 301 | 296 | 15 `DOS`, all "GNSS fix never acquired" | 1.0 + 4k (1.0 … 57.0) | T / T / T; 0 | OK, 15 |
| `007_delayed` | capture 007, `tools/delayed_replay.py`, first frame 1.5 s after connect | 1,580 | 301 | 289 | 15 `DOS`, all "GNSS fix never acquired" | 2.4, 6.4, …, 30.4, then 34.6, …, 58.6 | T / T / T; 8 | OK, 15 |
| `005` | capture 005 (HEARTBEAT only), `virtual_serial_replay.py` | 60 | 301 | 0 | 0 | — | T / F / F; 301 | OK, 0 |
| `005_delayed` | capture 005, `tools/delayed_replay.py`, first frame 1.5 s after connect | 59 | 301 | 0 | 0 | — | T / F / F; 301 | OK, 0 |
| `none` | silent listener: accepts the connection, sends nothing, 10 s | 0 | 51 | 35 | 2 `DOS`, "heartbeat stale (never received …)", each also carrying the coverage line | 3.2, 7.2 | F / F / F; 51 | OK, 2 |

Notes on the table:
- **Delayed runs:** the delayed server's last frame falls after the runner's 60 s stop.
  - 007_delayed: the server sent 1,581 of 1,620 frames, then got a connection reset when the runner closed; the runner
    read 1,580.
  - 005_delayed: the server sent 60 frames; the runner read 59.
- **The 301 decisions** are the 5 Hz decisions over t = 0 … 60 s of monitoring. The in-process `replay_p1p2_007` (300
  decisions, 295 threats) starts its clock at the first frame instead.
- **No GPS receiver:** in capture 007 the board reported no GPS receiver (see `../replay_p1p2_007/README.md`,
  2026-10-20 correction). The GNSS alerts therefore say nothing about GNSS reception.

## Tool-side disconnect in run `005`
- In run 005, `transport.disconnects` is 1 and `last_error` is `SerialException('read failed: socket disconnected')`.
- Cause: `virtual_serial_replay.py` sleeps 0.5 s after its last frame and then closes the socket. Capture 005's last
  frame is 59.0 s after the first, so the close comes about 59.5 s after connect, before the runner's 60 s deadline.
- This is the replay tool ending. It is not a link fault or a code fault. Exit is 0, there is no alert, and decisions
  continue to 301 because `origin="start"` keeps ticking without frames.
- In 007 the close would come at about 60.27 s (59.767 + 0.5), after the deadline, so that run has `disconnects` 0.
- In a loopback dry run, keep `--seconds` below the capture span plus 0.5 s.

## `events.sqlite` (git-ignored by `*.sqlite`; kept locally for completeness)
| run | sha256 |
|---|---|
| `007` | `94fb11073029f761d4bb338bbe07d839b9bf87449d313e9915e400a51ffdd84a` |
| `007_delayed` | `e1f5ed9f7b1b064e4ce3d06ea5640d324cd59310fb23dda7e274b031e3bc29b4` |
| `005` | `206fbe9bdf9046b9832a7de5faf1ade1343ee301d95db36921948a0055c60930` |
| `005_delayed` | `37eca8c9494a4808eeea38f79eb25911f4fc6f00b6df17d4b2bb9350c6b21657` |
| `none` | `eb6f782d3bd28f46009fd3ab7a76448ebc99fe14a0cd96dc0ca9f2bbf2b9a14f` |

## Other files (sha256)
| file | sha256 |
|---|---|
| `007/summary.json` | `0dd73e5181215af12d5092c834a008000f7bbdf7db55076475a82c8bc1c1a5b4` |
| `007/alerts.jsonl` | `6277bae1896947e263516424e3cf1014f6f2f41759ccdb81451efa96618844d2` |
| `007/health.jsonl` | `b0d436bce8212d54b07aa73273af5e97c60f908c7d8ea9e0f8474fbcc2cb0c59` |
| `007/console.txt` | `824f08adb9d7d44e2b377cec4fabdf313cfe3e8d1a0037910f3f567ec1f9bd9b` |
| `007/verify_log.txt` | `58000b6b69ac9f386e8ce1c4945b65e7e687ff4b3e01233b2e30a7940b27deb6` |
| `007/server.out` | `39ef2c265f77cf5d675ff0a611696dffcd54f88f592ee093f75e3b5d53a52e7c` |
| `007_delayed/summary.json` | `ade140e15fee8e6a7732adedf36de1e36294db7986f9d660e36b429c308ed8e9` |
| `007_delayed/alerts.jsonl` | `12560e86af40d2445bd5c670658d80c1a331278ccc5b00bfc5d3df8b1a35362a` |
| `007_delayed/health.jsonl` | `874ef77089d0d2ebb0cea47bd8226150e874f6a438290b95f1ff1cd89ffc953d` |
| `007_delayed/console.txt` | `725458fce11f9996103b7c6ae056141e7d5ed69c65987f1b4b402735f0309f31` |
| `007_delayed/verify_log.txt` | `58000b6b69ac9f386e8ce1c4945b65e7e687ff4b3e01233b2e30a7940b27deb6` |
| `007_delayed/server.json` | `77b6fa1dbc1c97833b6faaf34ba2cf092c53b176e49213df11e62396dcd2f0f9` |
| `007_delayed/server.out` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty) |
| `005/summary.json` | `65168d5302757d69ae2ff58924e186252c56543277d7fca0339c0bb1243187c3` |
| `005/alerts.jsonl` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty: no alerts) |
| `005/health.jsonl` | `5c682d5ab43a1d2913626d7e1e1f6b39a0a99e6500a141dacff5a3d230e46cd6` |
| `005/console.txt` | `c7404222481e1eb014f2bfbda238a2a7bb46e947887849fab351460931ec3d3d` |
| `005/verify_log.txt` | `7a713d229d77016ec2ab9997ba4f643b7877a22a493e5e05cfaa15302ef12f56` |
| `005/server.out` | `23f2ebb89a02763885e5cc894db52bec76d5187decac2c053305d93fd509cbf8` |
| `005_delayed/summary.json` | `0ef770bb747971aa9f426c043b78fd934816a413860327e34bdee3c5569b231b` |
| `005_delayed/alerts.jsonl` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty: no alerts) |
| `005_delayed/health.jsonl` | `91e830bd79fe0217d8f0ce97c52c049b8629bfca03738f3ebb2b30fbf16f9532` |
| `005_delayed/console.txt` | `c7404222481e1eb014f2bfbda238a2a7bb46e947887849fab351460931ec3d3d` |
| `005_delayed/verify_log.txt` | `7a713d229d77016ec2ab9997ba4f643b7877a22a493e5e05cfaa15302ef12f56` |
| `005_delayed/server.json` | `1e972b142315bc81c15fa1ac481da54f82790bf70292b31354d515cc1c86abf3` |
| `005_delayed/server.out` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty) |
| `none/summary.json` | `b8120e2c80f523d115fe1507c23274f3909757a271796f784b755792725ce916` |
| `none/alerts.jsonl` | `2930094cf0ae8536f94d63aa5a38094eafeaecc654e467895e61dc4ac7f71ad3` |
| `none/health.jsonl` | `defc34508b63a6de6c945faea7f9396d799700c8b62b27cdb7d7548d26f2ff48` |
| `none/console.txt` | `9deb2b58a17cee24f3e074fb5ffe23396a211dc13bb15e1a5a88093c8dec1948` |
| `none/verify_log.txt` | `4dbebb8e84eb2c0703523becd7659f6696faee1de0128204426f8f9387100244` |
| `none/server.json` | `0960c7e2923cf82f877a6f4cd1c4ba11983ad6f536be3943b4bb870e82c42f68` |
| `none/server.out` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty) |
| `tools/run_one.sh` | `6d263b801f6b93c319d5815ca6bcae087f6844ff75ea81c3ffaf6bb2d530b1bf` |
| `tools/delayed_replay.py` | `5aed637e36ab46b19ac5084168013656ccbaeb7078c16c5390a416bbdef106a3` |
| `tools/analyse.py` | `d558b8d8c7389cc907578119d62a419ea08ca8a07a2f9da79c8f553c2a72a9fa` |

## Limitations
- **Loopback TCP only.** This says nothing about the physical serial path (baud, CP210x driver, radio, DTR/RTS side
  effects). It does **not** replace the supervised physical run in `docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.9.
- **n = 1 per variant,** benign streams only, so there is no false-alarm rate.
- **Recorded inputs.** The captures were recorded on 2026-10-13/14. Today's board state is not represented.
- **Scratch tool.** The delayed and silent variants use `tools/delayed_replay.py`, a scratch tool, not a repo tool.
- **Loaded host.** Five concurrent runs ran on a loaded host. `late_ticks` is 0 everywhere, but tick-boundary timing may
  differ from an unloaded or physical run.
- **Not run:** ML on, `require_global_position: true`, and any attack.
