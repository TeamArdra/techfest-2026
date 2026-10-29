# Third-party notices

AegisFlight's own code is MIT-licensed (`LICENSE`; the copyright holder "Team Ardra" is taken from `pyproject.toml`
`authors` and must be confirmed by the team). This file lists what AegisFlight depends on or analyses and **how each
licence was determined**. It is not legal advice, and it does not reproduce the licence texts: those ship inside each
installed package (`*.dist-info/licenses`, `node_modules/<pkg>/LICENSE`) and must be kept with any redistributed copy.

**Method.** Python: licence metadata read with `importlib.metadata` from the environment that ran the tests
(CPython 3.13.15, 2026-10-29), walking the declared requirements of the `pyproject.toml` dependencies. npm: the
`license` field of each entry in `frontend/package-lock.json` / `node_modules`. Metadata is what the package author
declared; **no licence text was independently audited**, and a package's bundled sub-components (e.g. compiled
libraries inside wheels) may carry additional notices. Rows marked *unverified* were not installed or not readable here.

## 1. Python runtime dependencies (`pyproject.toml` `dependencies`)

| Package | Version checked | Declared licence | Notes |
|---|---|---|---|
| numpy | 2.5.3 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | wheel bundles other components |
| pandas | 3.0.6 | BSD-3-Clause | |
| scipy | 1.18.1 | BSD (classifier) | |
| scikit-learn | 1.9.1 | BSD-3-Clause | |
| joblib | 1.6.0 | BSD-3-Clause | model persistence; the trained model is **not** shipped in Git (see §5) |
| **pymavlink** | 2.4.50 | **LGPL-3.0** (LGPLv3 classifier) | imported as a library, not modified or vendored. Redistributing a bundle that includes it must keep its licence and allow replacement |
| psutil | 7.2.2 | BSD-3-Clause | |
| PyYAML | 6.0.3 | MIT | |
| pydantic / pydantic-core | 2.13.5 / 2.46.5 | MIT | |
| fastapi | 0.142.2 | MIT | |
| uvicorn (`standard` extra) | 0.54.0 | BSD-3-Clause | extra pulls httptools (MIT), watchfiles (MIT), python-dotenv (BSD-3-Clause), colorama (BSD), uvloop (*unverified*: not installed on Windows) |
| websockets | 17.2 | BSD-3-Clause | |
| matplotlib | 3.11.2 | PSF-based (matplotlib licence) | pulls contourpy (BSD-3-Clause), cycler (BSD), fonttools (MIT), kiwisolver (BSD), pillow (MIT-CMU), pyparsing (MIT), python-dateutil (BSD / Apache-2.0) |

Transitive packages seen in the same environment: starlette (BSD-3-Clause), anyio (MIT), h11 (MIT), click (BSD-3-Clause),
idna (BSD-3-Clause), annotated-types / annotated-doc (MIT), typing-extensions (PSF-2.0), typing-inspection (MIT),
threadpoolctl (BSD-3-Clause), cloudpickle (BSD-3-Clause), six (MIT), packaging (Apache-2.0 OR BSD-2-Clause),
narwhals (MIT), tzdata (Apache-2.0), opentelemetry-api (Apache-2.0), lxml (BSD-3-Clause), fastcrc (MIT; pulled in by pymavlink).

Optional extras: **pyserial** 3.5 (BSD; `serial` / `dev` extras; used for the receive-only serial source);
**pyulog** (`external` extra, PX4 ULog adapter): *unverified*, not installed in the checked environment.
Dev-only (not shipped): pytest, pytest-asyncio, httpx, ruff, mypy: *unverified*, not read for this file.

## 2. Frontend (`frontend/package.json`, `package-lock.json`)

Production dependencies in the lock file: react 18.3.1, react-dom 18.3.1, scheduler 0.23.2, loose-envify 1.4.0,
js-tokens 4.0.0: all declare **MIT**. The 115 lock entries in total declare: MIT 106, ISC 5 (electron-to-chromium,
lru-cache, picocolors, semver, yallist), Apache-2.0 2 (typescript, baseline-browser-mapping), BSD-3-Clause 1
(source-map-js), **CC-BY-4.0** 1 (caniuse-lite). The CC-BY-4.0 and Apache-2.0 entries are build-time (dev) packages and
are not part of the built `frontend/dist`; credit for `caniuse-lite` (data by caniuse.com contributors) is given here.
The dashboard uses no web fonts and no icon font (CSS font stacks only), and loads no map tiles.

## 3. Desktop shell and native code (prototype, outside the tested path)

`frontend/src-tauri/Cargo.toml` depends on `tauri` 2.0 (wry), `serde`, `serde_json`; `rust/aegis_fastpath` is the team's
own crate. No `Cargo.lock` is committed and no crate licences were read: *unverified*. Tauri's application icons
(`frontend/src-tauri/icons/*`) have no recorded origin: *unverified*; confirm or replace before redistributing the shell.

## 4. Datasets and external platforms (analysed, not redistributed)

| Item | Licence as recorded in this repository | Use |
|---|---|---|
| ALFA (AIR Lab Fault and Anomaly) | "CC BY 4.0" (`data/external/manifests/alfa.json`); the team has **not** re-checked it at the source | real fixed-wing `.tlog` replay (raw logs fetched by `scripts/fetch_external_data.py`, git-ignored; SHA-256 in the manifest) |
| PX4 Flight Review public logs | "no dataset licence stated" (`data/external/manifests/px4_review_v2.json`, `docs/EXTERNAL_DATA.md`) | analysed locally; raw logs not redistributed. Do not include them in the archive |
| PX4-Autopilot, ArduPilot (ArduCopter), Gazebo | *unverified*; used as external SITL executables, not vendored | `SITL` runs only |

## 5. Models and captures

- `models/isoforest.joblib`, `models/isoforest_px4.joblib`: trained by the team from simulator output with scikit-learn;
  git-ignored; regenerate with `aegis train`. They carry the scikit-learn pickle-compatibility constraint, not a third-party licence.
- Bench captures under `data/hardware/raw/` are the team's own, contain the vehicle position, and are git-ignored
  and **not** published (see `docs/SUBMISSION_ARCHIVE_MANIFEST.md`).
