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

**Status summary (2026-10-29).** *Verified from package metadata or a licence file shipped in the artifact:* the Python runtime and optional dependencies (§1), the npm lock (§2),
pyulog, uvloop, the dev tools, and the licence headers of PX4, ArduPilot and Gazebo Sim (§4). *Partially verified (declared metadata only, texts not audited):* the 391 Rust crates (§3),
the bundled components of wheels, PX4/Gazebo sub-components. *Unresolved:* origin of the Tauri icons (§3), the ALFA dataset licence at its source (§4), the copyright-holder line in `LICENSE`.
Nothing here is a legal determination.

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
**pyulog** (`external` extra, PX4 ULog adapter) 1.3.0: **BSD-3-Clause** (`License-Expression` in the wheel's `METADATA`; `LICENSE.md` present in the wheel). Read 2026-10-29 from the wheel downloaded with `pip download pyulog --no-deps` into a scratch directory; it is not installed in the project environment. Its own dependencies were not walked.
**uvloop** (`uvicorn[standard]` on Linux/macOS only) 0.23.0: **MIT** (`License: MIT License`; `LICENSE-MIT` and `LICENSE-APACHE` present in the manylinux wheel, i.e. dual MIT / Apache-2.0 files). Read from the downloaded wheel metadata; not installed on Windows.
Dev-only (not shipped), read with `importlib.metadata` from the project environment: pytest 9.1.1 MIT, pytest-asyncio 1.4.0 Apache-2.0, httpx 0.28.1 BSD-3-Clause (httpcore 1.0.9 BSD-3-Clause), ruff 0.16.10 MIT, mypy 2.4.0 MIT (its wheel also bundles typeshed, which has its own `LICENSE` file inside the wheel; not audited). Declared metadata only.

## 2. Frontend (`frontend/package.json`, `package-lock.json`)

Production dependencies in the lock file: react 18.3.1, react-dom 18.3.1, scheduler 0.23.2, loose-envify 1.4.0,
js-tokens 4.0.0: all declare **MIT**. The 115 lock entries in total declare: MIT 106, ISC 5 (electron-to-chromium,
lru-cache, picocolors, semver, yallist), Apache-2.0 2 (typescript, baseline-browser-mapping), BSD-3-Clause 1
(source-map-js), **CC-BY-4.0** 1 (caniuse-lite). The CC-BY-4.0 and Apache-2.0 entries are build-time (dev) packages and
are not part of the built `frontend/dist`; credit for `caniuse-lite` (data by caniuse.com contributors) is given here.
The dashboard uses no web fonts and no icon font (CSS font stacks only), and loads no map tiles.

## 3. Desktop shell and native code (prototype, outside the tested path)

`frontend/src-tauri/Cargo.toml` depends on `tauri` 2.0 (wry), `serde`, `serde_json`; `rust/aegis_fastpath` is the team's
own crate and has no dependencies. No `Cargo.lock` is committed, so the crate set below is a resolution from 2026-10-29, not a pinned one.
**Rust crates, partially verified.** `cargo metadata` was run on copies of both manifests in a scratch directory (cargo 1.99.0; the repository was not touched and
no `Cargo.lock` was created in it). It resolved **391 registry crates** (tauri 2.12.5, wry 0.57.1, serde 1.0.229, serde_json 1.0.154 and their
transitive crates, all platforms), **every one with a declared `license` field**. Declared expressions: mostly `MIT OR Apache-2.0` / `MIT` / `Apache-2.0`
variants; also Unicode-3.0 (18 crates), Zlib, Unlicense OR MIT, BSD-3-Clause OR MIT OR Apache-2.0, CC0-1.0 OR MIT-0 OR Apache-2.0, 0BSD OR MIT OR Apache-2.0, and
**MPL-2.0 for 5 crates** (cssparser, cssparser-macros, dtoa-short, option-ext, selectors; MPL-2.0 is file-level copyleft: keep their notices and source availability if the
shell is redistributed). `r-efi` (2 versions) is `MIT OR Apache-2.0 OR LGPL-2.1-or-later` (any of the three; the MIT or Apache option applies). **Not verified:** the licence *texts* in
the crate sources (34 of the 391 crate directories contain no `LICENSE*`/`COPYING*` file at the top level, though their manifests declare a licence), the platform-conditional
subset actually linked into a given build, and the licences of any crate the lock would pin differently. Treat as "declared, not audited".
**Tauri application icons: unresolved.** `frontend/src-tauri/icons/*` were added in the single commit `1a61231` with no recorded origin and were not compared with Tauri's template icons
(not available offline). Confirm they are Tauri's scaffold icons or the team's own, or replace them, before redistributing the shell.

## 4. Datasets and external platforms (analysed, not redistributed)

| Item | Licence as recorded in this repository | Use |
|---|---|---|
| ALFA (AIR Lab Fault and Anomaly) | "CC BY 4.0" (`data/external/manifests/alfa.json`); the team has **not** re-checked it at the source | real fixed-wing `.tlog` replay (raw logs fetched by `scripts/fetch_external_data.py`, git-ignored; SHA-256 in the manifest) |
| PX4 Flight Review public logs | "no dataset licence stated" (`data/external/manifests/px4_review_v2.json`, `docs/EXTERNAL_DATA.md`) | analysed locally; raw logs not redistributed. Do not include them in the archive |
| PX4-Autopilot `v1.18.0-rc1-27-gc239c63807` | **BSD-3-Clause**: first lines of `/home/astryx/PX4-Autopilot/LICENSE` read (read-only) in WSL on 2026-10-29; sub-modules and bundled third-party code in the PX4 tree were not audited | `SITL` runs only; external executable, not vendored |
| ArduPilot (ArduCopter 4.7.1 runs; checkout `/home/astryx/ardupilot`) | **GPL-3.0**: `COPYING.txt` there is the GPL v3 text (header read). Not vendored or linked; only run as a separate process and talked to over MAVLink. Derived works of ArduPilot would carry GPL obligations; AegisFlight contains none | `SITL` runs only |
| Gazebo Sim 8 (`libgz-sim8` 8.15.0-1~noble) | **Apache-2.0**: Debian `/usr/share/doc/libgz-sim8/copyright` (upstream gz-sim, Open Source Robotics Foundation) read in WSL; other Gazebo libraries and bundled models/worlds were not audited | `SITL` runs only; external executable, not vendored |

## 5. Models and captures

- `models/isoforest.joblib`, `models/isoforest_px4.joblib`: trained by the team from simulator output with scikit-learn;
  git-ignored; regenerate with `aegis train`. They carry the scikit-learn pickle-compatibility constraint, not a third-party licence.
- Bench captures under `data/hardware/raw/` are the team's own, contain the vehicle position, and are git-ignored
  and **not** published (see `docs/SUBMISSION_ARCHIVE_MANIFEST.md`).
