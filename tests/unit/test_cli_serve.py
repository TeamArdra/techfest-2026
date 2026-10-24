"""``aegis serve`` source wiring (lead, telemetry closure 2026-10-20).

Regression for a silent SIM fallback: the ``--source`` flags were parsed but never reached the app, so
``aegis serve --source serial --serial-port COM7`` served the simulator. The CLI now validates a ``SourceSpec``
first (exit 2 on any invalid or unsafe combination, before a server starts) and hands it to the app through
``AEGIS_*`` variables. ``uvicorn`` is stubbed: no server starts and no port is ever opened.
"""

from __future__ import annotations

import importlib
import os
import sys
import types

import pytest

from aegisflight.backend.sources import SourceSpec, spec_from_env

cli = importlib.import_module("aegisflight.cli.main")  # the package re-exports main(), which shadows the module

AEGIS_KEYS = ("AEGIS_SOURCE", "AEGIS_SERIAL_PORT", "AEGIS_BAUD", "AEGIS_ALLOW_URL", "AEGIS_TLOG",
              "AEGIS_REPLAY_SPEED", "AEGIS_UDP_PORT", "AEGIS_CONFIG_DIR", "AEGIS_ML", "AEGIS_RECONNECT",
              "AEGIS_DB", "AEGIS_SERVE_HOST")


@pytest.fixture
def uvicorn_calls(monkeypatch):
    for k in AEGIS_KEYS:  # recorded by monkeypatch, so whatever the CLI exports is undone after the test
        monkeypatch.setenv(k, "")
    calls: list[tuple[str, dict]] = []
    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=lambda app, **kw: calls.append((app, kw))))
    return calls


@pytest.fixture
def tlog(tmp_path):
    p = tmp_path / "placeholder.tlog"  # only existence is checked before the server starts
    p.write_bytes(b"")
    return str(p)


@pytest.mark.parametrize("argv", [
    ["--source", "serial"],                                           # no port
    ["--source", "serial", "--serial-port", "socket://127.0.0.1:9"],  # virtual port without --allow-url
    ["--source", "replay"],                                           # no tlog
    ["--source", "replay", "--tlog", "does/not/exist.tlog"],
    ["--source", "udp"],                                              # no port
])
def test_invalid_source_exits_2_and_never_starts_a_server(uvicorn_calls, argv, capsys):
    assert cli.main(["serve", *argv]) == 2
    assert uvicorn_calls == []
    assert "aegis serve:" in capsys.readouterr().err
    assert spec_from_env().environment == "SIM"  # nothing exported: no half-configured app


@pytest.mark.parametrize("extra", [["--reload"], ["--host", "0.0.0.0"], ["--host", "192.168.1.20"]])
def test_non_sim_source_refuses_reload_and_non_loopback_host(uvicorn_calls, tlog, extra):
    assert cli.main(["serve", "--source", "replay", "--tlog", tlog, *extra]) == 2
    assert uvicorn_calls == []


def test_replay_spec_reaches_the_app_unchanged(uvicorn_calls, tlog, tmp_path):
    db = str(tmp_path / "events.sqlite")
    assert cli.main(["serve", "--source", "replay", "--tlog", tlog, "--replay-speed", "2.5", "--db", db]) == 0
    assert uvicorn_calls == [("aegisflight.backend.app:app", {"host": "127.0.0.1", "port": 8000, "reload": False})]
    spec = spec_from_env()
    assert spec == SourceSpec(kind="replay", tlog=tlog, speed=2.5)
    assert spec.environment == "REPLAY"
    assert os.environ["AEGIS_DB"] == db


def test_serial_port_and_no_reconnect_reach_the_app(uvicorn_calls):
    assert cli.main(["serve", "--source", "serial", "--serial-port", "COM7", "--no-reconnect"]) == 0
    spec = spec_from_env()
    assert spec == SourceSpec(kind="serial", port="COM7", baud=115200, reconnect=False)
    assert spec.environment == "BENCH"  # an OS serial device was configured (not proof of a physical board)


def test_default_serve_is_sim_even_with_stale_shell_variables(uvicorn_calls, monkeypatch):
    monkeypatch.setenv("AEGIS_SOURCE", "serial")
    monkeypatch.setenv("AEGIS_SERIAL_PORT", "COM7")
    assert cli.main(["serve"]) == 0
    assert len(uvicorn_calls) == 1
    spec = spec_from_env()
    assert spec.kind == "sim" and spec.environment == "SIM" and spec.port is None


def test_every_exported_key_is_one_the_app_reads(tlog):
    args = cli.build_parser().parse_args(["serve", "--source", "replay", "--tlog", tlog])
    assert set(cli._serve_env(SourceSpec(kind="replay", tlog=tlog), args)) == set(AEGIS_KEYS)
