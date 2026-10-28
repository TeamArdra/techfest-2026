"""MAVLink-2 signing on the inline IPS uplink. SYNTHETIC frames; the key is a throwaway test value."""

from __future__ import annotations

import importlib
import time

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mavlink.signing import MAVLINK_EPOCH_UNIX_S, sign_mavlink2_frame
from aegisflight.mitigation.inline_policy import (
    FORCE_MAGIC,
    MAV_CMD_COMPONENT_ARM_DISARM,
    MAV_CMD_DO_SET_MODE,
    InlinePolicy,
)
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.proxy.hooks import FrameContext
from aegisflight.proxy.transport import split_frames

cli = importlib.import_module("aegisflight.cli.main")  # the package re-exports main(), which shadows the module

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def now_ts() -> int:
    return int((time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000)


def _enc(sysid: int, comp: int = 190) -> mav2.MAVLink:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    m.robust_parsing = True
    return m


def cmd(sysid: int, command: int = MAV_CMD_DO_SET_MODE, p1: float = 1.0, p2: float = 4.0) -> bytes:
    m = _enc(sysid)
    return bytes(m.command_long_encode(1, 1, command, 0, p1, p2, 0, 0, 0, 0, 0).pack(m))


def signed(raw: bytes, ts: int | None = None, key: bytes = KEY) -> bytes:
    return sign_mavlink2_frame(raw, key, link_id=0, timestamp_10us=ts if ts is not None else now_ts())


def ctx(raw: bytes) -> FrameContext:
    fr = split_frames(raw)[0][0]
    return FrameContext(direction="up", raw=fr.raw, recv_ns=1, sysid=fr.sysid, compid=fr.compid,  # type: ignore[arg-type]
                        seq=fr.seq, msgid=fr.msgid, signed=fr.signed)


class Clock:
    t = 100.0

    def __call__(self) -> float:
        return self.t


def make(**kw) -> InlinePolicy:
    p = InlinePolicy(FrameSanitizer(), signing_key=KEY, clock=Clock(), **kw)
    p.set_enforce(True)
    return p


def test_unsigned_control_is_dropped_even_from_the_real_gcs_sysid():
    p = make()
    assert p.up(ctx(cmd(66))) == [] and p.up(ctx(cmd(255))) == []   # a spoofed sysid 255 no longer works
    assert p.dropped_unsigned == 2


def test_validly_signed_pilot_command_passes_and_a_forged_signature_does_not():
    p = make()
    good = signed(cmd(255), 1000)
    assert p.up(ctx(good)) == [good]
    assert p.up(ctx(signed(cmd(255, p2=5.0), 2000, key=OTHER_KEY))) == []
    assert (p.signed_ok, p.dropped_bad_signature) == (1, 1)


def test_signature_not_sysid_is_what_makes_a_sender_trusted():
    p = make()
    raw = signed(cmd(66), 5000)           # holds the key, so it is authorised whatever sysid it uses
    assert p.up(ctx(raw)) == [raw]


def test_replay_of_a_captured_signed_frame_is_rejected():
    p = make()
    raw = signed(cmd(255), 7000)
    assert p.up(ctx(raw)) == [raw]
    assert p.up(ctx(raw)) == []           # gcs_replay: same bytes again
    assert p.up(ctx(signed(cmd(255, p2=9.0), 6999))) == []   # older timestamp
    assert p.dropped_replay == 2


def test_in_flight_plain_disarm_is_still_dropped_when_validly_signed():
    p = make()
    p.armed, p.rel_alt_m, p.groundspeed_ms = True, 30.0, 5.0
    plain = signed(cmd(255, MAV_CMD_COMPONENT_ARM_DISARM, 0.0, 0.0), 8000)
    assert p.up(ctx(plain)) == []
    kill = signed(cmd(255, MAV_CMD_COMPONENT_ARM_DISARM, 0.0, FORCE_MAGIC), 8001)
    assert p.up(ctx(kill)) == [kill]


def test_non_control_uplink_needs_no_signature():
    p = make()
    m = _enc(255)
    hb = bytes(m.heartbeat_encode(6, 8, 0, 0, 4).pack(m))
    assert p.up(ctx(hb)) == [hb]


def test_permissive_rollout_lets_unsigned_trusted_through_but_never_forged_or_foreign():
    p = make(allow_unsigned_from_trusted=True)
    raw = cmd(255)
    assert p.up(ctx(raw)) == [raw]
    assert p.up(ctx(cmd(66))) == []                                    # unsigned from an unknown sysid
    assert p.up(ctx(signed(cmd(255, p2=7.0), 1, key=OTHER_KEY))) == []  # forged signature


def test_timestamp_state_survives_a_restart(tmp_path):
    state = tmp_path / "sig.json"
    raw = signed(cmd(255), 9000)
    p1 = make(state_path=state)
    assert p1.up(ctx(raw)) == [raw]
    p1.flush()
    p2 = make(state_path=state)           # the bridge restarted
    assert p2.up(ctx(raw)) == []          # the replay window did not reopen
    assert p2.dropped_replay == 1
    assert make(state_path=tmp_path / "missing.json").up(ctx(raw)) == [raw]  # no state file: first sight is accepted


def test_max_age_rejects_a_captured_frame_held_back_and_released_later():
    p = make(max_age_s=30.0)
    stale = signed(cmd(255), now_ts() - 60 * 100_000)
    assert p.up(ctx(stale)) == []
    fresh = signed(cmd(255, p2=3.0), now_ts())
    assert p.up(ctx(fresh)) == [fresh]


def test_interop_with_pymavlinks_own_signer():
    """The verifier must accept what a real GCS library produces, not only this repo's signer."""
    m = _enc(255)
    m.signing.secret_key = KEY
    m.signing.sign_outgoing = True
    m.signing.link_id = 0
    m.signing.timestamp = now_ts()
    raw = bytes(m.command_long_encode(1, 1, MAV_CMD_DO_SET_MODE, 0, 1, 4, 0, 0, 0, 0, 0).pack(m))
    assert raw[2] & 1                      # incompat flag: signed
    p = make()
    assert p.up(ctx(raw)) == [raw]


def test_bridge_signs_its_counter_frames_and_forwards_a_valid_pilot_command():
    class Link:
        def __init__(self):
            self.inbox, self.sent = [], []

        def poll(self):
            out, self.inbox = self.inbox, []
            return out

        def send(self, d):
            self.sent.append(bytes(d))
            return True

        def close(self):
            pass

    fc, gcs = Link(), Link()
    b = InlineIpsBridge(fc, gcs, mode="active-ips", secret_key=KEY)
    frame = b.controller.actuator.encode_ekf_source_switch(source_set=2)
    assert frame[2] & 1, "counter-frames must be signed or a signing-enforcing FC would reject them"
    good = signed(cmd(255), 4000)
    gcs.inbox = [(1, good), (1, cmd(66)), (1, cmd(255, p2=8.0))]
    b.pump_once()
    assert fc.sent == [good] and b.status()["policy"]["signing"] is True


def test_cli_rejects_a_bad_key_file(tmp_path, capsys):
    bad = tmp_path / "k.bin"
    bad.write_bytes(b"too short")
    rc = cli.main(["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2",
                   "--allow-url", "--signing-key-file", str(bad), "--seconds", "0.1"])
    assert rc == 2 and "signing-key-file" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["ips-bridge", "--fc-port", "a"])  # --gcs-port is required
