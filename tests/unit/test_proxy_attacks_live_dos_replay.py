"""Unit tests for ``aegisflight.proxy.attacks_live_dos_replay`` -- ``DropAttack``,
``DelayAttack``, ``ReplayAttack`` and their ``draw_*_params`` functions. Synthetic
MAVLink 2/1 frames built with pymavlink's dialects; no sockets, no PX4, no transport
module involved -- same technique as ``test_proxy_attacks_live.py`` /
``test_proxy_command_injection.py``."""

from __future__ import annotations

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

from aegisflight.proxy.attacks_live_dos_replay import (
    DEFAULT_CAPTURE_COMMAND,
    DEFAULT_CAPTURE_COMPID,
    DEFAULT_CAPTURE_SYSID,
    DELAY_RANGES,
    DROP_RANGES,
    REPLAY_RANGES,
    DelayAttack,
    DelayParams,
    DropAttack,
    DropParams,
    ReplayAttack,
    ReplayParams,
    draw_delay_params,
    draw_drop_params,
    draw_replay_params,
)
from aegisflight.proxy.groundtruth import (
    FrameLogWriter,
    compute_delay_effect,
    compute_drop_effect,
    compute_replay_effect,
    read_frame_log,
)
from aegisflight.proxy.hooks import FrameContext

# --------------------------------------------------------------------------- #
# shared synthetic-frame helpers (same convention as the sibling test files)
# --------------------------------------------------------------------------- #


def _mk(sysid: int, compid: int, seq: int, dialect=mav2):
    m = dialect.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return m


def hb_raw(seq: int = 0, sysid: int = 3, compid: int = 1, autopilot: int = 12) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, autopilot, 0x80, 0, 4).pack(m))


def gpi_raw(seq: int = 0, sysid: int = 3, compid: int = 1, lat: int = 473977418, lon: int = 85455940,
            dialect=mav2, signed: bool = False) -> bytes:
    m = _mk(sysid, compid, seq, dialect)
    if signed:
        m.signing.secret_key = bytes(32)
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = 1000
    return bytes(m.global_position_int_encode(1000, lat, lon, 488000, 12000, 10, -20, 30, 9000).pack(m))


def gps_raw_int_raw(seq: int = 0, sysid: int = 3, compid: int = 1) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.gps_raw_int_encode(1000, 3, 473977418, 85455940, 488000, 100, 100, 0, 0, 10).pack(m))


def att_raw(seq: int = 0, sysid: int = 3, compid: int = 1) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.attitude_encode(1000, 0.1, -0.2, 1.5, 0.0, 0.0, 0.0).pack(m))


def cmd_long_raw(seq: int = 0, sysid: int = DEFAULT_CAPTURE_SYSID, compid: int = DEFAULT_CAPTURE_COMPID,
                  command: int = DEFAULT_CAPTURE_COMMAND, param1: float = 244.0, param2: float = 100000.0,
                  dialect=mav2, signed: bool = False) -> bytes:
    m = _mk(sysid, compid, seq, dialect)
    if signed:
        m.signing.secret_key = bytes(32)
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = 1000
    return bytes(m.command_long_encode(3, 1, command, 0, param1, param2, 0, 0, 0, 0, 0).pack(m))


def ack_raw(command: int = DEFAULT_CAPTURE_COMMAND, result: int = mav2.MAV_RESULT_ACCEPTED, seq: int = 0,
            sysid: int = 3, compid: int = 1, signed: bool = False) -> bytes:
    m = _mk(sysid, compid, seq)
    if signed:
        m.signing.secret_key = bytes(32)
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = 1000
    return bytes(m.command_ack_encode(command, result).pack(m))


def ctx_for(raw: bytes, direction: str, recv_ns: int = 0) -> FrameContext:
    if raw[0] == 0xFD:
        incompat = raw[2]
        seq, sysid, compid = raw[4], raw[5], raw[6]
        msgid = raw[7] | (raw[8] << 8) | (raw[9] << 16)
        signed = bool(incompat & 0x01)
    else:
        seq, sysid, compid, msgid = raw[2], raw[3], raw[4], raw[5]
        signed = False
    return FrameContext(direction=direction, raw=raw, recv_ns=recv_ns, sysid=sysid, compid=compid,
                        seq=seq, msgid=msgid, signed=signed)


def decode(raw: bytes):
    return mav2.MAVLink(None).decode(bytearray(raw))


# =========================================================================== #
# DropAttack
# =========================================================================== #

DROP_PARAMS = DropParams(trial_seed=1, trial_index=0, onset_s=5.0, duration_s=10.0)  # window [5, 15)


def _fresh_drop(**kw) -> DropAttack:
    return DropAttack(DROP_PARAMS, warmup_s=0.0, **kw)


def _learn_drop(a: DropAttack, recv_ns: int = 0) -> None:
    a(ctx_for(hb_raw(), "down", recv_ns=recv_ns))


def test_drop_fail_closed_before_target_learned():
    a = _fresh_drop()
    raw = gpi_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_dropped == 0


def test_drop_up_direction_always_passthrough():
    a = _fresh_drop()
    _learn_drop(a)
    raw = gpi_raw(seq=1)
    out = a(ctx_for(raw, "up", recv_ns=8_000_000_000))
    assert out == [raw]


def test_drop_global_position_int_in_window_is_dropped():
    a = _fresh_drop()
    _learn_drop(a)
    raw = gpi_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))  # elapsed 8s, inside [5, 15)
    assert out == []
    assert a.frames_dropped == 1


def test_drop_gps_raw_int_in_window_is_dropped():
    a = _fresh_drop()
    _learn_drop(a)
    raw = gps_raw_int_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == []
    assert a.frames_dropped == 1


def test_drop_non_target_msgid_passthrough():
    a = _fresh_drop()
    _learn_drop(a)
    raw = att_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_dropped == 0


def test_drop_outside_window_passthrough():
    a = _fresh_drop()
    _learn_drop(a)
    early = gpi_raw(seq=1)
    assert a(ctx_for(early, "down", recv_ns=2_000_000_000)) == [early]
    late = gpi_raw(seq=2)
    assert a(ctx_for(late, "down", recv_ns=16_000_000_000)) == [late]
    assert a.frames_dropped == 0


def test_drop_other_source_passthrough():
    a = _fresh_drop()
    _learn_drop(a)  # learned as (3, 1)
    raw = gpi_raw(seq=1, sysid=9, compid=1)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_dropped == 0


def test_drop_signed_frame_never_dropped_and_counted():
    a = _fresh_drop()
    _learn_drop(a)
    raw = gpi_raw(seq=1, signed=True)
    ctx = ctx_for(raw, "down", recv_ns=8_000_000_000)
    assert ctx.signed
    out = a(ctx)
    assert out == [raw]
    assert a.frames_dropped == 0
    assert a.frames_skipped_signed == 1


def test_drop_mavlink1_frame_also_dropped():
    # Unlike PositionDriftAttack (which must decode the frame it rewrites and therefore
    # requires a v2 target), DropAttack never decodes the frame it suppresses -- it acts
    # on header-parsed msgid/sysid/compid alone (what the transport already supplies), so
    # a v1 frame of a dropped msgid is dropped exactly like a v2 one. Intentional, not a
    # gap: there is no CRC/signature to break by dropping, regardless of MAVLink version.
    a = _fresh_drop()
    _learn_drop(a)
    raw = gpi_raw(seq=1, dialect=mav1)
    assert raw[0] == 0xFE
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == []
    assert a.frames_dropped == 1


def test_drop_partial_target_configuration_rejected():
    with pytest.raises(ValueError):
        DropAttack(DROP_PARAMS, target_sysid=5, target_compid=None)


def test_drop_frame_log_entries(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = DropAttack(DROP_PARAMS, warmup_s=0.0, frame_log=log)
        _learn_drop(a)
        a(ctx_for(gpi_raw(seq=1), "down", recv_ns=6_000_000_000))
        a(ctx_for(gps_raw_int_raw(seq=2), "down", recv_ns=7_000_000_000))
        a(ctx_for(gpi_raw(seq=3, signed=True), "down", recv_ns=7_500_000_000))
        a(ctx_for(att_raw(seq=4), "down", recv_ns=7_600_000_000))  # not logged: not touched

    entries = read_frame_log(path)
    actions = [e.action for e in entries]
    assert actions.count("dropped") == 2
    assert actions.count("forwarded") == 1
    assert len(entries) == 3


def test_compute_drop_effect(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = DropAttack(DROP_PARAMS, warmup_s=0.0, frame_log=log)
        _learn_drop(a)
        for i, t_s in enumerate([6.0, 7.0, 8.0], start=1):
            a(ctx_for(gpi_raw(seq=i), "down", recv_ns=int(t_s * 1e9)))

    effect = compute_drop_effect(path)
    assert effect["frames_dropped"] == 3
    assert effect["observed_duration_s"] == pytest.approx(2.0)
    assert effect["by_msgid"] == {33: 3}


def test_compute_drop_effect_empty(tmp_path):
    path = tmp_path / "frames.jsonl"
    FrameLogWriter(path).close()
    effect = compute_drop_effect(path)
    assert effect["frames_dropped"] == 0
    assert effect["by_msgid"] == {}


# -- draw_drop_params -- #


def test_draw_drop_params_within_ranges():
    for seed in (1, 2, 3, 100, 20261006):
        p = draw_drop_params(seed)
        assert DROP_RANGES["onset_s"][0] <= p.onset_s < DROP_RANGES["onset_s"][1]
        assert DROP_RANGES["duration_s"][0] <= p.duration_s < DROP_RANGES["duration_s"][1]
        assert p.trial_seed == seed


def test_draw_drop_params_deterministic_repeat():
    assert draw_drop_params(42, 3) == draw_drop_params(42, 3)


def test_draw_drop_params_trial_seed_is_seed_plus_trial_index():
    p = draw_drop_params(100, trial_index=3)
    assert p.trial_seed == 103 and p.trial_index == 3


# =========================================================================== #
# DelayAttack
# =========================================================================== #

DELAY_PARAMS = DelayParams(trial_seed=1, trial_index=0, onset_s=5.0, duration_s=10.0, delay_s=1.0)


def _fresh_delay(**kw) -> DelayAttack:
    return DelayAttack(DELAY_PARAMS, warmup_s=0.0, **kw)


def _prime_delay(a: DelayAttack, recv_ns: int = 0) -> None:
    """Establish ``_first_down_recv_ns`` with a dedicated baseline call at ``recv_ns``
    (elapsed 0 -> outside any window), separate from the timed call(s) a test makes
    afterwards -- same convention as ``PositionDriftAttack``'s ``_learn`` helper. Without
    this, a test's *first* downlink call would itself set the baseline, making its own
    ``elapsed_s`` always 0 regardless of the ``recv_ns`` passed."""
    a(ctx_for(hb_raw(seq=0), "down", recv_ns=recv_ns))


def test_delay_up_direction_always_passthrough():
    a = _fresh_delay()
    raw = gpi_raw(seq=1)
    out = a(ctx_for(raw, "up", recv_ns=8_000_000_000))
    assert out == [raw]


def test_delay_outside_window_immediate_passthrough():
    a = _fresh_delay()
    _prime_delay(a)
    raw = hb_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=1_000_000_000))  # elapsed 1s < onset 5s
    assert out == [raw]
    assert a.frames_delayed == 0


def test_delay_held_frame_not_forwarded_immediately():
    a = _fresh_delay()
    _prime_delay(a)
    raw = hb_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=6_000_000_000))  # inside [5, 15)
    assert out == []
    assert a.frames_delayed == 1


def test_delay_held_frame_released_once_release_time_passed():
    a = _fresh_delay()  # delay_s = 1.0
    _prime_delay(a)
    held = hb_raw(seq=1)
    out1 = a(ctx_for(held, "down", recv_ns=6_000_000_000))
    assert out1 == []
    # next frame arrives before release time (6.0 + 1.0 = 7.0s)
    nxt = hb_raw(seq=2)
    out2 = a(ctx_for(nxt, "down", recv_ns=6_500_000_000))
    assert out2 == []  # nxt itself held too; held's release not due yet
    # a later frame, past release time of the first held frame but not the second
    out3 = a(ctx_for(hb_raw(seq=3), "down", recv_ns=7_200_000_000))
    assert out3 == [held]  # only the first held frame is due; the rest still waiting


def test_delay_byte_identical_and_order_preserving():
    a = _fresh_delay()
    _prime_delay(a)
    frames = [hb_raw(seq=i) for i in range(1, 6)]
    times_ns = [6_000_000_000 + i * 100_000_000 for i in range(5)]  # 100ms apart
    released: list[bytes] = []
    for raw, t in zip(frames, times_ns, strict=True):
        released.extend(a(ctx_for(raw, "down", recv_ns=t)))
    # flush everything by advancing well past the window end (onset 5 + duration 10 = 15s)
    released.extend(a(ctx_for(hb_raw(seq=99), "down", recv_ns=20_000_000_000)))
    forwarded_held = [r for r in released if r in frames]
    assert forwarded_held == frames  # byte-identical, exactly once each, original order


def test_delay_no_frame_lost_or_duplicated_across_many_calls():
    a = _fresh_delay()
    _prime_delay(a)
    frames = [hb_raw(seq=i % 256) for i in range(1, 21)]
    times_ns = [6_000_000_000 + i * 50_000_000 for i in range(20)]  # inside the window
    out_all: list[bytes] = []
    for raw, t in zip(frames, times_ns, strict=True):
        out_all.extend(a(ctx_for(raw, "down", recv_ns=t)))
    # window ends at 15s; feed one more frame after the window closes to force the flush
    out_all.extend(a(ctx_for(hb_raw(seq=250), "down", recv_ns=16_000_000_000)))
    held_out = [r for r in out_all if r in frames]
    assert held_out == frames  # every held frame forwarded exactly once, in order
    assert len(held_out) == len(frames)


def test_delay_window_end_flushes_remaining_held_frames():
    a = _fresh_delay()  # window [5, 15), delay 1.0s
    _prime_delay(a)
    held1 = hb_raw(seq=1)
    held2 = hb_raw(seq=2)
    assert a(ctx_for(held1, "down", recv_ns=14_500_000_000)) == []
    assert a(ctx_for(held2, "down", recv_ns=14_800_000_000)) == []
    # next frame arrives after the window closed (elapsed 16s) -- flush everything first,
    # then forward the live frame
    after = hb_raw(seq=3)
    out = a(ctx_for(after, "down", recv_ns=16_000_000_000))
    assert out == [held1, held2, after]


def _burst_frames(n: int, t0_ns: int, step_ns: int):
    """n distinct frames (distinct lat) at a high rate, as ``(raw, recv_ns)`` pairs."""
    return [(gpi_raw(seq=i % 256, lat=i), t0_ns + i * step_ns) for i in range(1, n + 1)]


def test_delay_never_returns_more_frames_than_the_relay_allows_per_call():
    """Regression (pilot p2l_trial_001: relay ``hook_errors: 1`` + 'sequence gap 240'): the window-end flush
    used to return EVERY held frame in one call (hundreds at PX4 rates) and the relay rejects hook output
    longer than 64 frames, failing open to the single original and LOSING the flushed frames."""
    a = _fresh_delay()  # window [5, 15) s, delay 1.0 s
    _prime_delay(a)
    # 3 ms spacing -> ~330 frames held per second of delay; window closes at 15 s
    frames = _burst_frames(900, 14_000_000_000, 3_000_000)  # 14.0 s .. 16.7 s
    longest = 0
    for raw, t in frames:
        out = a(ctx_for(raw, "down", recv_ns=t))
        longest = max(longest, len(out))
    assert longest <= 64, longest


def test_delay_exactly_once_in_order_at_px4_rates_through_window_end():
    """No loss, no duplication, original order, across the window end at high rate, with the output
    capped per call. Everything fed is eventually forwarded (feed enough trailing frames to drain)."""
    a = _fresh_delay()
    _prime_delay(a)
    frames = _burst_frames(1500, 13_500_000_000, 3_000_000)  # 13.5 s .. 18.0 s
    out_all: list[bytes] = []
    for raw, t in frames:
        out_all.extend(a(ctx_for(raw, "down", recv_ns=t)))
    sent = [raw for raw, _ in frames]
    assert out_all == sent[: len(out_all)]  # exactly once, byte-identical, original order (a prefix)
    assert len(sent) - len(out_all) <= 340  # only a still-draining tail (<= ~1 s of frames) may remain


def test_delay_through_real_relay_has_no_hook_errors_and_loses_nothing():
    """End to end through the real ``MavlinkRelay`` (which enforces the 64-frame cap): zero hook errors,
    every downlink frame delivered to the client exactly once and in order once the backlog drains."""
    from aegisflight.proxy.transport import MavlinkRelay

    class Up:
        dropped_overflow = 0

        def __init__(self):
            self.inbox = []

        def start(self): ...
        def poll(self):
            out, self.inbox = self.inbox, []
            return out

        def send(self, data):
            return True

        def send_heartbeat(self):
            return True

        def close(self): ...

    class Down:
        dropped_overflow = 0

        def __init__(self):
            self.inbox = []
            self.sent = []

        def start(self): ...
        def poll(self):
            out, self.inbox = self.inbox, []
            return out

        def sendto(self, data, addr):
            self.sent.append(data)
            return True

        def close(self): ...

    client = ("127.0.0.1", 50001)
    a = _fresh_delay()
    up, down = Up(), Down()
    clock = [0]
    r = MavlinkRelay(up, down, down_hook=a, clock_ns=lambda: clock[0], sleep=lambda s: None)
    down.inbox.append((1, client, hb_raw(seq=0, sysid=255, compid=190)))  # registers the client
    r.pump_once()
    up.inbox.append((0, hb_raw(seq=0)))  # primes the hook's time base (elapsed 0)
    r.pump_once()
    frames = _burst_frames(1500, 13_500_000_000, 3_000_000)
    for raw, t in frames:
        up.inbox.append((t, raw))
        r.pump_once()
    delivered = [d for d in down.sent if d in {raw for raw, _ in frames}]
    sent = [raw for raw, _ in frames]
    assert r.stats["hook_errors"] == 0
    assert delivered == sent[: len(delivered)]
    assert len(sent) - len(delivered) <= 340


def test_delay_signed_frame_never_held_and_counted():
    a = _fresh_delay()
    _prime_delay(a)
    raw = gpi_raw(seq=1, signed=True)
    ctx = ctx_for(raw, "down", recv_ns=6_000_000_000)  # inside [5, 15)
    assert ctx.signed
    out = a(ctx)
    assert out == [raw]
    assert a.frames_delayed == 0
    assert a.frames_skipped_signed == 1


def test_delay_frame_log_entries(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = DelayAttack(DELAY_PARAMS, warmup_s=0.0, frame_log=log)
        _prime_delay(a)
        a(ctx_for(hb_raw(seq=1), "down", recv_ns=6_000_000_000))
    entries = read_frame_log(path)
    assert len(entries) == 1
    assert entries[0].action == "delayed"
    assert entries[0].field_deltas["delay_ns"] == 1_000_000_000
    assert entries[0].field_deltas["original_recv_ns"] == 6_000_000_000
    assert entries[0].field_deltas["release_ns"] == 7_000_000_000


def test_compute_delay_effect(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = DelayAttack(DELAY_PARAMS, warmup_s=0.0, frame_log=log)
        _prime_delay(a)
        a(ctx_for(hb_raw(seq=1), "down", recv_ns=6_000_000_000))
        a(ctx_for(hb_raw(seq=2), "down", recv_ns=6_500_000_000))
    effect = compute_delay_effect(path)
    assert effect["frames_delayed"] == 2
    assert effect["mean_delay_s"] == pytest.approx(1.0)
    assert effect["max_delay_s"] == pytest.approx(1.0)


def test_compute_delay_effect_empty(tmp_path):
    path = tmp_path / "frames.jsonl"
    FrameLogWriter(path).close()
    effect = compute_delay_effect(path)
    assert effect["frames_delayed"] == 0


# -- draw_delay_params -- #


def test_draw_delay_params_within_ranges():
    for seed in (1, 2, 3, 100, 20261006):
        p = draw_delay_params(seed)
        assert DELAY_RANGES["onset_s"][0] <= p.onset_s < DELAY_RANGES["onset_s"][1]
        assert DELAY_RANGES["duration_s"][0] <= p.duration_s < DELAY_RANGES["duration_s"][1]
        assert DELAY_RANGES["delay_s"][0] <= p.delay_s < DELAY_RANGES["delay_s"][1]
        assert p.trial_seed == seed


def test_draw_delay_params_deterministic_repeat():
    assert draw_delay_params(42, 3) == draw_delay_params(42, 3)


# =========================================================================== #
# ReplayAttack
# =========================================================================== #

REPLAY_PARAMS = ReplayParams(trial_seed=1, trial_index=0, replay_delay_s=5.0)


def _fresh_replay(**kw) -> ReplayAttack:
    return ReplayAttack(REPLAY_PARAMS, **kw)


def test_replay_downlink_never_modified():
    a = _fresh_replay()
    raw = hb_raw(seq=1, sysid=3)
    out = a(ctx_for(raw, "down", recv_ns=0))
    assert out == [raw]


def test_replay_real_carrier_always_passed_through_unchanged():
    a = _fresh_replay()
    raw = cmd_long_raw(seq=1)
    out = a(ctx_for(raw, "up", recv_ns=0))
    assert out == [raw]  # the capture candidate itself is only ever forwarded, never duplicated


def test_replay_fires_after_delay_on_a_later_carrier():
    a = _fresh_replay()  # replay_delay_s = 5.0
    captured = cmd_long_raw(seq=1)
    a(ctx_for(captured, "up", recv_ns=0))  # captured here
    carrier = hb_raw(seq=2, sysid=252)
    too_early = a(ctx_for(carrier, "up", recv_ns=3_000_000_000))  # 3s < 5s
    assert too_early == [carrier]
    assert a.frames_replayed == 0
    carrier2 = hb_raw(seq=3, sysid=252)
    out = a(ctx_for(carrier2, "up", recv_ns=6_000_000_000))  # 6s >= 5s
    assert out == [carrier2, captured]
    assert a.frames_replayed == 1


def test_replay_only_fires_once():
    a = _fresh_replay()
    captured = cmd_long_raw(seq=1)
    a(ctx_for(captured, "up", recv_ns=0))
    a(ctx_for(hb_raw(seq=2), "up", recv_ns=6_000_000_000))  # fires
    out2 = a(ctx_for(hb_raw(seq=3), "up", recv_ns=12_000_000_000))
    assert out2 == [hb_raw(seq=3)]
    assert a.frames_replayed == 1


def test_replay_wrong_source_not_captured():
    a = _fresh_replay()
    raw = cmd_long_raw(seq=1, sysid=99)  # not the capture identity
    a(ctx_for(raw, "up", recv_ns=0))
    out = a(ctx_for(hb_raw(seq=2), "up", recv_ns=10_000_000_000))
    assert out == [hb_raw(seq=2)]  # nothing captured -> nothing replayed
    assert a.frames_replayed == 0


def test_replay_wrong_command_not_captured():
    a = _fresh_replay()
    raw = cmd_long_raw(seq=1, command=mav2.MAV_CMD_DO_SET_MODE)
    a(ctx_for(raw, "up", recv_ns=0))
    out = a(ctx_for(hb_raw(seq=2), "up", recv_ns=10_000_000_000))
    assert out == [hb_raw(seq=2)]
    assert a.frames_replayed == 0


def test_replay_signed_candidate_never_captured_and_counted():
    a = _fresh_replay()
    raw = cmd_long_raw(seq=1, signed=True)
    ctx = ctx_for(raw, "up", recv_ns=0)
    assert ctx.signed
    out = a(ctx)
    assert out == [raw]
    out2 = a(ctx_for(hb_raw(seq=2), "up", recv_ns=10_000_000_000))
    assert out2 == [hb_raw(seq=2)]  # never captured -> nothing to replay
    assert a.frames_skipped_signed == 1


def test_replay_signed_carrier_never_used_to_piggyback():
    a = _fresh_replay()
    captured = cmd_long_raw(seq=1)
    a(ctx_for(captured, "up", recv_ns=0))
    m = mav2.MAVLink(None, srcSystem=3, srcComponent=1)
    m.seq = 2
    m.signing.secret_key = bytes(32)
    m.signing.sign_outgoing = True
    m.signing.link_id = 0
    m.signing.timestamp = 1000
    signed_carrier = bytes(m.heartbeat_encode(mav2.MAV_TYPE_GCS, 0, 0, 0, 4).pack(m))
    ctx = ctx_for(signed_carrier, "up", recv_ns=6_000_000_000)
    assert ctx.signed
    out = a(ctx)
    assert out == [signed_carrier]
    assert a.frames_replayed == 0
    assert a.frames_skipped_signed == 1


def test_replay_mavlink1_candidate_not_captured():
    a = _fresh_replay()
    raw = cmd_long_raw(seq=1, dialect=mav1)
    assert raw[0] == 0xFE
    a(ctx_for(raw, "up", recv_ns=0))
    out = a(ctx_for(hb_raw(seq=2), "up", recv_ns=10_000_000_000))
    assert out == [hb_raw(seq=2)]
    assert a.frames_replayed == 0


def test_replay_byte_identical_replay():
    a = _fresh_replay()
    captured = cmd_long_raw(seq=1, param1=244.0, param2=50000.0)
    a(ctx_for(captured, "up", recv_ns=0))
    out = a(ctx_for(hb_raw(seq=2), "up", recv_ns=6_000_000_000))
    assert out[1] == captured
    replayed_msg = decode(out[1])
    original_msg = decode(captured)
    assert replayed_msg.get_seq() == original_msg.get_seq()
    assert replayed_msg.get_srcSystem() == original_msg.get_srcSystem()


# -- ack bookkeeping and compute_replay_effect -- #


def test_replay_ack_observed_before_and_after(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = ReplayAttack(REPLAY_PARAMS, frame_log=log)
        a(ctx_for(cmd_long_raw(seq=1), "up", recv_ns=0))  # captured at t=0
        a(ctx_for(ack_raw(result=mav2.MAV_RESULT_ACCEPTED), "down", recv_ns=300_000_000))  # original ack
        a(ctx_for(hb_raw(seq=2), "up", recv_ns=6_000_000_000))  # replay fires at t=6s
        a(ctx_for(ack_raw(result=mav2.MAV_RESULT_ACCEPTED), "down", recv_ns=6_300_000_000))  # replay ack

    entries = read_frame_log(path)
    actions = [e.action for e in entries]
    assert actions.count("captured") == 1
    assert actions.count("replayed") == 1
    assert actions.count("observed_ack") == 2

    effect = compute_replay_effect(path)
    assert effect["captured"] is True
    assert effect["replayed"] is True
    assert effect["actual_delay_s"] == pytest.approx(6.0)
    assert effect["original_ack"]["result"] == mav2.MAV_RESULT_ACCEPTED
    assert effect["original_ack"]["result_name"] == "MAV_RESULT_ACCEPTED"
    assert effect["replay_ack"]["result"] == mav2.MAV_RESULT_ACCEPTED
    assert effect["replay_ack"]["recv_ns"] == 6_300_000_000


def test_replay_ack_different_command_not_attributed(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = ReplayAttack(REPLAY_PARAMS, frame_log=log)
        a(ctx_for(cmd_long_raw(seq=1), "up", recv_ns=0))
        a(ctx_for(ack_raw(command=mav2.MAV_CMD_DO_SET_MODE), "down", recv_ns=300_000_000))
    entries = read_frame_log(path)
    assert all(e.action != "observed_ack" for e in entries)


def test_compute_replay_effect_not_captured(tmp_path):
    path = tmp_path / "frames.jsonl"
    FrameLogWriter(path).close()
    effect = compute_replay_effect(path)
    assert effect["captured"] is False
    assert effect["replayed"] is False
    assert effect["actual_delay_s"] is None
    assert effect["original_ack"] is None
    assert effect["replay_ack"] is None


# -- draw_replay_params -- #


def test_draw_replay_params_within_ranges():
    for seed in (1, 2, 3, 100, 20261006):
        p = draw_replay_params(seed)
        assert REPLAY_RANGES["replay_delay_s"][0] <= p.replay_delay_s < REPLAY_RANGES["replay_delay_s"][1]
        assert p.trial_seed == seed


def test_draw_replay_params_deterministic_repeat():
    assert draw_replay_params(42, 3) == draw_replay_params(42, 3)


def test_draw_replay_params_trial_seed_is_seed_plus_trial_index():
    p = draw_replay_params(100, trial_index=3)
    assert p.trial_seed == 103 and p.trial_index == 3


# =========================================================================== #
# detector fields never touched
# =========================================================================== #


def test_detector_fields_never_touched_by_any_of_these_attacks():
    for a in (_fresh_drop(), _fresh_delay(), _fresh_replay()):
        assert not hasattr(a, "detector_decision")
        assert not hasattr(a, "time_to_detection_s")
