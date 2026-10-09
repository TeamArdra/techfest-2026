"""Serial MAVLink transport: stream framer, reader thread, reconnect, virtual-port tests.

No hardware and no PX4. Three layers:

* ``MavlinkStreamFramer`` is pure -- tested directly (partial frames, bursts, garbage,
  false magic bytes, CRC failures, bounded memory, chunking invariance).
* ``SerialMavlinkTransport`` with a scripted fake port (``serial_factory``) -- deterministic
  disconnect / reconnect / stale-partial / overflow / shutdown behaviour.
* REAL pyserial over a virtual port: ``socket://`` (a loopback TCP server standing in for a
  serial device; works on every OS, including this Windows host) and, on POSIX only, a real
  PTY pair. The PTY tests are skipped on Windows -- ``pty`` does not exist there -- so on a
  Windows-only run the PTY code path is NOT exercised; ``socket://`` covers the same
  transport code through pyserial's real ``Serial`` API, but not a termios tty.
"""

from __future__ import annotations

import itertools
import os
import random
import socket
import sys
import threading
import time

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

from aegisflight.sources.mavlink_live import (
    PX4_SITL_EXTRA_CRC,
    LiveMavlinkSource,
    MavlinkFrameParser,
    _load_dialect,
    _x25,
    frame_ticks,
)
from aegisflight.sources.mavlink_serial import (
    ALLOWED_URL_SCHEMES,
    MAX_FRAME_BYTES,
    MAX_READ_BYTES_LIMIT,
    MAX_TRACKED_UNVERIFIABLE_IDS,
    MavlinkStreamFramer,
    SerialMavlinkTransport,
    _crc_x25,
)

pytest.importorskip("serial", reason="pyserial not installed (pip install 'aegisflight[serial]')")

#: Hard upper bound on CRC steps per input byte. Every failed candidate drops exactly one byte,
#: so candidates evaluated <= bytes fed; one candidate costs at most v2 header(10) + payload(255)
#: = 265 steps (the header's 9 non-magic bytes + payload + the crc_extra byte). A WORK bound,
#: not a wall-clock or real-time claim.
CRC_STEPS_PER_BYTE_CAP = 265

# --------------------------------------------------------------------------- #
# frame builders
# --------------------------------------------------------------------------- #


def _mk(sysid: int = 3, compid: int = 1, seq: int = 0, dialect=mav2):
    m = dialect.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return m


def hb(seq: int = 0, sysid: int = 3) -> bytes:
    m = _mk(sysid, 1, seq)
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, 12, 0x80, 0, 4).pack(m))


def att(seq: int = 0, sysid: int = 3) -> bytes:
    m = _mk(sysid, 1, seq)
    return bytes(m.attitude_encode(1000, 0.1, -0.2, 1.5, 0.0, 0.0, 0.0).pack(m))


def gpi(seq: int = 0, sysid: int = 3) -> bytes:
    m = _mk(sysid, 1, seq)
    return bytes(m.global_position_int_encode(1000, 473977418, 85455940, 488000, 12000,
                                              10, -20, 30, 9000).pack(m))


def v1_hb(seq: int = 0) -> bytes:
    m = _mk(2, 5, seq, dialect=mav1)
    return bytes(m.heartbeat_encode(1, 12, 0, 0, 4).pack(m))


def signed_hb(seq: int = 0) -> bytes:
    m = _mk(3, 1, seq)
    m.signing.secret_key = bytes(32)
    m.signing.sign_outgoing = True
    m.signing.link_id = 0
    m.signing.timestamp = 1000
    return bytes(m.heartbeat_encode(1, 12, 0, 0, 4).pack(m))


def raw_v2(msgid: int, payload: bytes = b"\x01\x02\x03", seq: int = 0, sysid: int = 3,
           crc_extra: int | None = None) -> bytes:
    """Hand-built MAVLink 2 frame; CRC valid only if ``crc_extra`` is given."""
    head = bytes([0xFD, len(payload), 0, 0, seq, sysid, 1]) + msgid.to_bytes(3, "little")
    body = head + payload
    if crc_extra is None:
        return body + b"\xaa\xbb"
    return body + _x25(bytes([crc_extra]), _x25(body[1:])).to_bytes(2, "little")


def frame_stream(n: int) -> list[bytes]:
    makers = (hb, att, gpi)
    return [makers[i % 3](i % 256) for i in range(n)]


def unknown_v1_id() -> int:
    from aegisflight.sources.mavlink_live import _load_dialect

    known = _load_dialect().mavlink_map
    return next(i for i in range(256) if i not in known)


# --------------------------------------------------------------------------- #
# MavlinkStreamFramer
# --------------------------------------------------------------------------- #


def test_framer_whole_frame_roundtrip():
    f = MavlinkStreamFramer()
    fr = hb(5)
    assert f.feed(fr) == [fr]
    assert (f.frames_out, f.garbage_bytes, f.crc_rejects, f.pending_bytes) == (1, 0, 0, 0)


def test_framer_partial_frame_waits_then_completes_byte_by_byte():
    f = MavlinkStreamFramer()
    fr = gpi(9)
    got: list[bytes] = []
    for i, b in enumerate(fr):
        out = f.feed(bytes([b]))
        if i < len(fr) - 1:
            assert out == [] and f.pending_bytes == i + 1
        got += out
    assert got == [fr] and f.pending_bytes == 0 and f.garbage_bytes == 0


def test_framer_multiple_mixed_frames_in_one_read():
    frames = [hb(0), v1_hb(1), signed_hb(2), att(3), gpi(4)]
    assert len(frames[2]) == len(hb()) + 13  # signed: 13-byte signature counted in the length
    f = MavlinkStreamFramer()
    assert f.feed(b"".join(frames)) == frames
    assert f.pending_bytes == 0 and f.crc_rejects == 0 and f.garbage_bytes == 0


def test_framer_garbage_prefix_and_between_frames_resyncs_and_counts():
    a, b = hb(1), att(2)
    f = MavlinkStreamFramer()
    out = f.feed(b"\x01\x02\x03" + a + b"\x00" * 5 + b)
    assert out == [a, b]
    assert f.garbage_bytes == 8
    assert f.resync_events == 2  # one per garbage RUN, not per byte
    assert f.crc_rejects == 0


def test_framer_false_magic_does_not_swallow_following_frames():
    """A stray 0xFD claiming a 200-byte payload must not eat the real frames behind it."""
    real = [att(i) for i in range(8)]  # 8 * 40 bytes > the 212-byte false candidate
    f = MavlinkStreamFramer()
    out = f.feed(bytes([0xFD, 200, 0, 0]) + b"".join(real))
    assert out == real
    # this candidate's id (bytes 7..9 of the "header") is outside the dialect: unverifiable,
    # not a CRC failure -- the two counters must not be conflated
    assert f.unverifiable_rejects >= 1 and f.crc_rejects == 0 and f.garbage_bytes >= 4


def test_framer_stale_false_candidate_is_broken_by_flush():
    real = [hb(0), hb(1)]
    f = MavlinkStreamFramer()
    assert f.feed(bytes([0xFD, 200, 0, 0]) + b"".join(real)) == []  # still waiting for 212 bytes
    assert f.pending_bytes > 0
    assert f.flush_stale() == real
    assert f.partial_timeouts == 1 and f.pending_bytes == 0
    assert f.flush_stale() == [] and f.partial_timeouts == 1  # nothing pending: no-op


def test_framer_corrupt_crc_frame_dropped_next_frame_recovered():
    bad = bytearray(hb(1))
    bad[-1] ^= 0xFF
    good = att(2)
    f = MavlinkStreamFramer()
    assert f.feed(bytes(bad) + good) == [good]
    assert f.crc_rejects == 1


def test_framer_unknown_incompat_flags_dropped():
    bad = bytearray(hb(1))
    bad[2] = 0x02  # unknown incompat flag
    good = hb(2)
    f = MavlinkStreamFramer()
    assert f.feed(bytes(bad) + good) == [good]
    # refused on the header alone: not a CRC failure, not an unverifiable id
    assert f.header_rejects == 1 and f.crc_rejects == 0 and f.unverifiable_rejects == 0


def test_framer_refuses_unverifiable_ids_by_default():
    """An id with no crc_extra cannot be CRC-checked, so it is not presented as a frame."""
    f = MavlinkStreamFramer()
    frame = raw_v2(60001, crc_extra=77)  # perfectly well-formed, but the framer cannot know that
    assert f.feed(frame) == []
    assert f.unverifiable_rejects == 1 and f.unverified_accepted == 0 and f.crc_rejects == 0
    assert f.unverifiable_ids == {60001: 1}
    assert f.frames_out == 0 and f.pending_bytes == 0
    # a run of known frames right after it is untouched
    real = [hb(0), att(1), gpi(2)]
    assert f.feed(b"".join(real)) == real


def test_framer_opt_in_unverified_mode_is_header_plausibility_only():
    f = MavlinkStreamFramer(accept_unverified_ids=True)
    ok = raw_v2(60001)  # CRC bytes are junk and nothing checks them
    assert f.feed(ok) == [ok]
    assert f.unverified_accepted == 1 and f.crc_rejects == 0
    assert f.feed(raw_v2(60001, sysid=0)) == []  # sysid 0 refused
    v1 = bytes([0xFE, 3, 0, 3, 1, unknown_v1_id()]) + b"\x01\x02\x03" + b"\xaa\xbb"
    assert f.feed(v1) == []  # every v1 id is in the dialect: an unknown one is garbage
    assert f.feed(raw_v2(0x030000)) == []  # id above 0xFFFF: implausible, never a real message
    bad_compid = bytearray(raw_v2(60001))
    bad_compid[6] = 0
    assert f.feed(bytes(bad_compid)) == []
    bad_compat = bytearray(raw_v2(60001))
    bad_compat[3] = 1
    assert f.feed(bytes(bad_compat)) == []
    assert f.unverified_accepted == 1 and f.unverifiable_rejects == 5


def test_framer_extra_crc_makes_unknown_id_verifiable():
    f = MavlinkStreamFramer(extra_crc={60001: 77})
    good = raw_v2(60001, crc_extra=77)
    assert f.feed(good) == [good]
    assert f.unverifiable_rejects == 0 and f.unverified_accepted == 0  # verified, not "unverified"
    assert f.feed(raw_v2(60001, crc_extra=78)) == []  # wrong crc_extra: CRC failure
    assert f.crc_rejects == 1 and f.unverifiable_rejects == 0
    assert f.feed(raw_v2(60002, crc_extra=77)) == []  # a different id has no entry: unverifiable
    assert f.unverifiable_rejects == 1


def test_framer_chunking_invariance_random_splits():
    rng = random.Random(7)
    frames = frame_stream(60)
    stream = b"".join(frames[:20]) + b"\x13\x37" + b"".join(frames[20:])
    whole = MavlinkStreamFramer().feed(stream)
    assert whole == frames
    for _ in range(30):
        f, out, i = MavlinkStreamFramer(), [], 0
        while i < len(stream):
            n = rng.randint(1, 97)
            out += f.feed(stream[i : i + n])
            i += n
        assert out == frames and f.pending_bytes == 0


def test_framer_fuzz_never_raises_and_memory_stays_bounded():
    rng = random.Random(1234)
    magic_heavy = bytes([0xFD, 0xFE, 0xFD, 0xFD, 0xFF, 0x00, 0x01, 0xC8])
    f = MavlinkStreamFramer()
    for _ in range(400):
        chunk = bytes(rng.choice(magic_heavy) if rng.random() < 0.6 else rng.randrange(256)
                      for _ in range(rng.randint(0, 600)))
        f.feed(chunk)
        assert f.pending_bytes < MAX_FRAME_BYTES
    f.flush_stale()
    assert f.pending_bytes < MAX_FRAME_BYTES
    assert f.crc_bytes_checked <= CRC_STEPS_PER_BYTE_CAP * f.bytes_in


def test_framer_reset_drops_partial_and_reports_size():
    f = MavlinkStreamFramer()
    f.feed(hb(0)[:7])
    assert f.pending_bytes == 7
    assert f.reset() == 7 and f.pending_bytes == 0
    fr = hb(1)
    assert f.feed(fr) == [fr]


def test_framer_output_is_clean_input_for_the_existing_parser():
    frames = frame_stream(30)
    f = MavlinkStreamFramer()
    out = f.feed(b"\x00\x01" + b"".join(frames[:15]) + b"\xfd\xc8\x00" + b"".join(frames[15:]))
    assert out == frames
    p = MavlinkFrameParser()
    envs = [e for fr in out for e in p.parse(fr, 0.0)]
    assert len(envs) == 30 and p.stats.bad_frames == 0
    assert [e.seq for e in envs] == [i % 256 for i in range(30)]


# --------------------------------------------------------------------------- #
# M1: corrupted headers / inserted bytes must not fabricate frames
# --------------------------------------------------------------------------- #


def drain(f: MavlinkStreamFramer, data: bytes) -> list[bytes]:
    """Feed ``data`` then let the idle-line flush run until nothing is pending."""
    out = f.feed(data)
    while f.pending_bytes:
        out += f.flush_stale()
    return out


def sources_of(frames: list[bytes]) -> set[tuple[int, int]]:
    p = MavlinkFrameParser()
    return {(e.sysid, e.compid) for fr in frames for e in p.parse(fr, 0.0)}


def is_subsequence(sub: list[bytes], full: list[bytes]) -> bool:
    it = iter(full)
    return all(any(x == y for y in it) for x in sub)


def test_crc_table_is_bit_identical_to_the_reference_x25():
    rng = random.Random(99)
    for n in (0, 1, 2, 7, 64, 255, 264):
        for _ in range(20):
            data = bytes(rng.randrange(256) for _ in range(n))
            init = rng.choice((0xFFFF, 0, rng.randrange(0x10000)))
            assert _crc_x25(data, init) == _x25(data, init)
    # chained exactly as the framer uses it (payload CRC, then the crc_extra byte)
    assert _crc_x25(b"\x4d", _crc_x25(b"\x01\x02\x03")) == _x25(b"\x4d", _x25(b"\x01\x02\x03"))


@pytest.mark.parametrize("bit", range(24))
def test_msgid_bit_flip_never_yields_a_frame_and_neighbours_survive(bit):
    """The review's M1: one flipped bit in a frame's id field turns it into another id. Known
    ids fail the CRC (different crc_extra); unknown ids cannot be verified. Neither may emerge
    as a frame, and the frames on either side must be unaffected."""
    before, victim, after = hb(0), att(1), gpi(2)
    bad = bytearray(victim)
    bad[7 + bit // 8] ^= 1 << (bit % 8)
    f = MavlinkStreamFramer()
    out = drain(f, before + bytes(bad) + after)
    assert out == [before, after]
    assert f.crc_rejects + f.unverifiable_rejects >= 1
    assert f.unverified_accepted == 0
    assert sources_of(out) == {(3, 1)}  # no phantom source can reach the rogue-source logic


def test_msgid_bit_flip_in_v1_frames_never_yields_a_frame():
    for bit in range(8):
        bad = bytearray(v1_hb(1))
        bad[5] ^= 1 << bit
        f = MavlinkStreamFramer()
        good = v1_hb(2)
        assert drain(f, bytes(bad) + good) == [good]


def test_opt_in_unverified_mode_does_accept_a_corrupted_id_documented_limitation():
    """Characterisation, not an endorsement: with accept_unverified_ids=True a flipped high id
    bit survives as a plausible frame carrying a garbage payload. That is why it is off."""
    bad = bytearray(att(1))
    bad[8] ^= 0x80  # id 30 -> 30 + 0x8000, outside the dialect
    f = MavlinkStreamFramer(accept_unverified_ids=True)
    out = f.feed(bytes(bad))
    assert out == [bytes(bad)] and f.unverified_accepted == 1
    assert MavlinkStreamFramer().feed(bytes(bad)) == []  # default: refused


@pytest.mark.parametrize("insert", [0x00, 0x01, 0xFD, 0xFE, 0xFF])
def test_inserted_byte_never_fabricates_a_frame_and_neighbours_survive(insert):
    before, victim, after, tail = hb(0), att(1), gpi(2), hb(3)
    originals = [before, victim, after, tail]
    for at in range(1, len(victim)):  # strictly inside the victim frame
        mutated = victim[:at] + bytes([insert]) + victim[at:]
        stream = before + mutated + after + tail
        f = MavlinkStreamFramer()
        out = drain(f, stream)
        # inserting a copy of the leading magic byte right after it is just one garbage byte in
        # front of an intact victim; every other insertion destroys the victim
        intact = mutated == bytes([insert]) + victim
        want = originals if intact else [before, after, tail]
        assert out == want, f"insert 0x{insert:02x} at {at}"
        assert all(fr in originals for fr in out)
        assert sources_of(out) == {(3, 1)}
    # inserted byte BETWEEN frames: all four frames survive, the byte is counted as garbage
    f = MavlinkStreamFramer()
    assert drain(f, before + victim + bytes([insert]) + after + tail) == originals


@pytest.mark.parametrize(
    "prefix",
    [
        pytest.param(bytes([0xFD, 255, 0, 0]), id="v2-max-len-candidate"),
        pytest.param(bytes([0xFD, 9, 0x02, 0]), id="v2-unknown-incompat-bit"),
        pytest.param(bytes([0xFD, 9, 0x80, 0]), id="v2-unknown-incompat-high-bit"),
        pytest.param(bytes([0xFD, 0, 0, 0, 5, 0, 0, 0xE1, 0xEA, 0x00]), id="v2-sysid0-compid0"),
        pytest.param(bytes([0xFD, 4, 0, 1, 5, 3, 1, 0x01, 0x00, 0x03]), id="v2-compat-set-id-above-0xffff"),
        pytest.param(bytes([0xFE, 255, 0, 3, 1]), id="v1-max-len-truncated-header"),
        pytest.param(bytes([0xFE, 3, 0, 3, 1, 0xFF]) + b"\x01\x02\x03\xaa\xbb", id="v1-unknown-id"),
        pytest.param(bytes([0xFD, 0x40, 0]), id="v2-header-cut-short"),
        pytest.param(bytes([0xFD] * 12), id="run-of-magic-bytes"),
    ],
)
def test_malformed_candidate_headers_do_not_block_or_corrupt_following_frames(prefix):
    real = [hb(i) if i % 2 else att(i) for i in range(12)]  # > 265 bytes behind the prefix
    f = MavlinkStreamFramer()
    out = drain(f, prefix + b"".join(real))
    assert out == real
    assert f.frames_out == len(real)
    assert sources_of(out) == {(3, 1)}


def test_seeded_corruption_campaign_emits_only_original_frames_in_order():
    """Deterministic campaign (seeded): bit flips, insertions and deletions at random places in a
    longer stream, fed in random chunks. Nothing may be emitted that was not sent (no phantom
    frame, no duplicate, no reordering) and no phantom source may appear. A 16-bit CRC makes a
    false accept a ~1-in-65k event per corrupted known-id candidate; with this fixed seed the
    campaign is deterministic, so this is a regression test, not a proof of impossibility."""
    rng = random.Random(20261009)
    originals = frame_stream(60)
    stream = bytearray(b"".join(originals))
    for _ in range(40):
        at = rng.randrange(len(stream))
        kind = rng.randrange(3)
        if kind == 0:
            stream[at] ^= 1 << rng.randrange(8)
        elif kind == 1:
            stream.insert(at, rng.randrange(256))
        else:
            del stream[at]
    f = MavlinkStreamFramer()
    out, i = [], 0
    while i < len(stream):
        n = rng.randint(1, 120)
        out += f.feed(bytes(stream[i : i + n]))
        i += n
    while f.pending_bytes:
        out += f.flush_stale()
    assert is_subsequence(out, originals)
    assert len(out) == len(set(out))
    assert sources_of(out) <= {(3, 1)}
    assert len(out) >= 20  # corruption hit at most 40 of 60 frames: most of the stream survives
    assert f.crc_bytes_checked <= CRC_STEPS_PER_BYTE_CAP * f.bytes_in


def test_unverifiable_id_tracking_is_bounded():
    f = MavlinkStreamFramer()
    n_ids = MAX_TRACKED_UNVERIFIABLE_IDS + 40
    for i in range(n_ids):
        f.feed(raw_v2(40000 + i, crc_extra=1))
    assert len(f.unverifiable_ids) == MAX_TRACKED_UNVERIFIABLE_IDS
    assert f.unverifiable_id_overflow == 40
    assert f.unverifiable_rejects == n_ids


# --------------------------------------------------------------------------- #
# M2: bounded CPU work
# --------------------------------------------------------------------------- #


def test_work_bound_all_0xfe_stream_approaches_but_never_exceeds_the_cap():
    """The densest shape found: every byte is a v1 magic whose header (len 254, id 254 = a known
    v1 id) makes a ~262-byte candidate at EVERY position, so nearly each input byte costs a full
    CRC pass. This, not the 26/43 steps-per-byte shapes below, is the worst case seen; the
    documented cap of 265 steps per input byte must still hold."""
    n = 30_000
    f = MavlinkStreamFramer()
    assert f.feed(b"\xfe" * n) == []
    ratio = f.crc_bytes_checked / f.bytes_in
    assert 240 < ratio <= CRC_STEPS_PER_BYTE_CAP
    assert f.crc_bytes_checked <= CRC_STEPS_PER_BYTE_CAP * f.bytes_in
    assert f.pending_bytes < MAX_FRAME_BYTES and f.frames_out == 0


def test_work_bound_on_densely_overlapping_false_v1_candidates():
    """Adversarial: a known id (HEARTBEAT) with len 255 repeated every 6 bytes, so a long false
    candidate starts at every sixth position (a dense shape, but not the densest: see the
    all-0xFE test)."""
    unit = bytes([0xFE, 255, 0, 1, 1, 0])
    f = MavlinkStreamFramer()
    out = f.feed(unit * 2000)
    assert out == [] and f.pending_bytes < MAX_FRAME_BYTES
    ratio = f.crc_bytes_checked / f.bytes_in
    assert ratio > 20  # the stream really is adversarial (otherwise the bound proves nothing)
    assert f.crc_bytes_checked <= CRC_STEPS_PER_BYTE_CAP * f.bytes_in
    assert f.crc_rejects > 0 and f.unverifiable_rejects == 0


def test_work_bound_on_densely_overlapping_false_v2_candidates():
    unit = bytes([0xFD, 255, 0, 0, 0, 1, 1, 0, 0, 0])  # v2 HEARTBEAT id, len 255, every 10 bytes
    f = MavlinkStreamFramer()
    assert f.feed(unit * 1500) == []
    assert f.crc_bytes_checked / f.bytes_in > 15
    assert f.crc_bytes_checked <= CRC_STEPS_PER_BYTE_CAP * f.bytes_in
    assert f.pending_bytes < MAX_FRAME_BYTES


def test_unknown_id_candidates_cost_no_crc_work_at_all():
    """Early reject: the same dense shape with an id that has no crc_extra never reaches the CRC."""
    unit = bytes([0xFD, 255, 0, 0, 0, 1, 1, 0xE1, 0xEA, 0x00])  # id 60129: outside the dialect
    f = MavlinkStreamFramer()
    assert f.feed(unit * 1500) == []
    assert f.crc_bytes_checked == 0
    assert f.unverifiable_rejects > 100 and f.pending_bytes < MAX_FRAME_BYTES


def test_random_garbage_costs_little_crc_work_and_bounded_memory():
    rng = random.Random(5)
    f = MavlinkStreamFramer()
    total = 0
    for _ in range(50):
        chunk = rng.randbytes(4096)
        total += len(chunk)
        f.feed(chunk)
        assert f.pending_bytes < MAX_FRAME_BYTES
    assert f.bytes_in == total
    assert f.crc_bytes_checked <= total  # measured ~0.2 steps/byte for random data; 5x headroom


def test_large_single_feed_is_linear_not_quadratic_in_bookkeeping():
    """200 KB of garbage with no magic byte, in ONE feed: the consumed prefix is cut once."""
    f = MavlinkStreamFramer()
    assert f.feed(bytes(200_000)) == []
    assert f.garbage_bytes == 200_000 and f.pending_bytes == 0 and f.resync_events == 1


class _CountingBuf(bytearray):
    """bytearray that counts what ``find`` does: calls, bytes examined (up to the hit, or to the
    end on a miss) and misses. A work counter, not a clock."""

    def __init__(self, *a):
        super().__init__(*a)
        self.calls = 0
        self.examined = 0
        self.misses = 0

    def find(self, sub, start=0, end=None):  # noqa: D401 - signature mirrors bytearray.find
        hit = super().find(sub, start)
        self.calls += 1
        self.examined += (len(self) if hit < 0 else hit + 1) - start
        self.misses += hit < 0
        return hit


def test_scan_alternating_garbage_and_magic_is_linear_not_quadratic():
    """The repeating 00 FD 00 02: every FD is a header-rejected candidate (incompat 0x02) and
    every 00 starts a garbage run that must find the next magic. With an uncached search the
    absent 0xFE made each of those runs rescan to the end of the buffer (~n^2/8 bytes)."""
    n_units = 16_384
    data = bytes([0x00, 0xFD, 0x00, 0x02]) * n_units
    n = len(data)
    assert n == MAX_READ_BYTES_LIMIT  # the largest single read the transport allows
    f = MavlinkStreamFramer()
    f._buf = _CountingBuf()
    assert f.feed(data) == []
    buf = f._buf
    # the pattern really exercises the repeated-search branch (not just a run of zero bytes) ...
    # (the last two FDs sit < 10 bytes from the end of the buffer: their headers are incomplete,
    # so they wait for more data instead of being rejected)
    assert f.header_rejects == n_units - 2
    assert f.garbage_bytes + f.pending_bytes == n and f.pending_bytes < 10
    assert buf.calls >= n_units
    naive_examined = n_units * n // 2  # one end-of-buffer rescan per garbage run, on average
    assert naive_examined > 100 * n
    # ... and still costs O(n): the absent 0xFE is searched for once, every hit is found by a short scan
    assert buf.misses <= 2
    assert buf.examined <= 4 * n


def test_large_single_read_of_valid_mixed_frames_and_split_tail():
    frames = frame_stream(1200) + [v1_hb(7), signed_hb(8), v1_hb(9)]
    blob = b"".join(frames)
    assert len(blob) > 16_384
    cut = len(blob) - 5  # the last frame arrives split
    f = MavlinkStreamFramer()
    out = f.feed(blob[:cut])
    assert out == frames[:-1] and f.pending_bytes == len(frames[-1]) - 5
    assert f.feed(blob[cut:]) == [frames[-1]]
    assert f.garbage_bytes == 0 and f.crc_rejects == 0 and f.unverifiable_rejects == 0


# --------------------------------------------------------------------------- #
# PX4 out-of-dialect ids with provenance-verified crc_extra
# --------------------------------------------------------------------------- #

#: One genuine frame per id, copied from data/sitl/raw/benign_001.tlog (benign PX4 SITL capture,
#: PX4 v1.18.0-rc1-27-gc239c63807, sysid 3 / compid 1). Real bytes, so these tests do not need the
#: git-ignored tlog. All seven verify under PX4_SITL_EXTRA_CRC (provenance: see that constant).
PX4_REAL_FRAMES: dict[int, bytes] = {
    8: bytes.fromhex("fd150000cc0301080000c0f09d0100000000eb3b000000000000da21000001889b"),
    290: bytes.fromhex("fd2e0000bd0301220100c0f09d0100000000000000000000000000000000000000000000000000000000000088138813881388130004000fce2c"),
    291: bytes.fromhex("fd040000be0301230100c0f09d019c8b"),
    380: bytes.fromhex("fd140000a803017c010000000000ffffffffffffffffffffffffffffffff2619"),
    410: bytes.fromhex("fd1e0000df03019a0100e093a8019c6700001b00000088000000100080000000b03a7f80b03a7f80fe55"),
    411: bytes.fromhex("fd010000d703019b01001fdddf"),
    514: bytes.fromhex("fd340000c003010202000000c07f0000c07f0000c07f0000c07f0000c07f0000c07f0000c07f0000c07f0000c07f01010000010101000001000000010001ddea"),
}


def test_px4_extra_crc_table_covers_exactly_the_out_of_dialect_vectors():
    known = _load_dialect().mavlink_map
    assert set(PX4_SITL_EXTRA_CRC) == set(PX4_REAL_FRAMES) == {8, 290, 291, 380, 410, 411, 514}
    for mid, fr in PX4_REAL_FRAMES.items():
        assert mid not in known  # genuinely outside pymavlink's dialect
        assert fr[7] | fr[8] << 8 | fr[9] << 16 == mid and len(fr) == 12 + fr[1]


@pytest.mark.parametrize("mid", sorted(PX4_REAL_FRAMES))
def test_px4_real_frames_are_refused_by_default_and_verified_with_extra_crc(mid):
    fr = PX4_REAL_FRAMES[mid]
    f = MavlinkStreamFramer()
    assert f.feed(fr) == [] and f.unverifiable_rejects == 1 and f.crc_rejects == 0
    f = MavlinkStreamFramer(extra_crc=PX4_SITL_EXTRA_CRC)
    assert f.feed(fr) == [fr]
    # verified, not "unverified": no CRC bypass, nothing counted as unverifiable or unverified
    assert (f.unverifiable_rejects, f.unverified_accepted, f.crc_rejects) == (0, 0, 0)
    assert f.crc_bytes_checked > 0


@pytest.mark.parametrize("mid", sorted(PX4_REAL_FRAMES))
def test_px4_real_frame_corruption_is_rejected_and_neighbours_survive(mid):
    """Every single-bit flip anywhere in a genuine frame (header, payload, CRC): the corrupted
    frame is never emitted, and the intact frame after it always is."""
    fr, good = PX4_REAL_FRAMES[mid], hb(5)
    for bit in range(8 * len(fr)):
        bad = bytearray(fr)
        bad[bit // 8] ^= 1 << (bit % 8)
        f = MavlinkStreamFramer(extra_crc=PX4_SITL_EXTRA_CRC)
        out = drain(f, bytes(bad) + good)
        assert bytes(bad) not in out, f"id {mid} bit {bit}"
        assert out == [good], f"id {mid} bit {bit}"


def test_px4_wrong_extra_crc_is_rejected_not_trusted():
    fr = PX4_REAL_FRAMES[290]
    f = MavlinkStreamFramer(extra_crc={290: (PX4_SITL_EXTRA_CRC[290] + 1) & 0xFF})
    assert f.feed(fr) == [] and f.crc_rejects == 1 and f.unverifiable_rejects == 0


def test_extra_crc_never_overrides_a_dialect_id():
    f = MavlinkStreamFramer(extra_crc={0: 99, 30: 99})  # HEARTBEAT and ATTITUDE are in the dialect
    frames = [hb(0), att(1)]
    assert f.feed(b"".join(frames)) == frames


def test_extra_crc_passes_through_frame_ticks_and_the_parser_verifies_it():
    from aegisflight.sources.mavlink_live import LiveStats

    real = [PX4_REAL_FRAMES[m] for m in sorted(PX4_REAL_FRAMES)]
    pairs = [(i * 0.1, fr) for i, fr in enumerate(real + [hb(0)])]

    def run(extra):
        st = LiveStats()
        names = [m.msgname for t in frame_ticks(pairs, stats=st, extra_crc=extra)
                 for m in t.messages]
        return st, names

    st, names = run(None)  # default parser: header-sanity only, counted as unverified
    assert st.unverified_frames == 7 and st.bad_frames == 0 and "MSG_8" in names
    st, names = run(PX4_SITL_EXTRA_CRC)  # verified by the parser too
    assert st.unverified_frames == 0 and st.bad_frames == 0 and st.frames_received == 8
    assert sorted(n for n in names if n.startswith("MSG_")) == sorted(f"MSG_{m}" for m in PX4_REAL_FRAMES)
    bad = bytearray(PX4_REAL_FRAMES[291])
    bad[-1] ^= 0x01  # corrupt the CRC: the verifying parser drops it
    st = LiveStats()
    list(frame_ticks([(0.0, bytes(bad)), (0.1, hb(0))], stats=st, extra_crc=PX4_SITL_EXTRA_CRC))
    assert st.bad_frames == 1 and st.frames_received == 1


def test_live_source_over_serial_carries_extra_crc_end_to_end():
    real = [PX4_REAL_FRAMES[m] for m in sorted(PX4_REAL_FRAMES)]
    frames = real + [hb(0), att(1), gpi(2)] * 3
    results = {}
    for label, src_extra in (("verified", PX4_SITL_EXTRA_CRC), ("parser-default", None)):
        tr, _ = make_tr([FakePort([b"".join(frames)])], extra_crc=PX4_SITL_EXTRA_CRC)
        src = LiveMavlinkSource(tr, sample_rate_hz=10.0, max_ticks=4, extra_crc=src_extra)
        try:
            names = [m.msgname for t in src.stream() for m in t.messages]
        finally:
            src.close()
        results[label] = (src.stats, names)
        assert sum(n.startswith("MSG_") for n in names) == 7  # the transport delivered all seven
    assert results["verified"][0]["unverified_frames"] == 0
    assert results["parser-default"][0]["unverified_frames"] == 7
    assert results["verified"][0]["bad_frames"] == results["parser-default"][0]["bad_frames"] == 0


# --------------------------------------------------------------------------- #
# transport helpers
# --------------------------------------------------------------------------- #


def wait_for(pred, timeout: float = 5.0, what: str = "condition") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.005)
    raise AssertionError(f"timed out waiting for {what}")


def collect(tr: SerialMavlinkTransport, n: int, timeout: float = 5.0) -> list[tuple[int, bytes]]:
    got: list[tuple[int, bytes]] = []
    wait_for(lambda: (got.extend(tr.poll()), len(got) >= n)[1], timeout, f"{n} frames")
    return got


class FakePort:
    """Scripted serial port. Script items: bytes (one read returns them), None (timeout),
    or an Exception (raised by read). An empty script behaves like an idle line (timeouts)."""

    def __init__(self, script: list | None = None) -> None:
        self.script = list(script or [])
        self.lock = threading.Lock()
        self.closed = False
        self.written: list[bytes] = []
        self.fail_write: Exception | None = None

    def push(self, *items) -> None:
        with self.lock:
            self.script.extend(items)

    @property
    def in_waiting(self) -> int:
        with self.lock:
            return len(self.script[0]) if self.script and isinstance(self.script[0], bytes) else 0

    def read(self, size: int = 1) -> bytes:
        with self.lock:
            item = self.script.pop(0) if self.script else None
        if isinstance(item, BaseException):
            raise item
        if item is None:
            time.sleep(0.002)
            return b""
        if len(item) > size:
            with self.lock:
                self.script.insert(0, item[size:])
            return item[:size]
        return item

    def write(self, data: bytes) -> int:
        if self.fail_write is not None:
            raise self.fail_write
        self.written.append(data)
        return len(data)

    def close(self) -> None:
        self.closed = True


def make_tr(ports: list, **kw) -> tuple[SerialMavlinkTransport, list[int]]:
    """Transport whose factory hands out ``ports`` in order (an Exception item = open fails)."""
    calls = [0]
    it = iter(ports)
    lock = threading.Lock()

    def factory():
        with lock:
            calls[0] += 1
            item = next(it, OSError("no more ports"))
        if isinstance(item, BaseException):
            raise item
        return item

    kw.setdefault("reconnect_interval_s", 0.01)
    return SerialMavlinkTransport("FAKE", serial_factory=factory, **kw), calls


# --------------------------------------------------------------------------- #
# transport: framing, stamps, counters
# --------------------------------------------------------------------------- #


def test_transport_delivers_whole_frames_from_fragments_and_bursts():
    frames = frame_stream(9)
    blob = b"".join(frames)
    port = FakePort([blob[:5], blob[5:61], blob[61:62], blob[62:]])
    tr, _ = make_tr([port])
    with tr:
        got = collect(tr, 9)
    assert [d for _, d in got] == frames
    assert tr.datagrams_received == 9 and tr.bytes_received == len(blob)
    assert tr.reads >= 4 and tr.garbage_bytes == 0 and tr.crc_rejects == 0


def test_transport_stamps_are_per_completing_read_and_monotonic():
    a, b, c = hb(0), att(1), gpi(2)
    ticker = itertools.count(1_000_000, 1_000_000)
    port = FakePort([a + b, c[:10], c[10:]])  # a,b complete in read 1; c in read 3
    tr, _ = make_tr([port], clock_ns=lambda: next(ticker))
    with tr:
        got = collect(tr, 3)
    stamps = [s for s, _ in got]
    assert stamps[0] == stamps[1]  # same read -> same stamp (burst spacing is NOT recoverable)
    assert stamps[2] > stamps[1]  # completed by a later read -> later stamp
    assert tr.max_frames_per_read == 2


def test_transport_garbage_is_counted_and_resynced():
    a, b = hb(1), att(2)
    port = FakePort([b"\x00\x01\x02" + a, b"\xaa" * 7 + b])
    tr, _ = make_tr([port])
    with tr:
        got = collect(tr, 2)
    assert [d for _, d in got] == [a, b]
    assert tr.garbage_bytes == 10 and tr.resync_events == 2


def test_transport_stale_partial_is_flushed_after_timeout():
    real = [hb(0), hb(1)]
    port = FakePort([bytes([0xFD, 200, 0, 0]) + b"".join(real)])  # false 212-byte candidate, then idle
    tr, _ = make_tr([port], partial_timeout_s=0.05)
    with tr:
        got = collect(tr, 2)
    assert [d for _, d in got] == real
    assert tr.partial_timeouts == 1


def test_transport_stamp_is_the_resolving_read_not_the_read_that_delivered_the_last_byte():
    """Documents the real stamp semantics: a whole, valid frame queued behind a still-incomplete
    false candidate is held, and is stamped by the read that RESOLVES the candidate (here read 2),
    even though its last byte arrived in read 1."""
    real = hb(0)
    ticks = itertools.count(1)

    def clock() -> int:  # deterministic per-read stamps: only the reader thread advances it
        return next(ticks) * 1_000_000 if threading.current_thread().name == "mavlink-serial-rx" else 0

    # read 1: false 212-byte candidate header + a complete real frame; read 2: the candidate's tail
    port = FakePort([bytes([0xFD, 200, 0, 0]) + real, bytes(212 - 4 - len(real))])
    tr, _ = make_tr([port], clock_ns=clock)
    with tr:
        got = collect(tr, 1)
    assert got == [(2_000_000, real)]  # stamped by read 2, not read 1 (1_000_000)


def test_transport_bounded_queue_counts_overflow_and_releases_byte_budget():
    frames = frame_stream(20)
    port = FakePort([b"".join(frames)])
    tr, _ = make_tr([port], queue_size=5)
    with tr:
        wait_for(lambda: tr.datagrams_received == 20, what="20 frames read")
        assert tr.dropped_overflow == 15 and tr.queue_high_water == 5
        assert tr.dropped_overflow_bytes == sum(len(f) for f in frames[5:])
        got = tr.poll()
    assert [d for _, d in got] == frames[:5]  # the NEWEST frames are the ones dropped
    assert tr._queued_bytes == 0

    port2 = FakePort([b"".join(frames)])
    tr2, _ = make_tr([port2], max_queue_bytes=100)
    with tr2:
        wait_for(lambda: tr2.datagrams_received == 20, what="20 frames read")
        kept = tr2.poll()
    assert sum(len(d) for _, d in kept) <= 100 and tr2.dropped_overflow == 20 - len(kept)
    assert tr2._queued_bytes == 0


def test_transport_stats_dict_is_complete_and_honest_about_scope():
    tr, _ = make_tr([FakePort([hb(0)])])
    with tr:
        collect(tr, 1)
    s = tr.stats
    for key in ("connected", "reader_running", "bytes_received", "garbage_bytes",
                "resync_events", "header_rejects", "crc_rejects", "unverifiable_rejects",
                "unverified_accepted", "unverifiable_ids", "unverifiable_id_overflow",
                "crc_bytes_checked", "partial_timeouts", "reader_faults", "dropped_overflow",
                "queue_high_water", "max_poll_gap_s", "disconnects", "reconnects",
                "open_failures", "last_error"):
        assert key in s
    assert not any("kernel" in k or "os_drop" in k or "lost" in k for k in s)  # no pretend loss counter


# --------------------------------------------------------------------------- #
# transport: open failure, disconnect, reconnect, shutdown
# --------------------------------------------------------------------------- #


def test_transport_disconnect_discards_partial_and_reconnects():
    first, second = hb(1), att(2)
    p1 = FakePort([first, gpi(3)[:15], OSError("device unplugged")])
    p2 = FakePort([second])
    tr, calls = make_tr([p1, p2])
    with tr:
        got = collect(tr, 2)
        assert [d for _, d in got] == [first, second]  # the cut-off gpi(3) is NOT glued to anything
        wait_for(lambda: tr.connected, what="reconnected")
    assert tr.disconnects == 1 and tr.reconnects == 1 and calls[0] == 2
    assert tr.discarded_on_disconnect_bytes == 15
    assert "device unplugged" in (tr.last_error or "")
    assert p1.closed and p2.closed


def test_transport_start_with_missing_port_retries_until_it_appears():
    fr = hb(4)
    tr, calls = make_tr([OSError("no such device"), OSError("still no"), FakePort([fr])])
    tr.start()  # reconnect=True: does not raise
    try:
        got = collect(tr, 1)
        assert [d for _, d in got] == [fr]
        assert tr.open_failures == 2 and tr.connected
    finally:
        tr.close()


def test_transport_reconnect_disabled_fails_fast_and_stays_down():
    tr, calls = make_tr([OSError("nope")], reconnect=False)
    with pytest.raises(RuntimeError, match="cannot open serial port"):
        tr.start()
    tr.close()

    p = FakePort([hb(0), OSError("gone")])
    tr2, calls2 = make_tr([p], reconnect=False)
    with tr2:
        collect(tr2, 1)
        wait_for(lambda: tr2.disconnects == 1, what="disconnect")
        time.sleep(0.1)
        assert not tr2.connected and calls2[0] == 1  # never reopened
        assert tr2._thread is not None and not tr2._thread.is_alive()


def test_transport_survives_repeated_disconnect_cycles():
    ports = [FakePort([hb(i), OSError(f"drop {i}")]) for i in range(4)] + [FakePort([att(9)])]
    tr, _ = make_tr(ports)
    with tr:
        got = collect(tr, 5)
    assert len(got) == 5 and tr.disconnects == 4 and tr.reconnects == 4


def test_transport_close_is_prompt_idempotent_and_releases_the_port():
    port = FakePort()  # idle line
    tr, _ = make_tr([port])
    tr.start()
    thread = tr._thread
    t0 = time.monotonic()
    tr.close()
    tr.close()
    assert time.monotonic() - t0 < 1.5
    assert port.closed and thread is not None and not thread.is_alive()
    assert tr.poll() == [] and tr.send(b"x") is False
    tr.start()  # start after close is a no-op, not a resurrection
    assert tr._thread is thread


def test_transport_close_interrupts_a_long_reconnect_wait():
    tr, _ = make_tr([OSError("down")], reconnect_interval_s=60.0)
    tr.start()
    time.sleep(0.05)
    t0 = time.monotonic()
    tr.close()
    assert time.monotonic() - t0 < 1.5


def test_transport_send_writes_and_reports_failures():
    port = FakePort()
    tr, _ = make_tr([port])
    with tr:
        assert tr.send(b"\xfd\x00") is True
        assert port.written == [b"\xfd\x00"] and tr.bytes_sent == 2
        port.fail_write = OSError("write failed")
        assert tr.send(b"zz") is False and tr.write_errors == 1
    assert tr.send(b"late") is False


def test_transport_rejects_bad_arguments():
    with pytest.raises(ValueError):
        SerialMavlinkTransport("x", baudrate=0)
    with pytest.raises(ValueError):
        SerialMavlinkTransport("x", read_timeout_s=0)
    with pytest.raises(ValueError):
        SerialMavlinkTransport("x", queue_size=0)
    with pytest.raises(ValueError):
        SerialMavlinkTransport("x", max_queue_bytes=0)
    with pytest.raises(ValueError, match="max_read_bytes"):
        SerialMavlinkTransport("x", max_read_bytes=MAX_READ_BYTES_LIMIT + 1)
    SerialMavlinkTransport("x", max_read_bytes=MAX_READ_BYTES_LIMIT).close()  # the limit itself is fine


@pytest.mark.parametrize("name", ["reconnect_interval_s", "partial_timeout_s", "read_timeout_s"])
@pytest.mark.parametrize("bad", [0, 0.0, -1.0, float("nan"), float("inf")])
def test_transport_rejects_non_positive_or_non_finite_intervals(name, bad):
    with pytest.raises(ValueError, match=name):
        SerialMavlinkTransport("x", **{name: bad})


@pytest.mark.parametrize(
    ("kwargs", "expect_frame"),
    [({}, False), ({"extra_crc": {60001: 77}}, True), ({"accept_unverified_ids": True}, True)],
)
def test_transport_unverified_id_options_reach_the_framer(kwargs, expect_frame):
    fr = raw_v2(60001, crc_extra=77)
    want = 2 if expect_frame else 1
    tr, _ = make_tr([FakePort([fr, hb(0)])], **kwargs)
    with tr:
        wait_for(lambda: tr.datagrams_received >= want, what="frames read")
        got = [d for _, d in tr.poll()]
    assert (fr in got) is expect_frame and hb(0) in got
    if not expect_frame:
        assert tr.unverifiable_rejects == 1 and tr.unverifiable_ids == {60001: 1}


# --------------------------------------------------------------------------- #
# pyserial URL policy
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("port", ["COM5", "COM12", "\\\\.\\COM10", "/dev/ttyACM0",
                                  "/dev/serial/by-id/usb-3D_Robotics-if00"])
def test_plain_device_names_are_accepted_without_allow_url(port):
    tr = SerialMavlinkTransport(port)  # constructing must not open or import anything
    assert tr.port == port
    tr.close()


@pytest.mark.parametrize("port", ["socket://127.0.0.1:5760", "rfc2217://host:2217", "SOCKET://x:1",
                                  "spy:///tmp/leak.txt", "loop://", "alt://spy://COM1"])
def test_urls_are_refused_unless_allow_url(port):
    with pytest.raises(ValueError, match="allow_url"):
        SerialMavlinkTransport(port)


@pytest.mark.parametrize("port", ["spy://COM1?file=out.txt", "SPY:///tmp/x", "alt://spy://COM1",
                                  "loop://", "hwgrep://0403", "cp2110://x", "file:///etc/passwd",
                                  "nosuchscheme://x", "rfc2217://host:2217", "RFC2217://host:2217"])
def test_dangerous_or_unknown_url_schemes_are_refused_even_with_allow_url(port):
    with pytest.raises(ValueError, match="not allowed"):
        SerialMavlinkTransport(port, allow_url=True)


def test_only_passive_socket_urls_are_allowed():
    """rfc2217:// sends Telnet option negotiation to the peer on open, which contradicts the
    passive-observation model, so it is NOT allowed; socket:// is a raw TCP client that sends
    nothing on connect (see test_virtual_port_connect_sends_nothing)."""
    assert ALLOWED_URL_SCHEMES == {"socket"}
    SerialMavlinkTransport("socket://127.0.0.1:1", allow_url=True).close()


@pytest.mark.parametrize("port", ["", "COM5\x00x"])
def test_empty_or_nul_port_is_refused(port):
    with pytest.raises(ValueError):
        SerialMavlinkTransport(port)


def test_default_factory_never_reaches_the_url_handler_for_plain_names(monkeypatch):
    import serial

    calls: dict[str, list] = {"Serial": [], "serial_for_url": []}
    monkeypatch.setattr(serial, "Serial", lambda *a, **k: calls["Serial"].append((a, k)) or "S")
    monkeypatch.setattr(serial, "serial_for_url",
                        lambda *a, **k: calls["serial_for_url"].append((a, k)) or "U")
    assert SerialMavlinkTransport("COM7", baudrate=115200)._factory() == "S"
    assert calls["serial_for_url"] == []
    args, kw = calls["Serial"][0]
    assert args == ("COM7",) and kw["baudrate"] == 115200 and kw["rtscts"] is False
    assert SerialMavlinkTransport("socket://h:1", allow_url=True)._factory() == "U"
    assert len(calls["serial_for_url"]) == 1


def test_serial_factory_replaces_opening_and_the_port_label_is_not_a_url_check():
    tr, _ = make_tr([FakePort()])  # label "FAKE"
    assert tr.port == "FAKE"
    tr.close()


# --------------------------------------------------------------------------- #
# L1: reader-thread failures are visible, never silent
# --------------------------------------------------------------------------- #


def _raise_boom(_data: bytes):
    raise ValueError("boom in feed")


def test_framer_exception_marks_transport_unhealthy_and_shutdown_stays_prompt():
    port = FakePort([hb(0)])
    tr, _ = make_tr([port], reconnect=False)
    tr._framer.feed = _raise_boom  # type: ignore[method-assign]
    tr.start()
    thread = tr._thread
    wait_for(lambda: tr.reader_faults == 1, what="fault recorded")
    wait_for(lambda: not tr.reader_running, what="reader thread exit (reconnect=False)")
    assert tr.connected is False and tr.stats["connected"] is False
    assert tr.stats["reader_running"] is False and tr.stats["reader_faults"] == 1
    assert tr.disconnects == 1  # the port was closed
    assert "reader fault" in (tr.last_error or "") and "boom in feed" in (tr.last_error or "")
    assert port.closed and tr.poll() == []
    t0 = time.monotonic()
    tr.close()
    tr.close()  # idempotent
    assert time.monotonic() - t0 < 1.5
    assert thread is not None and not thread.is_alive()


def test_framer_exception_with_reconnect_recovers_through_the_normal_policy():
    real_feed = MavlinkStreamFramer.feed
    state = {"n": 0}

    def flaky(self, data):
        state["n"] += 1
        if state["n"] == 1:
            raise ValueError("first feed explodes")
        return real_feed(self, data)

    p1, p2 = FakePort([hb(0)]), FakePort([att(1)])
    tr, calls = make_tr([p1, p2])
    tr._framer.feed = flaky.__get__(tr._framer)  # type: ignore[method-assign]
    with tr:
        got = collect(tr, 1)
        wait_for(lambda: tr.connected, what="reconnected after the fault")
        assert [d for _, d in got] == [att(1)]  # the frame in the faulted read is lost, not replayed
        assert tr.reader_faults == 1 and tr.reconnects == 1 and tr.disconnects == 1
        assert "first feed explodes" in (tr.last_error or "")
        assert tr.reader_running
    assert p1.closed and p2.closed and calls[0] == 2


def test_persistent_framer_fault_does_not_spin_and_close_is_still_prompt():
    ports = [FakePort([hb(i)]) for i in range(30)]
    tr, calls = make_tr(ports, reconnect_interval_s=0.02)
    tr._framer.feed = _raise_boom  # type: ignore[method-assign]
    tr.start()
    wait_for(lambda: tr.reader_faults >= 3, what="repeated faults")
    # one reconnect wait per fault: it cannot fault faster than the reconnect interval allows
    assert tr.reader_faults <= calls[0]
    t0 = time.monotonic()
    tr.close()
    assert time.monotonic() - t0 < 1.5
    assert not tr.reader_running and tr.connected is False


def test_unrecoverable_fault_handler_failure_still_ends_disconnected():
    port = FakePort([hb(0)])
    tr, _ = make_tr([port])
    tr._framer.feed = _raise_boom  # type: ignore[method-assign]

    def broken_handler(_exc):
        raise OSError("handler broke too")

    tr._on_disconnect = broken_handler  # type: ignore[method-assign]
    tr.start()
    wait_for(lambda: not tr.reader_running, what="reader gave up")
    assert tr.connected is False and port.closed  # the finally-block closed it
    assert "unrecoverable" in (tr.last_error or "") and "handler broke too" in (tr.last_error or "")
    tr.close()


def test_read_exception_during_close_is_not_counted_as_a_disconnect():
    port = FakePort()
    tr, _ = make_tr([port])
    tr.start()
    tr.close()
    assert tr.disconnects == 0 and tr.reader_faults == 0


def test_transport_poll_gap_tracks_consumer_stalls():
    tr, _ = make_tr([FakePort()])
    with tr:
        tr.poll()
        time.sleep(0.12)
        tr.poll()
    assert tr.max_poll_gap_s >= 0.1


# --------------------------------------------------------------------------- #
# integration with the unchanged LiveMavlinkSource
# --------------------------------------------------------------------------- #


def test_live_source_runs_unchanged_over_the_serial_transport():
    frames = [hb(0), att(1), gpi(2)] * 5
    port = FakePort([b"".join(frames)])
    tr, _ = make_tr([port])
    src = LiveMavlinkSource(tr, sample_rate_hz=10.0, max_ticks=4)
    try:
        ticks = list(src.stream())
    finally:
        src.close()
    names = [m.msgname for t in ticks for m in t.messages]
    assert names.count("HEARTBEAT") == 5 and names.count("ATTITUDE") == 5
    assert names.count("GLOBAL_POSITION_INT") == 5
    st = src.stats
    assert st["bad_frames"] == 0 and st["dropped_overflow"] == 0 and "queue_high_water" in st


# --------------------------------------------------------------------------- #
# REAL pyserial over a virtual port: socket:// (portable)
# --------------------------------------------------------------------------- #


class VirtualPortServer:
    """Loopback TCP server that plays the 'device' end of a ``socket://`` serial port."""

    def __init__(self) -> None:
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.srv.settimeout(0.05)
        self.port = self.srv.getsockname()[1]
        self.conn: socket.socket | None = None
        self.received = bytearray()
        self.accepted = 0
        self._stop = threading.Event()
        self._th = threading.Thread(target=self._run, daemon=True)
        self._th.start()

    @property
    def url(self) -> str:
        return f"socket://127.0.0.1:{self.port}"

    def _run(self) -> None:
        while not self._stop.is_set():
            if self.conn is None:
                try:
                    self.conn, _ = self.srv.accept()
                    self.conn.settimeout(0.02)
                    self.accepted += 1
                except OSError:
                    continue
            try:
                data = self.conn.recv(4096)
                if data:
                    self.received += data
                else:
                    self.conn = None
            except TimeoutError:
                pass
            except OSError:
                self.conn = None

    def wait_connected(self) -> None:
        wait_for(lambda: self.conn is not None, what="client connected")

    def send(self, data: bytes, chunk: int | None = None, delay: float = 0.0) -> None:
        self.wait_connected()
        assert self.conn is not None
        if chunk is None:
            self.conn.sendall(data)
            return
        for i in range(0, len(data), chunk):
            self.conn.sendall(data[i : i + chunk])
            time.sleep(delay)

    def drop_client(self) -> None:
        self.wait_connected()
        c, self.conn = self.conn, None
        assert c is not None
        c.close()

    def close(self) -> None:
        self._stop.set()
        self._th.join(timeout=2)
        for s in (self.conn, self.srv):
            if s is not None:
                s.close()


@pytest.fixture
def vport():
    s = VirtualPortServer()
    yield s
    s.close()


def test_virtual_port_fragmented_stream_is_reassembled(vport):
    frames = frame_stream(12)
    tr = SerialMavlinkTransport(vport.url, allow_url=True, reconnect_interval_s=0.02)
    with tr:
        vport.send(b"".join(frames), chunk=7, delay=0.001)
        got = collect(tr, 12, timeout=10)
    assert [d for _, d in got] == frames
    assert tr.garbage_bytes == 0 and tr.crc_rejects == 0 and tr.reads > 12


def test_virtual_port_garbage_burst_and_resync(vport):
    a, b, c = hb(1), att(2), gpi(3)
    tr = SerialMavlinkTransport(vport.url, allow_url=True)
    with tr:
        vport.send(b"\x00\x11\x22" + a + bytes([0xFD, 120, 0, 0]) + b + c + b"\xee\xee" + a)
        got = collect(tr, 4, timeout=10)
    assert [d for _, d in got] == [a, b, c, a]
    assert tr.resync_events >= 2 and tr.garbage_bytes >= 9


def test_virtual_port_peer_close_then_reconnect(vport):
    a, b = hb(1), att(2)
    tr = SerialMavlinkTransport(vport.url, allow_url=True, reconnect_interval_s=0.05)
    with tr:
        vport.send(a)
        collect(tr, 1)
        vport.send(gpi(5)[:9])  # leave a partial frame on the wire
        wait_for(lambda: tr.bytes_received >= len(a) + 9, what="partial received")
        vport.drop_client()
        wait_for(lambda: tr.disconnects >= 1, what="disconnect noticed")
        wait_for(lambda: tr.connected and vport.accepted >= 2, what="reconnect")
        vport.send(b)
        got = collect(tr, 1)
    assert got[0][1] == b  # the cut-off gpi never leaks into the new session
    assert tr.reconnects >= 1 and tr.discarded_on_disconnect_bytes == 9


def test_virtual_port_send_reaches_the_device(vport):
    tr = SerialMavlinkTransport(vport.url, allow_url=True)
    with tr:
        vport.wait_connected()
        assert tr.send(b"hello-fc")
        wait_for(lambda: bytes(vport.received) == b"hello-fc", what="device received write")


def test_virtual_port_connect_sends_nothing(vport):
    """Passive-observation check for the one allowed URL scheme: opening socket:// and reading
    emits no bytes toward the peer (rfc2217:// would start Telnet negotiation here)."""
    tr = SerialMavlinkTransport(vport.url, allow_url=True)
    with tr:
        vport.wait_connected()
        vport.send(hb(1))
        collect(tr, 1)
        time.sleep(0.2)
    assert bytes(vport.received) == b"" and tr.bytes_sent == 0


def test_virtual_port_unreachable_with_reconnect_disabled_raises():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    tr = SerialMavlinkTransport(f"socket://127.0.0.1:{port}", allow_url=True, reconnect=False)
    with pytest.raises(RuntimeError, match="cannot open serial port"):
        tr.start()
    tr.close()


# --------------------------------------------------------------------------- #
# REAL pyserial over a PTY pair (POSIX only; skipped on Windows)
# --------------------------------------------------------------------------- #

posix_pty = pytest.mark.skipif(sys.platform == "win32",
                               reason="PTY pairs do not exist on Windows; socket:// tests cover "
                                      "the same transport paths there")


@pytest.fixture
def pty_pair():
    import pty
    import tty

    master, slave = pty.openpty()
    tty.setraw(slave)
    name = os.ttyname(slave)
    yield master, slave, name
    for fd in (master, slave):
        try:
            os.close(fd)
        except OSError:
            pass


@posix_pty
def test_pty_fragments_bursts_and_garbage(pty_pair):
    master, _slave, name = pty_pair
    frames = frame_stream(10)
    blob = b"\x00\x01" + b"".join(frames[:5]) + b"\xfd\xc8\x00" + b"".join(frames[5:])
    tr = SerialMavlinkTransport(name, baudrate=115200)
    with tr:
        for i in range(0, len(blob), 11):
            os.write(master, blob[i : i + 11])
            time.sleep(0.002)
        got = collect(tr, 10, timeout=10)
    assert [d for _, d in got] == frames
    assert tr.resync_events >= 2


def _read_ready(fd: int) -> bytes:
    import select

    r, _, _ = select.select([fd], [], [], 0.05)
    return os.read(fd, 64) if r else b""


@posix_pty
def test_pty_send_reaches_the_other_end(pty_pair):
    master, _slave, name = pty_pair
    tr = SerialMavlinkTransport(name)
    with tr:
        assert tr.send(b"ping")
        wait_for(lambda: _read_ready(master) == b"ping", what="master received write")


@posix_pty
def test_pty_device_disappearing_is_a_disconnect_not_a_crash(pty_pair):
    master, slave, name = pty_pair
    a = hb(1)
    tr = SerialMavlinkTransport(name, reconnect=False)
    with tr:
        os.write(master, a)
        collect(tr, 1)
        os.close(master)  # the 'USB cable' is pulled
        os.close(slave)
        wait_for(lambda: tr.disconnects >= 1, what="disconnect noticed")
        assert not tr.connected and tr.last_error
