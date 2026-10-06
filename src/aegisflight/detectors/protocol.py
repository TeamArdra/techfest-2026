"""Detector A — protocol / rule engine.

Stateless per-frame rules over MAVLink transport behaviour: aggregate message
rate, per-source sequence gaps, rogue system IDs, heartbeat / GPS liveness,
message signing, and command provenance. Each rule contributes a normalised
sub-score and a vote for the attack class it implies; the detector's score is
the strongest sub-score.
"""

from __future__ import annotations

from ..core.enums import AttackType, DetectorName
from ..core.types import DetectorResult
from ..features.extractor import FeatureFrame
from ..mavlink.codec import command_name_from_id
from .base import Detector, ramp

_NEVER_SEEN_S = 999.0  # FeatureExtractor sentinel age for "no such message received yet"


class ProtocolDetector(Detector):
    name = DetectorName.PROTOCOL

    def __init__(self, cfg: dict) -> None:
        p = cfg
        self.expected_sysids = set(p.get("expected_sysids", [1]))
        self.expected_gcs = set(p.get("expected_gcs_sysids", [255, 254]))
        self.autopilot_compid = int(p.get("autopilot_compid", 1))
        self.hb_timeout = float(p.get("heartbeat_timeout_s", 3.0))
        self.max_rate = float(p.get("max_msg_rate_hz", 400.0))
        self.nominal_rate = float(p.get("nominal_msg_rate_hz", 28.0))
        self.spike_factor = float(p.get("msg_rate_spike_factor", 3.0))
        self.max_seq_gap = float(p.get("max_seq_gap", 30))
        self.gps_dropout = float(p.get("gps_dropout_s", 2.0))
        self.sensitive = set(p.get("sensitive_commands", []))
        self.burst_max = int(p.get("command_burst_max", 4))
        self.require_signing = bool(p.get("require_signing", False))
        # GNSS fix loss (jamming / receiver denial): fix_type < min_fix_type or
        # satellites < min_satellites for >= gnss_loss_ticks consecutive decisions.
        self.min_fix_type = int(p.get("min_gnss_fix_type", 3))
        self.min_sats = int(p.get("min_gnss_satellites", 5))
        self.gnss_loss_ticks = int(p.get("gnss_loss_ticks", 5))
        self._gnss_bad = 0
        # Start-of-stream grace (additive, default 0 = Stage-1 behaviour): for this many
        # seconds after the first decision, the "never seen yet" sentinel (extractor
        # reports 999 s before the first heartbeat / GPS message) is not a liveness fault.
        # Once a message has been seen, staleness is judged exactly as before.
        self.startup_grace_s = float(p.get("startup_grace_s", 0.0))
        self._t0: float | None = None

    def process(self, frame: FeatureFrame) -> DetectorResult:
        evidence: list[str] = []
        votes: dict[AttackType, float] = {}
        signals: dict[str, float] = {}
        score = 0.0

        def bump(attack: AttackType, s: float) -> None:
            nonlocal score
            votes[attack] = max(votes.get(attack, 0.0), s)
            score = max(score, s)

        # ---- message-rate flood (DoS) ----
        rate = frame.msg_rate_hz
        spike = self.nominal_rate * self.spike_factor
        if rate >= self.max_rate:
            bump(AttackType.DOS, 1.0)
            evidence.append(f"message flood: {rate:.0f} msg/s ≥ hard limit {self.max_rate:.0f}")
        elif rate > spike:
            s = ramp(rate, spike, self.max_rate)
            bump(AttackType.DOS, max(0.6, s))
            evidence.append(
                f"message-rate spike: {rate:.0f} msg/s > {self.spike_factor:.0f}×nominal "
                f"({spike:.0f})"
            )
        signals["msg_rate_hz"] = rate

        # ---- sequence gaps (loss / scramble / flood) ----
        if frame.max_seq_gap > self.max_seq_gap:
            s = ramp(frame.max_seq_gap, self.max_seq_gap, self.max_seq_gap * 4)
            # attribute to DoS if the rate is also elevated, else a MAVLink anomaly
            attack = AttackType.DOS if rate > spike else AttackType.MAVLINK_ANOMALY
            bump(attack, max(0.55, s))
            evidence.append(f"sequence gap {frame.max_seq_gap} > {self.max_seq_gap:.0f}")
        signals["max_seq_gap"] = float(frame.max_seq_gap)

        # ---- rogue sources ----
        cmd_src = {(c.sysid, c.compid) for c in frame.commands_recent}
        rogue_telemetry = [
            (s, c)
            for (s, c) in frame.sources
            if s not in self.expected_sysids and s not in self.expected_gcs and (s, c) not in cmd_src
        ]
        if rogue_telemetry:
            bump(AttackType.MAVLINK_ANOMALY, 0.9)
            evidence.append(
                "rogue telemetry source(s): "
                + ", ".join(f"sys{s}/comp{c}" for s, c in rogue_telemetry)
            )
        signals["n_sources"] = float(frame.n_sources)

        # ---- liveness (heartbeat / GPS dropout -> DoS/blackout) ----
        if self._t0 is None:
            self._t0 = frame.t
        in_grace = self.startup_grace_s > 0.0 and (frame.t - self._t0) < self.startup_grace_s
        if frame.heartbeat_age_s > self.hb_timeout and not (in_grace and frame.heartbeat_age_s >= _NEVER_SEEN_S):
            s = ramp(frame.heartbeat_age_s, self.hb_timeout, self.hb_timeout * 2)
            bump(AttackType.DOS, max(0.6, s))
            evidence.append(f"heartbeat stale {frame.heartbeat_age_s:.1f}s > {self.hb_timeout:.1f}s")
        if frame.gps_age_s > self.gps_dropout and not (in_grace and frame.gps_age_s >= _NEVER_SEEN_S):
            s = ramp(frame.gps_age_s, self.gps_dropout, self.gps_dropout * 3)
            bump(AttackType.DOS, max(0.5, s))
            evidence.append(f"GPS dropout {frame.gps_age_s:.1f}s > {self.gps_dropout:.1f}s")

        # ---- GNSS fix loss (navigation-channel denial / jamming) ----
        snap = frame.snapshot
        fix, sats = snap.gps_fix_type, snap.satellites
        if fix is not None and sats is not None and (fix < self.min_fix_type or sats < self.min_sats):
            self._gnss_bad += 1
        else:
            self._gnss_bad = 0
        if self._gnss_bad >= self.gnss_loss_ticks:
            bump(AttackType.DOS, 0.7)
            evidence.append(f"GNSS fix lost: fix_type={fix}, satellites={sats} "
                            f"for {self._gnss_bad} decisions")
        signals["gnss_bad_ticks"] = float(self._gnss_bad)

        # ---- command provenance (injection) ----
        unexpected = [
            c
            for c in frame.commands_recent
            if c.sysid not in self.expected_gcs
            and not (c.sysid in self.expected_sysids and c.compid == self.autopilot_compid)
        ]
        if unexpected:
            names = {command_name_from_id(c.command) for c in unexpected}
            sensitive_hit = names & self.sensitive
            s = 0.9 if sensitive_hit else 0.65
            if len(unexpected) > self.burst_max:
                s = max(s, 0.95)
            bump(AttackType.COMMAND_INJECTION, s)
            src = {(c.sysid, c.compid) for c in unexpected}
            ev = (
                f"{len(unexpected)} command(s) from unexpected source "
                + ", ".join(f"sys{a}/comp{b}" for a, b in src)
            )
            if sensitive_hit:
                ev += f"; sensitive: {', '.join(sorted(sensitive_hit))}"
            evidence.append(ev)
        signals["cmd_rate_hz"] = frame.cmd_rate_hz

        # ---- signing policy ----
        if self.require_signing and frame.signed_ratio < 1.0:
            bump(AttackType.MAVLINK_ANOMALY, 0.5)
            evidence.append(f"unsigned messages present (signed ratio {frame.signed_ratio:.2f})")

        return DetectorResult(
            detector=self.name,
            score=score,
            triggered=score >= 0.5,
            evidence=evidence,
            attack_votes=votes,
            signals=signals,
        )

    def reset(self) -> None:
        self._gnss_bad = 0
        self._t0 = None
