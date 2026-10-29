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
        self.cadence_guard_enabled = bool(p.get("cadence_guard_enabled", False))
        self.cadence_min_interval_s = float(p.get("cadence_min_interval_s", 1.5))
        self._last_cmd_seen: dict[tuple[int, int], float] = {}
        # GNSS fix loss (jamming / receiver denial): fix_type < min_fix_type or
        # satellites < min_satellites for >= gnss_loss_ticks consecutive decisions.
        self.min_fix_type = int(p.get("min_gnss_fix_type", 3))
        self.min_sats = int(p.get("min_gnss_satellites", 5))
        self.gnss_loss_ticks = int(p.get("gnss_loss_ticks", 5))
        self._gnss_bad = 0
        # Has a valid fix (the rule's own healthy condition) ever been observed? Wording only:
        # a fix that was never acquired is not reported as "lost". Score/vote are identical.
        self._gnss_ever_valid = False
        # Start-of-stream grace (default 0): for this many seconds after the first
        # decision a NEVER-received heartbeat / position stream is not a liveness fault. It
        # combines with the elapsed-time gate below as a maximum, not a sum: the later of the two
        # decides. Once a message has been seen, staleness is judged on its measured age as before.
        self.startup_grace_s = float(p.get("startup_grace_s", 0.0))
        # GPS position policy (user decision 2026-10-15, "Coverage, not attack"). Default False:
        # a link that has NEVER delivered GLOBAL_POSITION_INT is a reported coverage condition
        # (score 0, no vote, a "coverage: ..." evidence line), not scored as attack evidence (the IDS cannot
        # tell why the stream is absent; see docs/DETECTION.md, security consequence). True: the
        # profile declares position as required, and a never-received stream is the DOS-voting
        # "GPS dropout: never received" fault, shaped by the two knobs below. GPS lost after
        # having been seen is a DOS fault under either setting.
        self.require_global_position = bool(p.get("require_global_position", False))
        # Never-seen GPS knobs (apply only when require_global_position is True): re-attribute
        # the vote (``never_seen_gps_vote``, e.g. MAVLINK_ANOMALY) and cap the score
        # (``never_seen_gps_max_score``). The cap is floored at 0.5, which guarantees DETECTOR-level
        # reporting (this detector triggers, score >= 0.5, evidence on the decision). It does NOT
        # guarantee a fused threat / operator alert: 0.5 x the max-normalised protocol fusion weight
        # (0.30/0.34) = 0.441 is below fusion.threat_threshold (0.45), so at the floor the
        # assessment is threat=False WHEN PROTOCOL IS THE ONLY CONTRIBUTING DETECTOR. Under the
        # noisy-OR a small ML (>= ~0.034) or physics (>= ~0.016) score lifts it past 0.45.
        self.never_seen_gps_vote = AttackType[str(p.get("never_seen_gps_vote", "DOS"))]
        self.never_seen_gps_max = max(0.5, min(1.0, float(p.get("never_seen_gps_max_score", 1.0))))
        self._t0: float | None = None
        # Link-rate baseline (default OFF, so Stage-1 / SIM / replay behave exactly as before). When
        # on, the link's own normal message rate is learned over ``rate_learn_s`` after the first
        # heartbeat and the rate thresholds are raised (never lowered) from it, then frozen.
        self.auto_rate_baseline = bool(p.get("auto_rate_baseline", False))
        self.rate_learn_s = float(p.get("rate_learn_s", 20.0))
        self._cfg_nominal = self.nominal_rate
        self._cfg_max = self.max_rate
        self._learn_t0: float | None = None
        self._learn_samples: list[float] = []
        self._learn_done = not self.auto_rate_baseline
        self._learn_note: str | None = None

    def _learn_rate(self, frame: FeatureFrame) -> bool:
        """Advance baseline learning; True while learning (rate alarms suppressed)."""
        if self._learn_done:
            return False
        if not (frame.heartbeat_seen if frame.heartbeat_seen is not None else frame.heartbeat_age_s < _NEVER_SEEN_S):
            return True  # learning starts at the first heartbeat
        if self._learn_t0 is None:
            self._learn_t0 = frame.t
        if frame.t - self._learn_t0 < self.rate_learn_s:
            if frame.msg_rate_hz > 0.0:
                self._learn_samples.append(float(frame.msg_rate_hz))
            return True
        self._learn_done = True
        xs = sorted(self._learn_samples)
        if not xs:
            self._learn_note = "link message-rate baseline learning rejected (no rate samples); configured thresholds kept"
            return False
        med = xs[len(xs) // 2] if len(xs) % 2 else 0.5 * (xs[len(xs) // 2 - 1] + xs[len(xs) // 2])
        p95 = xs[min(len(xs) - 1, int(0.95 * len(xs)))]
        if xs[-1] > self._cfg_max or p95 > 5.0 * med:
            self._learn_note = (
                f"link message-rate baseline learning rejected (peak {xs[-1]:.0f} msg/s, p95 {p95:.0f}, "
                f"median {med:.0f}: looks like a flood); configured thresholds kept"
            )
            return False
        self.nominal_rate = max(self._cfg_nominal, med)
        self.max_rate = max(self._cfg_max, 4.0 * med)
        self._learn_note = (
            f"link message-rate baseline learned: median {med:.0f} msg/s -> nominal {self.nominal_rate:.0f}, "
            f"flood limit {self.max_rate:.0f} (frozen)"
        )
        return False

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
        learning = self._learn_rate(frame)
        spike = self.nominal_rate * self.spike_factor
        if learning:
            if frame.heartbeat_seen is not False and self._learn_t0 is not None:
                evidence.append("coverage: learning link message-rate baseline (rate alarms suppressed)")
            spike = float("inf")
        if learning and rate < self.max_rate:
            pass  # a rate above the configured hard limit is still a flood while the baseline is being learned
        elif rate >= self.max_rate:
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
            attack = AttackType.DOS if (rate > spike and not learning) else AttackType.MAVLINK_ANOMALY
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
        elapsed = frame.t - self._t0
        in_grace = self.startup_grace_s > 0.0 and elapsed < self.startup_grace_s
        # "never received" is read from the explicit extractor flags when present; hand-built
        # frames (flags None) fall back to the 999 s sentinel, as before. For a NEVER-received
        # stream the elapsed monitoring time decides WHEN it may be a fault (only once monitoring
        # has run longer than the rule's own timeout); the SCORE still comes from the age ramp
        # below, which is 1.0 for extractor frames (age = the 999 s sentinel).
        hb_never = (
            (not frame.heartbeat_seen)
            if frame.heartbeat_seen is not None
            else frame.heartbeat_age_s >= _NEVER_SEEN_S
        )
        gps_never = (
            (not frame.gps_seen) if frame.gps_seen is not None else frame.gps_age_s >= _NEVER_SEEN_S
        )
        hb_fault = (
            elapsed > self.hb_timeout and not in_grace
            if hb_never
            else frame.heartbeat_age_s > self.hb_timeout
        )
        if hb_fault:
            s = ramp(frame.heartbeat_age_s, self.hb_timeout, self.hb_timeout * 2)
            bump(AttackType.DOS, max(0.6, s))
            if hb_never:
                evidence.append(
                    "heartbeat stale (never received: no HEARTBEAT since monitoring began) "
                    f"> {self.hb_timeout:.1f}s"
                )
            else:
                evidence.append(
                    f"heartbeat stale {frame.heartbeat_age_s:.1f}s > {self.hb_timeout:.1f}s"
                )
        coverage: str | None = None
        if gps_never and not self.require_global_position:
            # coverage condition: no vote, no score (exact substring matched by acceptance tests).
            # Appended LAST (just before return), so it never heads an alert raised by another rule.
            raw = {True: "GPS_RAW_INT present", False: "GPS_RAW_INT never received"}.get(
                frame.gps_raw_seen, "GPS_RAW_INT presence unknown"
            )
            coverage = (
                f"coverage: GLOBAL_POSITION_INT never received ({raw}); position-dependent checks "
                "inactive; not attack evidence under this profile "
                "(protocol.require_global_position=false)"
            )
        elif (
            elapsed > self.gps_dropout and not in_grace
            if gps_never
            else frame.gps_age_s > self.gps_dropout
        ):
            s = max(0.5, ramp(frame.gps_age_s, self.gps_dropout, self.gps_dropout * 3))
            if gps_never:
                bump(self.never_seen_gps_vote, min(s, self.never_seen_gps_max))
                evidence.append(
                    "GPS dropout: never received (no GLOBAL_POSITION_INT since monitoring began;"
                    f" incomplete telemetry, not a measured dropout) > {self.gps_dropout:.1f}s"
                )
            else:
                bump(AttackType.DOS, s)
                evidence.append(f"GPS dropout {frame.gps_age_s:.1f}s > {self.gps_dropout:.1f}s")

        # ---- GNSS fix loss (navigation-channel denial / jamming) ----
        snap = frame.snapshot
        fix, sats = snap.gps_fix_type, snap.satellites
        if fix is not None and sats is not None and (fix < self.min_fix_type or sats < self.min_sats):
            self._gnss_bad += 1
        else:
            self._gnss_bad = 0
            if fix is not None and sats is not None:
                self._gnss_ever_valid = True
        if self._gnss_bad >= self.gnss_loss_ticks:
            bump(AttackType.DOS, 0.7)
            if self._gnss_ever_valid:  # exact text parsed by scripts/sitl/make_p2n_summary.py
                evidence.append(f"GNSS fix lost: fix_type={fix}, satellites={sats} "
                                f"for {self._gnss_bad} decisions")
            else:
                evidence.append(f"GNSS fix never acquired: fix_type={fix}, satellites={sats} "
                                f"for {self._gnss_bad} decisions (no valid fix since monitoring began)")
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

        # ---- state-aware command cadence guard (unsigned replay & mid-air disarm protection) ----
        if self.cadence_guard_enabled and frame.commands_recent:
            high_risk_cmds = {400, 176, 20, 21}  # ARM_DISARM, DO_SET_MODE, RTL, LAND
            seen_in_window: dict[tuple[int, int], float] = {}
            for c in frame.commands_recent:
                if c.command not in high_risk_cmds:
                    continue
                key = (c.sysid, c.command)
                last = self._last_cmd_seen.get(key)
                if last is not None and c.recv_time <= last:
                    continue  # already evaluated on an earlier decision (commands_recent is a sliding window)
                prev_t = seen_in_window.get(key, last)
                if prev_t is not None and 0.0 < (c.recv_time - prev_t) < self.cadence_min_interval_s:
                    bump(AttackType.COMMAND_INJECTION, 0.90)
                    evidence.append(
                        f"duplicate high-risk command {command_name_from_id(c.command)} "
                        f"from sys{c.sysid} violates operator cadence "
                        f"(Δt={c.recv_time - prev_t:.2f}s < {self.cadence_min_interval_s:.1f}s)"
                    )
                if c.command == 400 and (not c.params or c.params[0] == 0.0):
                    if (snap.groundspeed or 0.0) > 1.0 and snap.armed:
                        bump(AttackType.COMMAND_INJECTION, 0.95)
                        evidence.append(
                            f"state-aware cadence guard: mid-air motor disarm (sys{c.sysid}) "
                            f"at groundspeed={snap.groundspeed:.1f} m/s"
                        )
                seen_in_window[key] = c.recv_time
                self._last_cmd_seen[key] = c.recv_time

        # ---- signing policy ----
        if self.require_signing and frame.signed_ratio < 1.0:
            bump(AttackType.MAVLINK_ANOMALY, 0.5)
            evidence.append(f"unsigned messages present (signed ratio {frame.signed_ratio:.2f})")
        # P4, additive: a REAL cryptographic signature failure (bad/missing HMAC, or an
        # unsigned frame for a message the signing policy does not allow unsigned -- see
        # ``sources.mavlink_live.MavlinkFrameParser``), as opposed to the rule above (which
        # only ever checks the claimed-signed bit, never a key). Only ever non-zero when the
        # live source was given a signing key AND require_signing is this profile's policy;
        # 0 for Stage-1, every current SITL profile, and any source without a key.
        if self.require_signing and frame.sig_invalid_count > 0:
            bump(AttackType.COMMAND_INJECTION, 0.95)
            evidence.append(f"{frame.sig_invalid_count} frame(s) failed MAVLink-2 signature verification")

        if self._learn_note is not None and "rejected" in self._learn_note:
            evidence.append(f"coverage: {self._learn_note}")
        if coverage is not None:  # score-0 coverage note: always the last protocol evidence item
            evidence.append(coverage)

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
        self._gnss_ever_valid = False
        self._t0 = None
        self._last_cmd_seen.clear()
        self.nominal_rate, self.max_rate = self._cfg_nominal, self._cfg_max
        self._learn_t0 = None
        self._learn_samples.clear()
        self._learn_done = not self.auto_rate_baseline
        self._learn_note = None
