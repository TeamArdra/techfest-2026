"""Evidence-fusion engine.

Combines the four detectors' :class:`DetectorResult` outputs into one
explainable :class:`ThreatAssessment` per decision tick.

Fusion model
------------
A plain weighted sum (the config weights sum to 1.0) would cap any lone
detector below the 0.45 threat threshold — a firmware SHA-256 failure alone
(weight 0.20) would never alert, which is wrong. Instead we combine via
**noisy-OR with max-normalised weights**:

    w'_i = w_i / max_j(w_j)
    threat = 1 - Π_i (1 - score_i · w'_i)

This keeps the config's *relative* detector trust (physics is trusted most, ML
least), lets a single strong high-trust detector raise a threat, boosts the
score when independent detectors corroborate, and keeps a lone weak ML signal
below threshold. A lone *strong* ML score (>= 0.45 / 0.47 ~= 0.956) does cross
the threshold on its own -- that is the source of the baseline's false positives.

Attack attribution is a weighted vote across detectors; severity comes from the
configured bands; alerting adds per-attack-type cooldown de-duplication and a
clear-tick hysteresis so the alert state falls back to NORMAL cleanly.
"""

from __future__ import annotations

from ..core.enums import AttackType, DetectorName, IntegrityStatus, Severity
from ..core.types import DetectorResult, ThreatAssessment

_WEIGHT_KEYS = {
    DetectorName.PROTOCOL: "protocol_rule",
    DetectorName.PHYSICS: "physics_consistency",
    DetectorName.ANOMALY: "ml_anomaly",
    DetectorName.INTEGRITY: "firmware_integrity",
}


class FusionEngine:
    def __init__(self, cfg: dict) -> None:
        self.weights_cfg: dict[str, float] = dict(cfg.get("weights", {}))
        wmax = max(self.weights_cfg.values()) if self.weights_cfg else 1.0
        # max-normalised weights per DetectorName
        self.w: dict[DetectorName, float] = {
            det: (self.weights_cfg.get(key, 0.0) / wmax) if wmax else 0.0
            for det, key in _WEIGHT_KEYS.items()
        }
        self.threat_threshold = float(cfg.get("threat_threshold", 0.45))
        bands = cfg.get("severity_bands", {})
        self.bands = {
            Severity.WATCH: float(bands.get("WATCH", 0.30)),
            Severity.SUSPICIOUS: float(bands.get("SUSPICIOUS", 0.45)),
            Severity.HIGH: float(bands.get("HIGH", 0.62)),
            Severity.CRITICAL: float(bands.get("CRITICAL", 0.80)),
        }
        self.alert_min_severity = Severity[cfg.get("alert_threshold_severity", "SUSPICIOUS")]
        self.cooldown_s = float(cfg.get("cooldown_s", 4.0))
        self.clear_ticks = int(cfg.get("clear_ticks", 4))

        # alert state
        self._last_alert_t: dict[AttackType, float] = {}
        self._normal_streak = 0
        self._active = False

    def _severity(self, score: float) -> Severity:
        sev = Severity.NORMAL
        for s in (Severity.WATCH, Severity.SUSPICIOUS, Severity.HIGH, Severity.CRITICAL):
            if score >= self.bands[s]:
                sev = s
        return sev

    def fuse(
        self,
        t: float,
        wall_time: float,
        results: list[DetectorResult],
        integrity_status: IntegrityStatus,
        telemetry: dict | None = None,
    ) -> ThreatAssessment:
        by_name = {r.detector: r for r in results}
        detector_scores = {r.detector.value: r.score for r in results}

        # ---- noisy-OR combination with max-normalised weights ----
        prod = 1.0
        for r in results:
            wi = self.w.get(r.detector, 0.0)
            prod *= 1.0 - min(1.0, r.score * wi)
        threat_score = 1.0 - prod

        # ---- attack attribution: weighted vote across detectors ----
        vote_totals: dict[AttackType, float] = {}
        for r in results:
            wi = self.w.get(r.detector, 0.0)
            for atk, v in r.attack_votes.items():
                vote_totals[atk] = vote_totals.get(atk, 0.0) + wi * v
        if vote_totals:
            primary = max(vote_totals, key=lambda k: vote_totals[k])
            total_vote = sum(vote_totals.values())
            secondary = [
                a
                for a, v in sorted(vote_totals.items(), key=lambda kv: -kv[1])
                if a != primary and v >= 0.25 * vote_totals[primary]
            ]
        else:
            primary = AttackType.BENIGN
            total_vote = 0.0
            secondary = []

        threat = threat_score >= self.threat_threshold
        severity = self._severity(threat_score)
        if not threat:
            # below threat threshold => at most WATCH, and BENIGN label
            primary = primary if threat_score >= self.bands[Severity.WATCH] else AttackType.BENIGN

        # confidence: threat strength × attribution dominance
        dominance = (vote_totals.get(primary, 0.0) / total_vote) if total_vote > 0 else 0.0
        confidence = round(threat_score * (0.5 + 0.5 * dominance), 4)

        # ---- evidence aggregation ----
        # Stage-1 order (physics, protocol, integrity, anomaly), except that evidence from a
        # PHYSICS result with score 0 is moved after the others. Only the estimator gate's
        # degraded-navigation line produces score-0 physics evidence, so Stage-1 order is exact
        # whenever no EKF_STATUS_REPORT gates a fix.
        evidence: list[str] = []
        deferred: list[str] = []
        for det in (DetectorName.PHYSICS, DetectorName.PROTOCOL, DetectorName.INTEGRITY,
                    DetectorName.ANOMALY):
            r = by_name.get(det)
            if r and r.evidence:
                if det is DetectorName.PHYSICS and r.score <= 0.0:
                    deferred.extend(r.evidence)
                else:
                    evidence.extend(r.evidence)
        evidence.extend(deferred)
        contributing = [r.detector.value for r in results if r.score > 0.1]

        # ---- alert de-duplication + clear hysteresis ----
        is_alert = False
        if threat and severity.rank >= self.alert_min_severity.rank:
            last = self._last_alert_t.get(primary, -1e9)
            if (t - last) >= self.cooldown_s or not self._active:
                is_alert = True
                self._last_alert_t[primary] = t
            self._active = True
            self._normal_streak = 0
        else:
            self._normal_streak += 1
            if self._normal_streak >= self.clear_ticks:
                self._active = False

        return ThreatAssessment(
            t=t,
            wall_time=wall_time,
            threat=threat,
            threat_score=round(threat_score, 4),
            severity=severity if threat else Severity.NORMAL,
            attack_type=primary,
            confidence=confidence,
            secondary_indicators=secondary,
            evidence=evidence,
            detector_scores=detector_scores,
            contributing_detectors=contributing,
            integrity_status=integrity_status,
            telemetry=telemetry or {},
            is_alert=is_alert,
        )

    def reset(self) -> None:
        self._last_alert_t.clear()
        self._normal_streak = 0
        self._active = False
