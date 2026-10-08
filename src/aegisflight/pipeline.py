"""The IDS pipeline: telemetry in, threat assessments out.

Wires the detection stack together and runs it at the configured decision
cadence:

    messages -> FeatureExtractor.update (every tick)
    at each decision tick:
        FeatureExtractor.extract -> {Protocol, Physics, Anomaly, Integrity}
            -> FusionEngine.fuse -> ThreatAssessment

The pipeline owns a :class:`FirmwareVerifier` (its own copy of the firmware
manifest) so the integrity detector performs a genuine SHA-256 check every
decision. Detection latency is measured around the per-decision work.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

from .config import AegisConfig
from .core.types import ThreatAssessment
from .detectors import AnomalyDetector, IntegrityDetector, PhysicsDetector, ProtocolDetector
from .features.extractor import FeatureExtractor, FeatureFrame
from .fusion.engine import FusionEngine
from .integrity.verifier import FirmwareVerifier
from .sources.stream import TelemetryTick


class IDSPipeline:
    def __init__(
        self,
        cfg: AegisConfig,
        model_path: str | Path | None = None,
        firmware_dir: str | Path | None = None,
    ) -> None:
        self.cfg = cfg
        det = cfg.detector
        self.extractor = FeatureExtractor(
            cmd_window_s=det["protocol"].get("command_burst_window_s", 2.0)
        )
        self.protocol = ProtocolDetector(det["protocol"])
        self.physics = PhysicsDetector(det["physics"])
        self.anomaly = AnomalyDetector(det["anomaly"], model_path)

        self.verifier: FirmwareVerifier | None = None
        if firmware_dir is not None:
            self.verifier = FirmwareVerifier(firmware_dir)
            self.verifier.ensure_fixture()
        self.integrity = IntegrityDetector(self.verifier)

        self.fusion = FusionEngine(det["fusion"])

        base = float(cfg.simulation.get("sample_rate_hz", 10.0))
        dec = float(det.get("decision_rate_hz", 5.0))
        self.decision_every = max(1, int(round(base / dec)))
        self._last: ThreatAssessment | None = None
        # Most recent FeatureFrame (read-only; used by external-data analysis
        # to inspect features without re-running extraction).
        self.last_frame: FeatureFrame | None = None

    @property
    def ml_available(self) -> bool:
        return self.anomaly.available

    def _telemetry_dict(self) -> dict:
        s = self.extractor.snapshot
        return {
            "lat": s.lat,
            "lon": s.lon,
            "alt_msl": round(s.alt_msl, 2) if s.alt_msl is not None else None,
            "rel_alt": round(s.rel_alt, 2) if s.rel_alt is not None else None,
            "groundspeed": round(s.groundspeed, 2) if s.groundspeed is not None else None,
            "heading": round(s.heading, 1) if s.heading is not None else None,
            "battery_voltage": round(s.battery_voltage, 2) if s.battery_voltage is not None else None,
            "battery_remaining": s.battery_remaining,
            "satellites": s.satellites,
            "flight_mode": s.flight_mode,
            "armed": s.armed,
        }

    def process_tick(self, tick: TelemetryTick) -> ThreatAssessment | None:
        """Ingest one tick; return a ThreatAssessment at decision cadence, else None."""
        for m in tick.messages:
            self.extractor.update(m)
        self.extractor.note_sig_invalid(tick.sig_invalid)  # P4: 0 for every non-signing source
        if tick.tick % self.decision_every != 0:
            return None

        t0 = time.perf_counter()
        frame = self.extractor.extract(tick.t)
        self.last_frame = frame
        r_proto = self.protocol.process(frame)
        r_phys = self.physics.process(frame)
        r_anom = self.anomaly.process(frame)
        r_integ = self.integrity.process()
        assessment = self.fusion.fuse(
            t=tick.t,
            wall_time=time.time(),
            results=[r_proto, r_phys, r_anom, r_integ],
            integrity_status=self.integrity.status,
            telemetry=self._telemetry_dict(),
        )
        assessment.latency_ms = (time.perf_counter() - t0) * 1000.0
        self.extractor.clear_window_counts()
        self._last = assessment
        return assessment

    def run(self, ticks: Iterator[TelemetryTick]) -> Iterator[ThreatAssessment]:
        for tick in ticks:
            a = self.process_tick(tick)
            if a is not None:
                yield a

    def reset(self) -> None:
        """Return the pipeline (and its simulated firmware) to a clean baseline.

        Order matters. The simulated firmware artifact is restored to known-good
        *first*, so when the integrity detector next re-verifies it reads clean
        bytes — clearing the detector cache alone would just re-read the still
        tampered file and report INVALID again. Then every extractor / detector /
        fusion state is cleared so no stale signal (network windows, position
        residual, alert hysteresis, firmware verdict) survives into the next run.
        """
        # 1. Restore the simulated firmware to known-good (reflash) BEFORE
        #    the integrity detector re-verifies against it.
        if self.verifier is not None:
            self.verifier.restore_fixture()
        # 2. Reset feature extraction + every detector + fusion state.
        self.extractor.reset()
        self.protocol.reset()
        self.physics.reset()
        self.anomaly.reset()
        self.integrity.reset()
        self.fusion.reset()
        self._last = None
        self.last_frame = None
