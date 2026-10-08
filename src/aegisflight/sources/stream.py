"""Simulated telemetry source: the 'wire' the IDS ingests.

Ties the pieces together into a single tick-by-tick stream:

    FlightSimulator (clean truth)
        -> attack.perturb_state           (value attacks)
        -> MavlinkEncoder.encode_tick      (genuine MAVLink 2 + sensor noise)
        -> attack.perturb_packets          (stream attacks: drop/dup/delay/inject)
        -> MavlinkDecoder.decode           (bytes -> MessageEnvelope)

Each :class:`TelemetryTick` carries the decoded messages the IDS will actually
see, plus the **ground truth** (clean state, attack label, integrity status)
that only the benchmark harness is allowed to read.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

import numpy as np

from ..attacks.base import Attack, AttackContext, NoAttack
from ..config import AegisConfig
from ..core.enums import AttackType, IntegrityStatus
from ..core.types import FlightState, MessageEnvelope
from ..mavlink.codec import MavlinkDecoder, MavlinkEncoder, RawPacket
from ..simulator.flight import FlightSimulator, SimulatorConfig


@dataclass
class TelemetryTick:
    """One simulator tick's worth of observed telemetry + hidden ground truth."""

    t: float
    tick: int
    messages: list[MessageEnvelope] = field(default_factory=list)
    # --- ground truth (benchmark only; detectors must not read these) ---
    truth_state: FlightState | None = None
    label: AttackType = AttackType.BENIGN
    integrity_truth: IntegrityStatus = IntegrityStatus.VALID
    # multi-label ground truth (every active attack class; empty when benign)
    labels: frozenset[AttackType] = frozenset()
    # ADDITIVE (P4): count of frames this tick that violated the live source's signing
    # policy (bad/missing MAVLink-2 signature; see ``sources.mavlink_live.MavlinkFrameParser``
    # ``secret_key``). Always 0 for this simulated source and for any live source not
    # configured with a signing key -- not detector-visible ground truth, a live-source
    # measurement (the equivalent of a dropped/bad frame count), always 0 by construction
    # here, never read by anything in this module.
    sig_invalid: int = 0


class SimulatedTelemetrySource:
    """Deterministic in-process telemetry source with an optional attack."""

    def __init__(
        self,
        cfg: AegisConfig,
        attack: Attack | None = None,
        seed: int | None = None,
    ) -> None:
        self.cfg = cfg
        self.seed = int(seed if seed is not None else cfg.simulation.get("seed", 42))
        self.sim = FlightSimulator(SimulatorConfig.from_config(cfg.simulation))
        self.encoder = MavlinkEncoder(cfg.message_rates, cfg.simulation.get("noise", {}), self.seed)
        self.decoder = MavlinkDecoder()
        self.attack = attack or NoAttack()
        self.rng = np.random.default_rng(self.seed + 777)
        # Optional benign link impairment (stress test; default OFF so the
        # baseline benchmark is bit-for-bit unchanged). Separate RNG stream.
        link = cfg.simulation.get("link", {}) or {}
        self.link_delay_ms = float(link.get("mean_delay_ms", 0.0))
        self.link_loss_prob = float(link.get("loss_prob", 0.0))
        self.link_fifo = bool(link.get("fifo", True))  # False => independent delays (reordering)
        self.link_rng = np.random.default_rng(self.seed + 4242)
        self._link_last_arrival = -1e18

    def stream(self) -> Iterator[TelemetryTick]:
        for tick, state in enumerate(self.sim.run()):
            t = state.t
            self.attack.before_encode(t, tick, self.encoder)
            pstate = self.attack.perturb_state(t, state)
            packets = self.encoder.encode_tick(pstate, tick)
            ctx = AttackContext(t=t, tick=tick, encoder=self.encoder, rng=self.rng, state=state)
            packets = self.attack.perturb_packets(t, packets, ctx)
            if self.link_delay_ms > 0 or self.link_loss_prob > 0:
                packets = self._impair(packets)
            # Deliver in arrival-time order (matters under the latency attack).
            packets.sort(key=lambda p: p.send_time)

            messages: list[MessageEnvelope] = []
            for p in packets:
                messages.extend(self.decoder.decode(p.data, p.send_time))

            yield TelemetryTick(
                t=t,
                tick=tick,
                messages=messages,
                truth_state=state,
                label=self.attack.label(t),
                integrity_truth=self.attack.integrity_status(t),
                labels=self.attack.labels(t),
            )

    def _impair(self, packets):
        """Benign radio-link imperfection: random loss + exponential delivery delay.

        With ``fifo`` (default) the link is a queue -- frames may be delayed but
        never overtake each other (serial telemetry radio). With ``fifo: false``
        each frame is delayed independently, so frames can arrive out of order
        (e.g. UDP over Wi-Fi / cellular).
        """
        out = []
        for p in packets:
            if self.link_loss_prob > 0 and self.link_rng.random() < self.link_loss_prob:
                continue
            d = self.link_rng.exponential(self.link_delay_ms / 1000.0) if self.link_delay_ms > 0 else 0.0
            arrival = p.send_time + d
            if self.link_fifo:
                arrival = max(arrival, self._link_last_arrival)
                self._link_last_arrival = arrival
            out.append(RawPacket(arrival, p.data))
        return out
