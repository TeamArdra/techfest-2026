// Presentation-only: turn the backend's own source + link report into display text. Nothing here
// decides anything — the backend derives `environment` (never user-settable) and the link `state`
// (backend/engine.py link_status); this module only words them, so the dashboard cannot present
// simulated, replayed or stale data as live physical telemetry. Pure functions (frontend/tests/).
import type { Environment, GpsLink, LinkStatus } from "../types";

export interface EnvView {
  badge: Environment | "—";
  label: string;
  footer: string;
  telemetryNote: string;
  trackNote: string;
  distanceNote: string;
  emptyAlerts: string;
  clockLabel: string;
  controls: boolean; // the backend accepts control / attack requests only for SIM (HTTP 409 otherwise)
}

const NON_SIM_EMPTY = "No alerts persisted for this run.";

const VIEWS: Record<Environment, EnvView> = {
  SIM: {
    badge: "SIM",
    label: "Simulation",
    footer: "All flight data and attacks shown are local simulations — this source is not a real UAV.",
    telemetryNote: "simulated airframe state",
    trackNote: "simulated",
    distanceNote: "Flight path · simulated",
    emptyAlerts: "No incidents logged. Inject an attack to generate a tamper-evident event record.",
    clockLabel: "Mission clock",
    controls: true,
  },
  REPLAY: {
    badge: "REPLAY",
    label: "Replay · not live",
    footer: "Recorded or loopback telemetry replayed through the IDS — not live and not a flight. Read-only.",
    telemetryNote: "replayed telemetry · not live",
    trackNote: "replayed positions",
    distanceNote: "Reported-position path · replay",
    emptyAlerts: NON_SIM_EMPTY,
    clockLabel: "Replay clock",
    controls: false,
  },
  SITL: {
    badge: "SITL",
    label: "SITL · UDP",
    footer: "Telemetry received on a local UDP link, sender not verified — a software-in-the-loop setup, not a physical vehicle. Read-only.",
    telemetryNote: "SITL telemetry · sender not verified",
    trackNote: "SITL positions",
    distanceNote: "Reported-position path · SITL",
    emptyAlerts: NON_SIM_EMPTY,
    clockLabel: "Source clock",
    controls: false,
  },
  BENCH: {
    badge: "BENCH",
    label: "Bench · live serial",
    footer: "Live receive-only telemetry from a serial link on a bench — not flight data. The IDS never transmits; frame origin is not authenticated (unsigned link).",
    telemetryNote: "bench telemetry · not flight data",
    trackNote: "reported positions · bench, not flight",
    distanceNote: "Reported-position path · bench, not flight",
    emptyAlerts: NON_SIM_EMPTY,
    clockLabel: "Monitor clock",
    controls: false,
  },
};

const UNKNOWN_VIEW: EnvView = {
  badge: "—",
  label: "Connecting…",
  footer: "Waiting for the backend to report its telemetry source.",
  telemetryNote: "source not reported yet",
  trackNote: "source not reported yet",
  distanceNote: "Reported-position path",
  emptyAlerts: "No alerts yet.",
  clockLabel: "Source clock",
  controls: false,
};

export function envView(env: Environment | null | undefined): EnvView {
  return (env && VIEWS[env]) || UNKNOWN_VIEW;
}

export type Tone = "on" | "off" | "warn" | "idle" | "sim";

export interface LinkView {
  label: string;
  tone: Tone;
  detail: string;
}

export function fmtAge(s: number | null | undefined): string {
  return s == null ? "—" : `${s.toFixed(1)} s`;
}

function num(v: unknown): number | null {
  return typeof v === "number" ? v : null;
}

// What the VEHICLE itself reports about its position solution, worded next to the receiver's "valid
// fix" so a 3D fix is never the only thing an operator sees. Passive: this is not an alert and not an
// authenticity check (a spoofer can report a clean fix). null = nothing to say (healthy or unknown).
export function gpsNote(gps: GpsLink | null | undefined): string | null {
  const parts: string[] = [];
  if (gps?.horizontal_solution === false) parts.push("autopilot reports no horizontal position solution");
  if (gps?.gps_healthy === false) parts.push("autopilot marks the GPS sensor unhealthy");
  // Stale is not healthy: once the autopilot's last position-solution report is older than the backend's 2 s
  // freshness rule the state is unknown, and "no warning" there would read as "all clear".
  if (gps?.horizontal_solution == null && typeof gps?.ekf_age_s === "number" && gps.ekf_age_s > 2) {
    parts.push(`autopilot position-solution report is stale (${Math.round(gps.ekf_age_s)} s old)`);
  }
  return parts.length ? `${parts.join(" · ")} — treat this position as unconfirmed` : null;
}

// `updateAgeS`: seconds since the dashboard last received ANY update from the backend. The backend
// pushes one per tick while a source runs (a dead live link still ticks), so silence there means the
// backend itself stopped — except after "ended" / "error", which are final and send nothing more.
export function linkView(
  link: LinkStatus | null | undefined,
  backendConnected: boolean,
  updateAgeS: number | null,
  environment?: Environment | null,
): LinkView {
  if (!link) {
    return backendConnected
      ? { label: "No data", tone: "idle", detail: "the backend has not reported a link yet" }
      : { label: "Backend offline", tone: "off", detail: "no connection to the AegisFlight backend" };
  }
  const final = link.state === "ended" || link.state === "error";
  const silence = Math.max(3, link.stale_after_s ?? 3);
  if (!final && updateAgeS != null && updateAgeS > silence) {
    return { label: "No updates", tone: "warn", detail: `no update from the backend for ${fmtAge(updateAgeS)}` };
  }
  const tr = link.transport ?? {};
  switch (link.state) {
    case "simulated":
      return { label: "Simulated", tone: "sim", detail: "in-process simulator, no external link" };
    case "live":
      // a replayed file is "flowing", not a live link: never word it as live
      return { label: environment === "REPLAY" ? "Replaying" : "Live", tone: "on", detail: `last frame ${fmtAge(link.last_frame_age_s)} ago · ${link.frames} frames` };
    case "waiting":
      return { label: "Waiting for data", tone: "warn", detail: "source open, no MAVLink frame received yet" };
    case "stale":
      return {
        label: "Stale",
        tone: "warn",
        detail: `no frame for ${fmtAge(link.last_frame_age_s)} (> ${fmtAge(link.stale_after_s)})`,
      };
    case "disconnected": {
      const fails = num(tr.open_failures);
      return {
        label: "Disconnected",
        tone: "off",
        detail: `transport down${fails ? ` · ${fails} open failure${fails === 1 ? "" : "s"}` : ""}`,
      };
    }
    case "ended":
      return { label: "Ended", tone: "idle", detail: `source finished · ${link.frames} frames` };
    case "error":
      return { label: "Source error", tone: "off", detail: link.error ?? "the source failed" };
    default:
      return { label: String(link.state), tone: "idle", detail: "" };
  }
}
