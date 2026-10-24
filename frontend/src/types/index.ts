// Types mirroring the FastAPI backend payloads (see src/aegisflight/backend).

export interface Telemetry {
  lat: number | null;
  lon: number | null;
  alt_msl: number | null;
  rel_alt: number | null;
  groundspeed: number | null;
  heading: number | null;
  battery_voltage: number | null;
  battery_remaining: number | null;
  satellites: number | null;
  flight_mode: string | null;
  armed: boolean | null;
}

export interface Threat {
  threat: boolean;
  threat_score: number;
  severity: string;
  attack_type: string;
  confidence: number;
  evidence: string[];
  detector_scores: Record<string, number>;
  contributing_detectors: string[];
  integrity_status: string;
  latency_ms: number;
  is_alert: boolean;
}

// Derived by the backend from the configured source (backend/sources.py); never user-settable.
export type Environment = "SIM" | "REPLAY" | "SITL" | "BENCH";
export type LinkState = "simulated" | "waiting" | "live" | "stale" | "disconnected" | "ended" | "error";

export interface SourceInfo {
  kind: "sim" | "replay" | "serial" | "udp";
  environment: Environment;
  physical: boolean;
  label: string;
  detail: Record<string, unknown>;
  ml: boolean;
  config_dir: string;
}

export interface GpsLink {
  fix_type: number | null;
  fix_name: string | null;
  satellites: number | null;
  valid_fix: boolean | null;
  gps_raw_age_s: number | null;
  position_age_s: number | null;
  position_zero: boolean | null;
}

// Application-level link health (backend/engine.py link_status); ages are on the source's tick clock.
export interface LinkStatus {
  state: LinkState;
  frames: number;
  last_frame_age_s: number | null;
  stale_after_s: number;
  messages: Record<string, { count: number; age_s: number | null }>;
  transport: Record<string, unknown> | null;
  gps: GpsLink;
  error: string | null;
}

export interface Update {
  type: "update";
  sim: boolean;
  environment: Environment;
  source: SourceInfo;
  link: LinkStatus;
  run_id: string;
  t: number;
  telemetry: Telemetry;
  attack_active: string | null;
  distance_m: number;
  threat?: Threat;
}

// One persisted alert of the current run, as stored in the hash-chained event log (/api/events).
export interface AlertRow {
  id: number | null;
  run_id?: string;
  environment?: Environment;
  t: number;
  wall_time?: number;
  attack_type: string;
  severity: string;
  threat_score: number;
  confidence: number;
  evidence: string[];
  integrity_status: string;
  latency_ms: number;
  hash?: string;
  prev_hash?: string;
}

export interface EventsResponse {
  events: AlertRow[];
  run_id: string;
  source: SourceInfo;
  count: number;
}

export interface Status {
  running: boolean;
  sim: boolean;
  environment: Environment;
  source: SourceInfo;
  link: LinkStatus;
  sim_time_s: number;
  uptime_s: number;
  active_attack: string | null;
  ml_available: boolean;
  threat: boolean;
  severity: string;
  attack_type: string;
  threat_score: number;
  integrity_status: string;
  run_id: string;
}

export interface Metrics {
  messages_processed: number;
  decisions: number;
  alerts: number;
  throughput_msgs_per_s: number;
  decision_compute_ms: number | null;
  last_latency_ms: number | null; // legacy alias of decision_compute_ms
  time_to_detect_s: number | null;
  distance_m: number;
  event_log: { count: number; chain_ok: boolean };
  ml_available: boolean;
  environment?: Environment;
}
