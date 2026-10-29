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

export type DefenseMode = "passive" | "advisory" | "active-ips";
export type MitigationState = "NOMINAL" | "AUTO_MITIGATING" | "SAFE_HOLD" | "GCS_TAKEOVER";

export interface AttackParameters {
  attack_type: string;
  sub_mode: string;
  trusted_lat: number | null;
  trusted_lon: number | null;
  trusted_alt_m: number | null;
  trusted_mode: string | null;
  lat_offset_deg: number;
  lon_offset_deg: number;
  north_offset_m: number;
  east_offset_m: number;
  drift_rate_ms: number;
  alt_bias_m: number;
  speed_bias_ms: number;
  battery_bias_v: number;
  rogue_sysids: number[];
  target_restore_mode: string | null;
}

export interface MitigationInputs {
  trusted_lat: number | null;
  trusted_lon: number | null;
  trusted_alt_m: number | null;
  trusted_mode: string | null;
}

export interface MitigationOutputs {
  north_offset_m: number;
  east_offset_m: number;
  drift_rate_ms: number;
  alt_bias_m: number;
  speed_bias_ms: number;
  battery_bias_v: number;
  rogue_sysids: number[];
  target_restore_mode: string | null;
  quarantined_sysids: number[];
  sanitize_gps: boolean;
  sanitize_alt: boolean;
  ekf_switched: boolean;
  last_command_sent: string | null;
  counter_frames_sent: number;
}

export interface MitigationActionItem {
  t: number;
  tag: string;
  detail: string;
}

export interface MitigationInfo {
  t: number;
  mode: DefenseMode;
  state: MitigationState;
  sub_mode: string;
  clean_streak: number;
  recovery_target_ticks: number;
  recovery_progress?: number;
  counter_frames_sent: number;
  quarantined_sysids: number[];
  sanitize_gps: boolean;
  sanitize_alt: boolean;
  ekf_switched: boolean;
  last_command_sent: string | null;
  actions?: MitigationActionItem[];
  inputs?: MitigationInputs;
  outputs?: MitigationOutputs;
  params?: AttackParameters;
  summary: string;
}

export interface SourceInfo {
  kind: "sim" | "replay" | "serial" | "udp";
  environment: Environment;
  physical: boolean;
  label: string;
  detail: Record<string, unknown>;
  ml: boolean;
  config_dir: string;
  defense_mode?: DefenseMode;
}

export interface GpsLink {
  fix_type: number | null;
  fix_name: string | null;
  satellites: number | null;
  valid_fix: boolean | null;
  gps_raw_age_s: number | null;
  position_age_s: number | null;
  position_zero: boolean | null;
  // vehicle-stated estimator / GPS health (core/gps_health.py); optional: absent on older backends.
  // null = unknown. Not an authenticity check.
  hdop?: number | null;
  ekf_flags?: number | null;
  ekf_age_s?: number | null;
  horizontal_solution?: boolean | null;
  gps_healthy?: boolean | null;
  quality_flags?: string[];
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

export interface Checks {
  mission: { known: boolean; xtrack_m: number | null; wp_seq: number | null };
  crossend: { active: boolean; matched: number; mismatches: number; last_summary_age_s: number | null };
  receiver: { ekf_vel_var: number | null; ekf_pos_var: number | null; sat_jump: number | null; snr_spread: number | null };
}

export type TopologyKind = "A" | "A+B" | "SIM" | "REPLAY" | "UNKNOWN";
export type TopologySource = "detected" | "modelled" | "none";

export interface TopologyLink {
  connected: boolean | null;
  name: string | null;
}

// Read-only wiring report produced by the backend (or the inline bridge). Never operator-selected.
export interface TopologyInfo {
  kind: TopologyKind;
  label: string;
  source: TopologySource;
  posture: DefenseMode;
  links: { fc?: TopologyLink; gcs?: TopologyLink };
  uplink_visible: boolean | null;
  can_block_frames: boolean;
  can_send_counter_commands: boolean;
  reasons: string[];
}

export interface BridgeStatus {
  topology?: TopologyInfo | null;
  mode?: string;
  state?: string;
  frames?: Record<string, number>;
  latency_us?: { p50?: number; p95?: number; max?: number; samples?: number };
  policy?: Record<string, number | boolean | string | null>;
  signing?: { configured: boolean; unsigned_acknowledged?: boolean };
  control?: { enabled: boolean };
  analyser?: { decisions?: number; alerts?: number; errors?: number; counter_frames_sent?: number; summary?: unknown };
  last_error?: string | null;
  crossend?: { sent?: number };
}

export interface Update {
  type: "update";
  sim: boolean;
  environment: Environment;
  source: SourceInfo;
  defense_mode?: DefenseMode;
  signing?: { configured: boolean; unsigned_acknowledged?: boolean };
  topology_info?: TopologyInfo | null;
  mitigation?: MitigationInfo;
  link: LinkStatus;
  checks?: Checks | null;
  run_id: string;
  t: number;
  telemetry: Telemetry;
  sanitized_telemetry?: Telemetry;
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
  defense_mode?: DefenseMode;
  signing?: { configured: boolean; unsigned_acknowledged?: boolean };
  topology_info?: TopologyInfo | null;
  mitigation?: MitigationInfo;
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
