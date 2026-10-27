import { useEffect, useReducer, useRef } from "react";
import { api, wsUrl } from "../services/api";
import type {
  AlertRow, DefenseMode, Environment, LinkStatus, Metrics, MitigationInfo, SourceInfo, Telemetry, Threat, Update,
} from "../types";

export interface LiveState {
  connected: boolean; // dashboard <-> backend WebSocket (NOT the vehicle link: see `link`)
  environment: Environment | null; // as reported by the backend; null until it has reported
  source: SourceInfo | null;
  defenseMode: DefenseMode;
  mitigation: MitigationInfo | null;
  link: LinkStatus | null;
  runId: string | null;
  eventsCount: number | null; // persisted alerts of the current run
  updateAgeS: number | null; // seconds since the last WebSocket update (backend freshness)
  t: number;
  telemetry: Telemetry | null;
  sanitizedTelemetry: Telemetry | null;
  threat: Threat | null;
  attackActive: string | null;
  distance: number; // cumulative simulated flight-path length (m), live
  track: Array<[number, number]>; // effective vehicle [lat, lon] (IPS-restored when active-ips)
  trackThreat: boolean[]; // index-aligned with `track`: true where that fix was flown under threat
  rawTrack: Array<[number, number]>; // raw un-sanitized GPS [lat, lon] for the CURRENT attack episode only
  scoreHistory: Array<{ t: number; score: number }>;
  altHistory: Array<{ t: number; rawAlt: number; effAlt: number; diverging: boolean }>;
  topology: string;
  topologyReasons: string[];
  alerts: AlertRow[];
  metrics: Metrics | null;
}

const MAX_TRACK = 400;
const MAX_HISTORY = 240;

interface ReducerState {
  connected: boolean;
  environment: Environment | null;
  source: SourceInfo | null;
  defenseMode: DefenseMode;
  topology: string;
  topologyReasons: string[];
  mitigation: MitigationInfo | null;
  link: LinkStatus | null;
  runId: string | null;
  eventsCount: number | null;
  lastUpdate: number | null;
  now: number;
  t: number;
  telemetry: Telemetry | null;
  sanitizedTelemetry: Telemetry | null;
  threat: Threat | null;
  attackActive: string | null;
  distance: number;
  track: Array<[number, number]>;
  trackThreat: boolean[];
  rawTrack: Array<[number, number]>;
  scoreHistory: Array<{ t: number; score: number }>;
  altHistory: Array<{ t: number; rawAlt: number; effAlt: number; diverging: boolean }>;
  alerts: AlertRow[];
  metrics: Metrics | null;
}

const initialState: ReducerState = {
  connected: false,
  environment: null,
  source: null,
  defenseMode: "passive",
  topology: "b",
  topologyReasons: [],
  mitigation: null,
  link: null,
  runId: null,
  eventsCount: null,
  lastUpdate: null,
  now: Date.now(),
  t: 0,
  telemetry: null,
  sanitizedTelemetry: null,
  threat: null,
  attackActive: null,
  distance: 0,
  track: [],
  trackThreat: [],
  rawTrack: [],
  scoreHistory: [],
  altHistory: [],
  alerts: [],
  metrics: null,
};

type Action =
  | { type: "WS_OPEN" }
  | { type: "WS_CLOSE" }
  | { type: "UPDATE"; payload: Update; now: number }
  | { type: "POLL"; events: AlertRow[]; count: number; metrics: Metrics; status: any }
  | { type: "TICK"; now: number };

function liveReducer(state: ReducerState, action: Action): ReducerState {
  switch (action.type) {
    case "WS_OPEN":
      return { ...state, connected: true };
    case "WS_CLOSE":
      return { ...state, connected: false };
    case "TICK":
      return { ...state, now: action.now };
    case "POLL": {
      const st = action.status;
      const last = state.lastUpdate;
      return {
        ...state,
        alerts: action.events,
        eventsCount: action.count,
        metrics: action.metrics,
        environment: st?.environment ?? state.environment,
        source: st?.source ?? state.source,
        defenseMode: st?.defense_mode ?? (st?.source?.defense_mode || state.defenseMode),
        topology: st?.topology ?? state.topology,
        topologyReasons: st?.topology_reasons ?? state.topologyReasons,
        mitigation: st?.mitigation ?? state.mitigation,
        link: st?.link && (last == null || Date.now() - last > 1000) ? st.link : state.link,
      };
    }
    case "UPDATE": {
      const msg = action.payload;
      const isNewRun = msg.run_id && msg.run_id !== state.runId;

      const currentMode = msg.defense_mode ?? (msg.source?.defense_mode || state.defenseMode);
      const isIps = currentMode === "active-ips";
      const effTele = isIps && msg.sanitized_telemetry ? msg.sanitized_telemetry : msg.telemetry;
      const trimmed = state.track.length >= MAX_TRACK;
      const newTrack = isNewRun ? [] : trimmed ? state.track.slice(-(MAX_TRACK - 1)) : state.track.slice();
      // Per-point "flown under threat" flag, kept index-aligned with `track` so the
      // map highlights only the segment flown during an attack, not the whole history.
      const newTrackThreat = isNewRun ? [] : trimmed ? state.trackThreat.slice(-(MAX_TRACK - 1)) : state.trackThreat.slice();
      if (effTele?.lat != null && effTele?.lon != null) {
        newTrack.push([effTele.lat, effTele.lon]);
        const underThreat = !!(msg.threat?.threat ?? state.threat?.threat) || !!msg.attack_active;
        newTrackThreat.push(underThreat);
      }

      // The raw (pre-sanitization) track only feeds the rejected-GPS ghost overlay, so it
      // is scoped to the CURRENT attack episode: switching or clearing the attack starts a
      // fresh ghost. Otherwise an earlier GPS-spoof excursion would be redrawn (and
      // mislabelled) during a later, unrelated attack such as DoS or telemetry manipulation.
      const attackChanged = (msg.attack_active ?? null) !== state.attackActive;
      const newRawTrack = isNewRun || attackChanged ? [] : state.rawTrack.length >= MAX_TRACK ? state.rawTrack.slice(-(MAX_TRACK - 1)) : state.rawTrack.slice();
      if (msg.telemetry?.lat != null && msg.telemetry?.lon != null) {
        newRawTrack.push([msg.telemetry.lat, msg.telemetry.lon]);
      }

      const newHistory = isNewRun ? [] : state.scoreHistory.length >= MAX_HISTORY ? state.scoreHistory.slice(-(MAX_HISTORY - 1)) : state.scoreHistory.slice();
      if (msg.threat) {
        newHistory.push({ t: msg.t, score: msg.threat.threat_score });
      }

      const rawAlt = msg.telemetry?.rel_alt ?? msg.telemetry?.alt_msl ?? 60.0;
      const effAlt = effTele?.rel_alt ?? effTele?.alt_msl ?? 60.0;
      const diverging = isIps && Math.abs(rawAlt - effAlt) > 1.5;
      const newAltHistory = isNewRun ? [] : state.altHistory.length >= MAX_HISTORY ? state.altHistory.slice(-(MAX_HISTORY - 1)) : state.altHistory.slice();
      newAltHistory.push({ t: msg.t, rawAlt, effAlt, diverging });

      return {
        ...state,
        lastUpdate: action.now,
        environment: msg.environment ?? state.environment,
        source: msg.source ?? state.source,
        defenseMode: msg.defense_mode ?? (msg.source?.defense_mode || state.defenseMode),
        topology: msg.topology ?? state.topology,
        topologyReasons: msg.topology_reasons ?? state.topologyReasons,
        mitigation: msg.mitigation ?? state.mitigation,
        link: msg.link ?? state.link,
        runId: msg.run_id ?? state.runId,
        t: msg.t,
        telemetry: msg.telemetry,
        sanitizedTelemetry: msg.sanitized_telemetry ?? msg.telemetry,
        attackActive: msg.attack_active,
        distance: typeof msg.distance_m === "number" ? msg.distance_m : state.distance,
        threat: msg.threat ?? state.threat,
        track: newTrack,
        trackThreat: newTrackThreat,
        rawTrack: newRawTrack,
        scoreHistory: newHistory,
        altHistory: newAltHistory,
      };
    }
    default:
      return state;
  }
}

export function useLiveData(): LiveState {
  const [state, dispatch] = useReducer(liveReducer, initialState);
  const stateRef = useRef(state);
  stateRef.current = state;

  // WebSocket live telemetry stream (auto-reconnect).
  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let retry: number | undefined;

    const connect = () => {
      ws = new WebSocket(wsUrl());
      ws.onopen = () => dispatch({ type: "WS_OPEN" });
      ws.onclose = () => {
        dispatch({ type: "WS_CLOSE" });
        if (!closed) retry = window.setTimeout(connect, 1500);
      };
      ws.onerror = () => ws?.close();
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as Update;
          if (msg.type === "update") {
            dispatch({ type: "UPDATE", payload: msg, now: Date.now() });
          }
        } catch {
          // ignore corrupted frame
        }
      };
    };
    connect();
    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      ws?.close();
    };
  }, []);

  // Poll REST for the persisted alerts, metrics and status.
  // Throttles polling during active mitigation (state !== "NOMINAL") to save companion CPU & bandwidth.
  useEffect(() => {
    let alive = true;
    let timerId: number | undefined;

    const poll = async () => {
      try {
        const [ev, m, st] = await Promise.all([api.events(30), api.metrics(), api.status()]);
        if (!alive) return;
        dispatch({
          type: "POLL",
          events: ev.events,
          count: ev.count ?? ev.events.length,
          metrics: m,
          status: st,
        });
      } catch {
        /* backend not ready */
      } finally {
        if (alive) {
          const isMitigating = stateRef.current.mitigation && stateRef.current.mitigation.state !== "NOMINAL";
          const delay = isMitigating ? 5000 : 2000;
          timerId = window.setTimeout(poll, delay);
        }
      }
    };

    poll();
    return () => {
      alive = false;
      if (timerId) clearTimeout(timerId);
    };
  }, []);

  // 1 Hz clock for the "time since the last backend update" freshness indicator.
  useEffect(() => {
    const id = window.setInterval(() => dispatch({ type: "TICK", now: Date.now() }), 1000);
    return () => clearInterval(id);
  }, []);

  const last = state.lastUpdate;
  return {
    connected: state.connected,
    environment: state.environment,
    source: state.source,
    defenseMode: state.defenseMode,
    mitigation: state.mitigation,
    link: state.link,
    runId: state.runId,
    eventsCount: state.eventsCount,
    updateAgeS: last == null ? null : Math.max(0, (state.now - last) / 1000),
    t: state.t,
    telemetry: state.telemetry,
    sanitizedTelemetry: state.sanitizedTelemetry,
    threat: state.threat,
    attackActive: state.attackActive,
    distance: state.distance,
    track: state.track,
    trackThreat: state.trackThreat,
    rawTrack: state.rawTrack,
    scoreHistory: state.scoreHistory,
    altHistory: state.altHistory,
    topology: state.topology,
    topologyReasons: state.topologyReasons,
    alerts: state.alerts,
    metrics: state.metrics,
  };
}
