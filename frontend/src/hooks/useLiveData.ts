import { useEffect, useRef, useState } from "react";
import { api, wsUrl } from "../services/api";
import type {
  AlertRow, Environment, LinkStatus, Metrics, SourceInfo, Telemetry, Threat, Update,
} from "../types";

export interface LiveState {
  connected: boolean; // dashboard <-> backend WebSocket (NOT the vehicle link: see `link`)
  environment: Environment | null; // as reported by the backend; null until it has reported
  source: SourceInfo | null;
  link: LinkStatus | null;
  runId: string | null;
  eventsCount: number | null; // persisted alerts of the current run
  updateAgeS: number | null; // seconds since the last WebSocket update (backend freshness)
  t: number;
  telemetry: Telemetry | null;
  threat: Threat | null;
  attackActive: string | null;
  distance: number; // cumulative simulated flight-path length (m), live
  track: Array<[number, number]>; // recent [lat, lon]
  scoreHistory: Array<{ t: number; score: number }>;
  alerts: AlertRow[];
  metrics: Metrics | null;
}

const MAX_TRACK = 400;
const MAX_HISTORY = 240;

export function useLiveData(): LiveState {
  const [connected, setConnected] = useState(false);
  const [environment, setEnvironment] = useState<Environment | null>(null);
  const [source, setSource] = useState<SourceInfo | null>(null);
  const [link, setLink] = useState<LinkStatus | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [eventsCount, setEventsCount] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const lastUpdateRef = useRef<number | null>(null);
  const runRef = useRef<string | null>(null);
  const [t, setT] = useState(0);
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [threat, setThreat] = useState<Threat | null>(null);
  const [attackActive, setAttackActive] = useState<string | null>(null);
  const [distance, setDistance] = useState(0);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const trackRef = useRef<Array<[number, number]>>([]);
  const histRef = useRef<Array<{ t: number; score: number }>>([]);
  const [, force] = useState(0);

  // WebSocket live telemetry stream (auto-reconnect).
  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let retry: number | undefined;

    const connect = () => {
      ws = new WebSocket(wsUrl());
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = window.setTimeout(connect, 1500);
      };
      ws.onerror = () => ws?.close();
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data) as Update;
        if (msg.type !== "update") return;
        lastUpdateRef.current = Date.now();
        setEnvironment(msg.environment ?? null);
        setSource(msg.source ?? null);
        setLink(msg.link ?? null);
        if (msg.run_id && msg.run_id !== runRef.current) {
          // a new run (SIM reset, or a backend restarted on another source): never mix tracks across runs
          runRef.current = msg.run_id;
          trackRef.current = [];
          histRef.current = [];
          setRunId(msg.run_id);
        }
        setT(msg.t);
        setTelemetry(msg.telemetry);
        setAttackActive(msg.attack_active);
        if (typeof msg.distance_m === "number") setDistance(msg.distance_m);
        if (msg.telemetry.lat != null && msg.telemetry.lon != null) {
          const tr = trackRef.current;
          tr.push([msg.telemetry.lat, msg.telemetry.lon]);
          if (tr.length > MAX_TRACK) tr.shift();
        }
        if (msg.threat) {
          setThreat(msg.threat);
          const h = histRef.current;
          h.push({ t: msg.t, score: msg.threat.threat_score });
          if (h.length > MAX_HISTORY) h.shift();
          force((n) => n + 1);
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

  // Poll REST for the persisted alerts, metrics and status. Status also keeps the source / link current
  // when the WebSocket is silent (a finished or failed source sends no further updates).
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const [ev, m, st] = await Promise.all([api.events(30), api.metrics(), api.status()]);
        if (!alive) return;
        setAlerts(ev.events);
        setEventsCount(ev.count ?? ev.events.length);
        setMetrics(m);
        setEnvironment(st.environment ?? null);
        setSource(st.source ?? null);
        const last = lastUpdateRef.current;
        if (st.link && (last == null || Date.now() - last > 1000)) setLink(st.link);
      } catch {
        /* backend not ready */
      }
    };
    tick();
    const id = window.setInterval(tick, 2000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  // 1 Hz clock for the "time since the last backend update" freshness indicator.
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const last = lastUpdateRef.current;
  return {
    connected,
    environment,
    source,
    link,
    runId,
    eventsCount,
    updateAgeS: last == null ? null : Math.max(0, (now - last) / 1000),
    t,
    telemetry,
    threat,
    attackActive,
    distance,
    track: trackRef.current,
    scoreHistory: histRef.current,
    alerts,
    metrics,
  };
}
