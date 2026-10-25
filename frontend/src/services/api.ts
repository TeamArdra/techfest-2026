// REST + WebSocket endpoints. In the Vite dev server (:5173) requests are
// proxied to the backend on :8000; when served by FastAPI they are same-origin.
import type { DefenseMode, EventsResponse, Metrics, MitigationInfo, Status } from "../types";

const API = "";

export function wsUrl(): string {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  // Dev server proxies /ws to the backend, so same-origin works everywhere.
  return `${proto}://${location.host}/ws/telemetry`;
}

async function jget<T>(path: string): Promise<T> {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

async function jpost<T>(path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const metaEnv = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
  const token =
    (typeof window !== "undefined" && window.localStorage?.getItem("aegis_api_token")) ||
    metaEnv?.VITE_AEGIS_API_TOKEN;
  if (token) {
    headers["X-Aegis-Token"] = String(token);
  }
  const r = await fetch(API + path, {
    method: "POST",
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  return r.json();
}

export const api = {
  status: () => jget<Status>("/api/status"),
  metrics: () => jget<Metrics>("/api/metrics"),
  // the CURRENT run's persisted alerts (hash-chained event log), newest first
  events: (limit = 50) => jget<EventsResponse>(`/api/events?limit=${limit}`),
  config: () => jget<Record<string, unknown>>("/api/config"),
  start: () => jpost("/api/simulation/start"),
  stop: () => jpost("/api/simulation/stop"),
  reset: () => jpost("/api/simulation/reset"),
  attack: (attack: string | null, mode?: string, drift_rate_ms?: number) =>
    jpost("/api/simulation/attack", { attack, mode, drift_rate_ms }),
  forensic: (limit = 200) => jget<Record<string, unknown>>(`/api/events/forensic?limit=${limit}`),
  setDefenseMode: (mode: DefenseMode) => jpost<{ ok: boolean; mode: DefenseMode }>("/api/defense/mode", { mode }),
  defenseOverride: (action: "safe_hold" | "reset_quarantine" | "ack_takeover") =>
    jpost<{ ok: boolean; action: string; mitigation: MitigationInfo }>("/api/defense/override", { action }),
  getTopology: () => jget<{ ok: boolean; topology: string; reasons: string[]; available: string[] }>("/api/topology"),
  setTopology: (topology: string) =>
    jpost<{ ok: boolean; topology: string; reasons: string[] }>("/api/topology", { topology }),
};
