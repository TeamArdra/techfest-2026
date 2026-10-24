// REST + WebSocket endpoints. In the Vite dev server (:5173) requests are
// proxied to the backend on :8000; when served by FastAPI they are same-origin.
import type { EventsResponse, Metrics, Status } from "../types";

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
  const r = await fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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
  attack: (attack: string | null) => jpost("/api/simulation/attack", { attack }),
};
