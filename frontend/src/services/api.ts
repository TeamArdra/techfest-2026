// REST + WebSocket endpoints. In the Vite dev server (:5173) requests are
// proxied to the backend on :8000; when served by FastAPI they are same-origin.
import type { DefenseMode, EventsResponse, Metrics, MitigationInfo, Status } from "../types";

import { bridgeAuthHeaders, bridgePostureUrl, parsePostureResponse, postureBody, type PostureResult, type SigningInfo } from "../lib/posture";
import { isHttpUrl, normalizeUrl, resolveBackend, resolveWsUrl } from "./backend";

export const BACKEND_KEY = "aegis_backend_url";
export const BRIDGE_KEY = "aegis_bridge_url";
export const BRIDGE_TOKEN_KEY = "aegis_bridge_token";

function lsGet(k: string): string | null {
  try { return window.localStorage?.getItem(k) ?? null; } catch { return null; }
}

/** Base URL for every REST call and the WebSocket ('' = same origin). Resolved per call so settings apply live. */
export function backendBase(): string {
  const metaEnv = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
  return resolveBackend({
    win: (window as unknown as { __AEGIS_BACKEND__?: string }).__AEGIS_BACKEND__ ?? null,
    stored: lsGet(BACKEND_KEY),
    vite: metaEnv?.VITE_BACKEND_URL ?? null,
    protocol: location.protocol,
    hostname: location.hostname,
  });
}

export function wsUrl(): string {
  return resolveWsUrl(backendBase(), location.protocol, location.host);
}

export function getBridgeToken(): string { return lsGet(BRIDGE_TOKEN_KEY) ?? ""; }
export function saveBridgeToken(v: string): void {
  try { v.trim() ? window.localStorage.setItem(BRIDGE_TOKEN_KEY, v.trim()) : window.localStorage.removeItem(BRIDGE_TOKEN_KEY); } catch { /* storage unavailable */ }
}

/** POST <bridge>/posture; token goes only in the Authorization header. Never throws. */
export async function setBridgePosture(url: string, token: string, mode: DefenseMode, allowUnsigned?: boolean): Promise<PostureResult> {
  try {
    const r = await fetch(bridgePostureUrl(url), { method: "POST", headers: bridgeAuthHeaders(token), body: postureBody(mode, allowUnsigned) });
    let body: unknown = null;
    try { body = await r.json(); } catch { /* non-JSON body */ }
    return parsePostureResponse(r.status, body);
  } catch {
    return { kind: "error", message: "Bridge unreachable (network error)." };
  }
}

export function getBridgeUrl(): string | null {
  const v = lsGet(BRIDGE_KEY);
  return v && isHttpUrl(v) ? normalizeUrl(v) : null;
}

/** Save (or clear with "") a URL setting; returns an error string for invalid input. */
export function saveUrlSetting(key: string, value: string): string | null {
  const v = value.trim();
  try {
    if (!v) { window.localStorage.removeItem(key); return null; }
    if (!isHttpUrl(v)) return "Must be an http(s):// URL";
    window.localStorage.setItem(key, normalizeUrl(v));
    return null;
  } catch {
    return "Browser storage unavailable";
  }
}
export function getUrlSetting(key: string): string { return lsGet(key) ?? ""; }

async function jget<T>(path: string): Promise<T> {
  const r = await fetch(backendBase() + path);
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
  const r = await fetch(backendBase() + path, {
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
  setDefenseMode: (mode: DefenseMode, allowUnsigned?: boolean) =>
    jpost<{ ok: boolean; mode?: DefenseMode; error?: string; message?: string; signing?: SigningInfo }>(
      "/api/defense/mode", allowUnsigned ? { mode, allow_unsigned: true } : { mode }),
  defenseOverride: (action: "safe_hold" | "reset_quarantine" | "ack_takeover") =>
    jpost<{ ok: boolean; action: string; mitigation: MitigationInfo }>("/api/defense/override", { action }),
};
