// Backend / bridge URL resolution. Pure (inputs injected) so it is unit tested without a DOM.
export interface BackendEnv {
  win?: string | null;      // window.__AEGIS_BACKEND__
  stored?: string | null;   // localStorage aegis_backend_url
  vite?: string | null;     // import.meta.env.VITE_BACKEND_URL
  protocol?: string;        // location.protocol
  hostname?: string;        // location.hostname
  host?: string;            // location.host
}

export function isHttpUrl(s: string | null | undefined): boolean {
  if (!s) return false;
  try {
    const u = new URL(s.trim());
    return (u.protocol === "http:" || u.protocol === "https:") && !!u.hostname;
  } catch {
    return false;
  }
}

export function normalizeUrl(s: string): string {
  return s.trim().replace(/\/+$/, "");
}

export function isTauri(protocol?: string, hostname?: string): boolean {
  return protocol === "tauri:" || hostname === "tauri.localhost";
}

/** Base URL ('' = same origin) following: window override, stored setting, build env, Tauri default, same-origin. */
export function resolveBackend(e: BackendEnv): string {
  for (const c of [e.win, e.stored, e.vite]) {
    if (c && isHttpUrl(c)) return normalizeUrl(c);
  }
  if (isTauri(e.protocol, e.hostname)) return "http://127.0.0.1:8000";
  return "";
}

/** WebSocket URL for the telemetry stream given the resolved base. */
export function resolveWsUrl(base: string, protocol: string | undefined, host: string | undefined): string {
  if (base) return base.replace(/^http/i, "ws") + "/ws/telemetry";
  const proto = protocol === "https:" ? "wss" : "ws";
  return `${proto}://${host}/ws/telemetry`;
}
