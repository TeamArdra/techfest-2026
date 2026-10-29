// Pure helpers for the ACTIVE IPS confirmation flow and bridge posture control (frontend/tests/).
import type { DefenseMode, Environment } from "../types";

export interface SigningInfo { configured: boolean; unsigned_acknowledged?: boolean }

/** The dialog is needed only for a NON-SIM source switching TO active-ips from another posture. */
export function needsActiveIpsDialog(env: Environment | null | undefined, current: DefenseMode | string | null | undefined, target: DefenseMode): boolean {
  if (!env || env === "SIM") return false;
  return target === "active-ips" && current !== "active-ips";
}

export function signingText(s: SigningInfo | null | undefined): string {
  if (!s) return "Signing: unknown";
  return s.configured ? "Signing: configured" : "Signing: NOT configured";
}

export const UNSIGNED_RISK =
  "On an unsigned link, a forger who copies the pilot's counter-command still gets through. Only MAVLink-2 signing stops it.";

export type PostureResult =
  | { kind: "ok"; status: Record<string, unknown> | null }
  | { kind: "signing_required"; message: string }
  | { kind: "unauthorized"; message: string }
  | { kind: "disabled"; message: string }
  | { kind: "bad_request"; message: string }
  | { kind: "error"; message: string };

/** Map an HTTP status + parsed body (may be null) to a typed result. */
export function parsePostureResponse(httpStatus: number, body: unknown): PostureResult {
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const msg = typeof b.message === "string" ? b.message : "";
  if (httpStatus === 409 && b.error === "signing_required") {
    return { kind: "signing_required", message: msg || "Signing is not configured; active IPS needs explicit unsigned acknowledgement." };
  }
  if (httpStatus === 401) return { kind: "unauthorized", message: "Wrong or missing bridge control token (401). Check Settings." };
  if (httpStatus === 403) return { kind: "disabled", message: "Remote control is disabled on the bridge (403). Start it with --control-token-file." };
  if (httpStatus === 400) return { kind: "bad_request", message: msg || "Bridge rejected the request (400)." };
  if (httpStatus >= 200 && httpStatus < 300 && b.ok !== false) {
    const st = b.status && typeof b.status === "object" ? (b.status as Record<string, unknown>) : null;
    return { kind: "ok", status: st };
  }
  return { kind: "error", message: msg || `Request failed (HTTP ${httpStatus}).` };
}

export function bridgePostureUrl(base: string): string { return base.replace(/\/+$/, "") + "/posture"; }

/** Token travels only in the Authorization header, never in the URL. */
export function bridgeAuthHeaders(token: string): Record<string, string> {
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

export function postureBody(mode: DefenseMode, allowUnsigned?: boolean): string {
  return JSON.stringify(allowUnsigned ? { mode, allow_unsigned: true } : { mode });
}

export function controlHint(controlEnabled: boolean | undefined, hasToken: boolean): string | null {
  if (controlEnabled && hasToken) return null;
  return "Remote posture control unavailable: start the bridge with --control-token-file, then enter the token in Settings.";
}
