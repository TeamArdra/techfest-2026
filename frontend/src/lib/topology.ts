import type { TopologyInfo, TopologyKind, TopologySource } from "../types";

// Read-only wiring report. The operator never selects a topology; the software reports what it
// detected (or what the simulator models).

export interface TopologySelection {
  info: TopologyInfo;
  origin: "bridge" | "backend";
}

const isInfo = (v: unknown): v is TopologyInfo =>
  !!v && typeof v === "object" && typeof (v as TopologyInfo).kind === "string";

// Prefer the inline bridge's own report, fall back to the backend's, else null.
export function selectTopology(
  backend: TopologyInfo | null | undefined,
  bridge: TopologyInfo | null | undefined,
): TopologySelection | null {
  if (isInfo(bridge)) return { info: bridge, origin: "bridge" };
  if (isInfo(backend)) return { info: backend, origin: "backend" };
  return null;
}

export interface CapRow {
  id: "uplink" | "block" | "counter";
  label: string;
  value: boolean | null;
  text: "yes" | "no" | "unknown";
}

export interface LinkRow {
  id: "fc" | "gcs";
  label: string;
  state: "connected" | "disconnected" | "unknown";
  name: string | null;
}

export interface TopologyView {
  kind: TopologyKind;
  badge: string;
  source: TopologySource;
  sourceText: string;
  origin: "bridge" | "backend";
  originText: string;
  caps: CapRow[];
  links: LinkRow[];
  reasons: string[];
  posture: string;
}

export const KIND_BADGE: Record<TopologyKind, string> = {
  A: "A — sidecar monitor",
  "A+B": "A+B — inline bridge",
  SIM: "SIM — modelled",
  REPLAY: "REPLAY — no wiring",
  UNKNOWN: "UNKNOWN",
};

const yn = (v: boolean | null | undefined): { value: boolean | null; text: "yes" | "no" | "unknown" } =>
  v === true ? { value: true, text: "yes" } : v === false ? { value: false, text: "no" } : { value: null, text: "unknown" };

export function describe(sel: TopologySelection): TopologyView {
  const t = sel.info;
  const kind: TopologyKind = t.kind in KIND_BADGE ? t.kind : "UNKNOWN";
  const source: TopologySource = t.source === "detected" || t.source === "modelled" ? t.source : "none";
  const link = (id: "fc" | "gcs", label: string): LinkRow | null => {
    const l = t.links?.[id];
    if (!l) return null;
    const st = l.connected === true ? "connected" : l.connected === false ? "disconnected" : "unknown";
    return { id, label, state: st, name: l.name ?? null };
  };
  const caps: CapRow[] = [
    { id: "uplink", label: "Uplink visible", ...yn(t.uplink_visible) },
    { id: "block", label: "Can block hostile frames", ...yn(t.can_block_frames === true) },
    { id: "counter", label: "Can send counter-commands", ...yn(t.can_send_counter_commands === true) },
  ];
  return {
    kind,
    badge: KIND_BADGE[kind],
    source,
    sourceText: source,
    origin: sel.origin,
    originText: sel.origin === "bridge" ? "from the inline bridge" : "from the backend",
    caps,
    links: [link("fc", "Flight controller link"), link("gcs", "GCS link")].filter((x): x is LinkRow => x !== null),
    reasons: Array.isArray(t.reasons) ? t.reasons : [],
    posture: t.posture,
  };
}
