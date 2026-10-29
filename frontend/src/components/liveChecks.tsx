import { useEffect, useState } from "react";
import { getBridgeUrl } from "../services/api";
import type { BridgeStatus, Checks } from "../types";

const f = (v: number | null | undefined, d = 2) => (typeof v === "number" && Number.isFinite(v) ? v.toFixed(d) : "—");

// Backend-computed checks for non-SIM sources (mission path, cross-end, receiver health).
export function ChecksPanel({ checks }: { checks: Checks | null }) {
  if (!checks) {
    return (
      <div className="panel" data-testid="checks-panel">
        <header><span className="panel-title">Checks</span><span className="panel-note">not reported</span></header>
      </div>
    );
  }
  const { mission, crossend, receiver } = checks;
  const mism = crossend.mismatches > 0;
  return (
    <div className="panel" data-testid="checks-panel">
      <header><span className="panel-title">Checks</span><span className="panel-note">live-link integrity checks</span></header>
      <div className="source-bar" style={{ flexWrap: "wrap" }}>
        <span>Mission path: {mission.known
          ? <>xtrack <b>{f(mission.xtrack_m, 1)} m</b>{mission.wp_seq != null ? ` · wp ${mission.wp_seq}` : ""}</>
          : <b>unknown (no mission known)</b>}</span>
        <span data-testid="crossend" style={mism ? { color: "var(--crit)", fontWeight: 700 } : undefined}>
          Cross-end: {crossend.active
            ? <>matched <b>{crossend.matched}</b> · mismatches <b>{crossend.mismatches}</b> · summary age <b>{f(crossend.last_summary_age_s, 1)} s</b>{mism ? " — WARNING: mismatch" : ""}</>
            : <b>inactive</b>}
        </span>
        <span>Receiver: EKF vel var <b>{f(receiver.ekf_vel_var)}</b> · pos var <b>{f(receiver.ekf_pos_var)}</b> · sat jump <b>{f(receiver.sat_jump, 0)}</b> · SNR spread <b>{f(receiver.snr_spread)}</b></span>
      </div>
    </div>
  );
}

// Polls the optional inline-IPS bridge /status every 2 s; hidden when no URL is configured.
export function useBridge() {
  const url = getBridgeUrl();
  const [st, setSt] = useState<BridgeStatus | null>(null);
  const [bad, setBad] = useState(false);
  useEffect(() => {
    if (!url) return;
    let alive = true;
    let id: number | undefined;
    const poll = async () => {
      try {
        const r = await fetch(url + "/status");
        if (!r.ok) throw new Error(String(r.status));
        const j = (await r.json()) as BridgeStatus;
        if (alive) { setSt(j); setBad(false); }
      } catch {
        if (alive) setBad(true);
      } finally {
        if (alive) id = window.setTimeout(poll, 2000);
      }
    };
    poll();
    return () => { alive = false; if (id) clearTimeout(id); };
  }, [url]);
  return { url, st, bad };
}

export function BridgePanel({ url, st, bad }: { url: string | null; st: BridgeStatus | null; bad: boolean }) {
  if (!url) return null;
  if (bad || !st) {
    return (
      <div className="panel" data-testid="bridge-panel">
        <header><span className="panel-title">Inline IPS bridge</span><span className="panel-note">{url}</span></header>
        <div className="source-bar"><span style={{ color: bad ? "var(--crit)" : undefined }}>{bad ? "bridge unreachable" : "connecting…"}</span></div>
      </div>
    );
  }
  const p = st.policy ?? {};
  const fr = st.frames ?? {};
  const n = (v: unknown) => (typeof v === "number" ? v : 0);
  return (
    <div className="panel" data-testid="bridge-panel">
      <header><span className="panel-title">Inline IPS bridge</span><span className="panel-note">{url}</span></header>
      <div className="source-bar" style={{ flexWrap: "wrap" }}>
        <span>posture <b>{st.mode ?? "—"}</b> · state <b>{st.state ?? "—"}</b></span>
        <span>frames down/up <b>{n(fr.down)}/{n(fr.up)}</b> · dropped <b>{n(fr.dropped_down) + n(fr.dropped_up)}</b> · send failures <b>{n(fr.send_failures)}</b></span>
        <span>latency p95 <b>{f(st.latency_us?.p95, 0)} µs</b></span>
        <span>signing {p.signing ? "on" : "off"} · ok <b>{n(p.signed_ok)}</b> · unsigned drop <b>{n(p.dropped_unsigned)}</b> · bad sig <b>{n(p.dropped_bad_signature)}</b> · replay <b>{n(p.dropped_replay)}</b></span>
        <span>rewritten <b>{n(p.rewritten)}</b> · hook errors <b style={n(p.hook_errors) > 0 ? { color: "var(--crit)" } : undefined}>{n(p.hook_errors)}</b></span>
        <span>counter-frames <b>{n(st.analyser?.counter_frames_sent)}</b></span>
        <span>last error <b>{st.last_error ?? "none"}</b></span>
      </div>
    </div>
  );
}
