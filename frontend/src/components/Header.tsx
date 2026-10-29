import { gpsNote } from "../lib/source";
import type { EnvView, LinkView } from "../lib/source";
import type { DefenseMode, LinkStatus, SourceInfo } from "../types";

interface Props {
  connected: boolean;
  clock: number;
  mlAvailable: boolean;
  env: EnvView;
  link: LinkView;
  defenseMode?: DefenseMode;
  onSettings?: () => void;
}

export function Header({ connected, clock, mlAvailable, env, link, defenseMode, onSettings }: Props) {
  const mm = Math.floor(clock / 60);
  const ss = Math.floor(clock % 60);
  const def = defenseMode || "passive";
  return (
    <header className="header">
      <div className="brand">
        <h1>
          <span className="mark">Aegis</span>Flight
        </h1>
        <div className="tagline">UAV Cyber-Physical Intrusion Detection System</div>
      </div>

      <div className="status-rail">
        <div className="stat" data-testid="defense-mode-stat">
          <span className={`env-badge def-badge-${def}`}>{def.toUpperCase()}</span>
          <span className="val">Defense</span>
        </div>
        <div className="stat" data-testid="source-env">
          <span className={`env-badge env-${env.badge}`}>{env.badge}</span>
          <span className="val">{env.label}</span>
        </div>
        <div className="stat" data-testid="link-state" title={link.detail}>
          <span className={`dot ${link.tone}`} />
          <span>Link</span>
          <span className="val">{link.label}</span>
        </div>
        <div className="stat">
          <span>{env.clockLabel}</span>
          <span className="val mono">
            {mm}:{ss.toString().padStart(2, "0")}
          </span>
        </div>
        <div className="stat">
          <span className={`dot ${mlAvailable ? "on" : "idle"}`} />
          <span>ML engine</span>
          <span className="val">{mlAvailable ? "Online" : "Offline"}</span>
        </div>
        <div className="stat">
          <span className={`dot ${connected ? "on" : "off"}`} />
          <span>Backend</span>
          <span className="val">{connected ? "Connected" : "Disconnected"}</span>
        </div>
        {onSettings && (
          <div className="stat">
            <button type="button" data-testid="open-settings" onClick={onSettings} title="Backend / bridge URL settings">Settings</button>
          </div>
        )}
      </div>
    </header>
  );
}

function fmt(v: unknown): string {
  return v == null ? "—" : String(v);
}

// One line naming exactly what is being displayed: the source, the run, the link and the GPS report.
export function SourceBar({ source, link, linkView, runId, eventsCount }: {
  source: SourceInfo | null;
  link: LinkStatus | null;
  linkView: LinkView;
  runId: string | null;
  eventsCount: number | null;
}) {
  const d = source?.detail ?? {};
  const where =
    source?.kind === "serial" ? `${fmt(d.port)} @ ${fmt(d.baud)} baud${d.virtual ? " · virtual port" : ""}`
    : source?.kind === "replay" ? `${fmt(d.tlog)} · speed ${fmt(d.speed)}`
    : source?.kind === "udp" ? `${fmt(d.bind)} · passive`
    : source?.kind === "sim" ? "in-process simulator"
    : "—";
  const gps = link?.gps;
  const note = gpsNote(gps);
  return (
    <div className="source-bar" data-testid="source-bar">
      <span><b>{source?.label ?? "Source not reported"}</b> · {where}</span>
      <span>run <b className="mono">{runId ?? "—"}</b> · {eventsCount ?? 0} persisted alerts</span>
      <span>link <b>{linkView.label}</b>{linkView.detail ? ` — ${linkView.detail}` : ""}</span>
      {gps && gps.fix_type != null && (
        <span>
          GPS as reported (unauthenticated) <b>{fmt(gps.fix_name)}</b> · {fmt(gps.satellites)} sats · usable fix{" "}
          <b>{gps.valid_fix ? "yes" : "no"}</b>
        </span>
      )}
      {note && <span data-testid="gps-note" style={{ color: "var(--warn)" }}>{note}</span>}
      {source && !source.ml && source.kind !== "sim" && <span>ML off · integrity UNKNOWN (no verifier)</span>}
    </div>
  );
}
