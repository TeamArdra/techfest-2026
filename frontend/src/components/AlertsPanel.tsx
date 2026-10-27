import { useState } from "react";
import type { AlertRow } from "../types";
import { sourcesOf, SOURCE_LABEL } from "../lib/evidence";
import { api } from "../services/api";

// `alerts`: the current run's alerts as persisted in the hash-chained event log (/api/events), newest first.
export function AlertsPanel({ alerts, emptyText, count, environment }: {
  alerts: AlertRow[];
  emptyText: string;
  count: number | null;
  environment: string;
}) {
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{ ok: boolean; length: number; head: string } | null>(null);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const data = await api.forensic();
      const cv = data?.chain_verification as any;
      if (cv) {
        setVerifyResult({
          ok: cv.ok,
          length: cv.length ?? 0,
          head: cv.head_hash ? cv.head_hash.slice(0, 10) : "0000000000",
        });
      }
    } catch {
      // ignore network errors
    } finally {
      setVerifying(false);
    }
  };

  const handleExport = async () => {
    try {
      const data = await api.forensic();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aegisflight_forensic_${data?.run_id ?? "audit"}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // ignore
    }
  };

  return (
    <div className="panel" data-testid="alerts-panel">
      <header>
        <span className="panel-title">Incident History & Forensics</span>
        <span className="panel-note">{count ?? alerts.length} persisted · {environment} · this run</span>
      </header>

      {/* Forensic Verification & Export Actions */}
      <div style={{ display: "flex", gap: 6, margin: "6px 0 8px 0", flexWrap: "wrap", alignItems: "center" }}>
        <button
          className="ghost"
          style={{ fontSize: 11, padding: "3px 8px" }}
          disabled={verifying}
          onClick={handleVerify}
          title="Verify SHA-256 rolling cryptographic hash chain against SQLite EventStore"
        >
          {verifying ? "Verifying..." : "🛡️ Verify SHA-256 Chain"}
        </button>
        <button
          className="ghost"
          style={{ fontSize: 11, padding: "3px 8px" }}
          onClick={handleExport}
          title="Export complete tamper-evident JSON audit trail with hashes"
        >
          📥 Export Forensic JSON
        </button>
        {verifyResult && (
          <span
            style={{
              fontSize: 10,
              fontFamily: "var(--mono)",
              color: verifyResult.ok ? "var(--ok)" : "var(--crit)",
              fontWeight: 700,
            }}
          >
            {verifyResult.ok
              ? `✓ Chain Intact · ${verifyResult.length} alerts · Head ${verifyResult.head}...`
              : "✗ Hash Chain Broken!"}
          </span>
        )}
      </div>

      {alerts.length === 0 ? (
        <div className="empty">{emptyText}</div>
      ) : (
        <ul className="incidents">
          {alerts.map((a, i) => {
            const sources = sourcesOf(a.evidence);
            return (
              <li className={`incident lvl-${a.severity}`} key={a.id ?? i}>
                <div className="i-head">
                  <span className="i-name">{a.attack_type.replace(/_/g, " ")}</span>
                  <span className={`i-sev sev-${a.severity}`}>{a.severity}</span>
                </div>
                <div className="i-meta">
                  #{a.id ?? "—"} · t={a.t.toFixed(1)}s · score {a.threat_score.toFixed(2)} · conf {a.confidence.toFixed(2)}
                </div>
                {a.evidence[0] && <div className="i-ev">{a.evidence[0]}</div>}
                {sources.length > 0 && (
                  <div className="i-src">
                    {sources.map((s) => (
                      <span className="src-tag" key={s}>{SOURCE_LABEL[s]}</span>
                    ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
