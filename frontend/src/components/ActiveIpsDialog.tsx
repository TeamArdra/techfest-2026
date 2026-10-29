import { useEffect, useRef } from "react";
import { UNSIGNED_RISK, signingText, type SigningInfo } from "../lib/posture";

interface Props {
  signing: SigningInfo | null;
  busy: boolean;
  error: string | null; // e.g. the backend's 409 signing_required message
  onCancel: () => void;
  onConfirm: (allowUnsigned: boolean) => void;
}

// Informed-consent step before switching a real (non-SIM) link to ACTIVE IPS.
export function ActiveIpsDialog({ signing, busy, error, onCancel, onConfirm }: Props) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => { cancelRef.current?.focus(); }, []);
  const signed = signing?.configured === true;
  return (
    <div role="dialog" aria-modal="true" aria-labelledby="aips-title" data-testid="active-ips-dialog"
      style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.6)", display: "grid", placeItems: "center", zIndex: 60 }}
      onKeyDown={(e) => { if (e.key === "Escape") onCancel(); }}>
      <div className="panel" style={{ width: 480, maxWidth: "92vw", padding: 16 }}>
        <div id="aips-title" className="panel-title" style={{ marginBottom: 10 }}>Switch to ACTIVE IPS?</div>
        <p>ACTIVE IPS makes the monitor send counter-commands to the flight controller. On the inline bridge it also drops hostile frames.</p>
        <p data-testid="aips-signing" style={{ fontWeight: 700, color: signed ? "var(--ok)" : "var(--crit)" }}>{signingText(signing)}</p>
        {!signed && <p data-testid="aips-risk" style={{ color: "var(--crit)" }}>{UNSIGNED_RISK}</p>}
        {error && <p role="alert" data-testid="aips-error" style={{ color: "var(--crit)" }}>{error}</p>}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 14 }}>
          <button type="button" ref={cancelRef} onClick={onCancel} disabled={busy}>Cancel</button>
          {signed
            ? <button type="button" onClick={() => onConfirm(false)} disabled={busy}>Switch to ACTIVE IPS</button>
            : <button type="button" onClick={() => onConfirm(true)} disabled={busy}>I understand — proceed unsigned</button>}
        </div>
      </div>
    </div>
  );
}
