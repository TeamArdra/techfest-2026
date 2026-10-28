import { useState } from "react";
import { BACKEND_KEY, BRIDGE_KEY, backendBase, getUrlSetting, saveUrlSetting } from "../services/api";

// Backend URL (REST + WebSocket) and optional inline-IPS bridge status URL; stored in localStorage.
export function SettingsModal({ onClose }: { onClose: () => void }) {
  const [backend, setBackend] = useState(getUrlSetting(BACKEND_KEY));
  const [bridge, setBridge] = useState(getUrlSetting(BRIDGE_KEY));
  const [err, setErr] = useState<string | null>(null);
  const save = () => {
    const e1 = saveUrlSetting(BACKEND_KEY, backend);
    const e2 = saveUrlSetting(BRIDGE_KEY, bridge);
    if (e1 || e2) { setErr(`${e1 ? "Backend: " + e1 : ""} ${e2 ? "Bridge: " + e2 : ""}`.trim()); return; }
    window.location.reload(); // reconnect the WebSocket + pollers against the new URLs
  };
  const clear = () => { setBackend(""); setBridge(""); saveUrlSetting(BACKEND_KEY, ""); saveUrlSetting(BRIDGE_KEY, ""); window.location.reload(); };
  const field = { width: "100%", boxSizing: "border-box", padding: 6, marginTop: 4 } as const;
  return (
    <div role="dialog" aria-modal="true" data-testid="settings-modal"
      style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.6)", display: "grid", placeItems: "center", zIndex: 50 }}
      onClick={onClose}>
      <div className="panel" style={{ width: 460, maxWidth: "92vw", padding: 16 }} onClick={(e) => e.stopPropagation()}>
        <div className="panel-title" style={{ marginBottom: 10 }}>Connection settings</div>
        <label>Backend URL <span className="panel-note">(active: {backendBase() || "same-origin"})</span>
          <input style={field} value={backend} placeholder="http://127.0.0.1:8000" onChange={(e) => setBackend(e.target.value)} />
        </label>
        <label style={{ display: "block", marginTop: 10 }}>Inline IPS bridge status URL <span className="panel-note">(optional)</span>
          <input style={field} value={bridge} placeholder="http://127.0.0.1:8765" onChange={(e) => setBridge(e.target.value)} />
        </label>
        {err && <div style={{ color: "var(--crit)", marginTop: 8 }}>{err}</div>}
        <div style={{ display: "flex", gap: 8, marginTop: 14, justifyContent: "flex-end" }}>
          <button type="button" onClick={clear}>Clear</button>
          <button type="button" onClick={onClose}>Cancel</button>
          <button type="button" onClick={save}>Save &amp; reload</button>
        </div>
      </div>
    </div>
  );
}
