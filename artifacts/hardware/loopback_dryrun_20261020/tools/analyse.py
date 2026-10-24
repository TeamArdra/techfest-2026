"""SCRATCH ONLY: summarise one dry-run out-dir (read-only)."""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

d = Path(sys.argv[1])
srvlog = Path(sys.argv[2]) if len(sys.argv) > 2 and Path(sys.argv[2]).exists() else None
s = json.loads((d / "summary.json").read_text(encoding="utf-8"))
print("exit_code", s["exit_code"], "| decisions", s["decisions"], "| threat", s["threat_decisions"],
      "| alert_decisions", s["alert_decisions"], "| alert_types", s["alert_types"])
print("telemetry_coverage", s.get("telemetry_coverage"))
print("passive_check", s["passive_check"], "| hash_chain", s["hash_chain"],
      "| link_ever_delivered_frames", s["link_ever_delivered_frames"])
t = s["transport"]
print("transport frames", t["frames_received"], "garbage", t["garbage_bytes"], "crc", t["crc_rejects"],
      "disconnects", t["disconnects"], "last_error", t["last_error"], "| source late_ticks",
      s["source"]["late_ticks"], "late_frames", s["source"]["late_frames"], "ticks", s["source"]["ticks_emitted"])
al = [json.loads(x) for x in (d / "alerts.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
print("alerts", len(al), "| earliest t", al[0]["t"] if al else None)
for a in al[:3]:
    print("  t=%s %s score=%s | %s" % (a["t"], a["type"], a["score"], a["evidence"][0] if a["evidence"] else ""))
nr = [a for a in al if any("never received" in e for e in a["evidence"])]
print("'never received' alerts:", [(a["t"], a["type"]) for a in nr][:5],
      "| any at t<=3.0:", any(a["t"] <= 3.0 for a in nr))
fam = {}
for a in al:
    k = a["evidence"][0].split(":")[0] if a["evidence"] else ""
    fam[k] = fam.get(k, 0) + 1
print("alert first-evidence families", fam)
print("alert t list", [a["t"] for a in al])
cov_in_alert = sum(any(e.startswith("coverage:") for e in a["evidence"]) for a in al)
print("alerts carrying a coverage line:", cov_in_alert)
h = [json.loads(x) for x in (d / "health.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
print("health lines", len(h), "| first coverage", h[0].get("telemetry_coverage") if h else None)
if srvlog:
    lg = json.loads(srvlog.read_text(encoding="utf-8"))
    st = datetime.fromisoformat(s["started_utc"]).timestamp()
    print("server: accept - runner_started = %.3f s" % (lg["accept_unix"] - st),
          "| first_send - runner_started = %s" % (round(lg["first_send_unix"] - st, 3) if "first_send_unix" in lg else None),
          "| last_send - runner_started = %s" % (round(lg["last_send_unix"] - st, 3) if "last_send_unix" in lg else None),
          "| sent", lg.get("sent"), "/", lg.get("frames_total"))
