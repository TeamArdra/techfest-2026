import assert from "node:assert/strict";
import { test } from "node:test";
import { bridgeAuthHeaders, bridgePostureUrl, controlHint, needsActiveIpsDialog, parsePostureResponse, postureBody, signingText } from "../src/lib/posture.ts";

test("dialog needed only for non-SIM switch to active-ips", () => {
  assert.equal(needsActiveIpsDialog("BENCH", "passive", "active-ips"), true);
  assert.equal(needsActiveIpsDialog("REPLAY", "advisory", "active-ips"), true);
  assert.equal(needsActiveIpsDialog("SIM", "passive", "active-ips"), false);
  assert.equal(needsActiveIpsDialog("BENCH", "active-ips", "active-ips"), false);
  assert.equal(needsActiveIpsDialog("BENCH", "active-ips", "passive"), false);
  assert.equal(needsActiveIpsDialog("BENCH", "passive", "advisory"), false);
  assert.equal(needsActiveIpsDialog(null, "passive", "active-ips"), false);
});

test("signing text", () => {
  assert.equal(signingText({ configured: true }), "Signing: configured");
  assert.equal(signingText({ configured: false }), "Signing: NOT configured");
  assert.equal(signingText(null), "Signing: unknown");
});

test("parse 409/401/403/400/200", () => {
  assert.deepEqual(parsePostureResponse(409, { ok: false, error: "signing_required", message: "m" }), { kind: "signing_required", message: "m" });
  assert.equal(parsePostureResponse(401, {}).kind, "unauthorized");
  assert.equal(parsePostureResponse(403, { error: "control_disabled" }).kind, "disabled");
  assert.equal(parsePostureResponse(400, null).kind, "bad_request");
  assert.deepEqual(parsePostureResponse(200, { ok: true, status: { mode: "passive" } }), { kind: "ok", status: { mode: "passive" } });
  assert.equal(parsePostureResponse(500, null).kind, "error");
});

test("token only in header, never in URL", () => {
  const url = bridgePostureUrl("http://h:1/");
  assert.equal(url, "http://h:1/posture");
  assert.ok(!url.includes("secret"));
  assert.equal(bridgeAuthHeaders("secret").Authorization, "Bearer secret");
  assert.ok(!postureBody("active-ips", true).includes("secret"));
  assert.equal(postureBody("passive"), '{"mode":"passive"}');
  assert.equal(postureBody("active-ips", true), '{"mode":"active-ips","allow_unsigned":true}');
});

test("control hint", () => {
  assert.equal(controlHint(true, true), null);
  assert.match(controlHint(false, true)!, /--control-token-file/);
  assert.match(controlHint(true, false)!, /Settings/);
});
