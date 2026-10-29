import assert from "node:assert/strict";
import { test } from "node:test";
import { describe, selectTopology } from "../src/lib/topology.ts";
import * as topo from "../src/lib/topology.ts";
import { readFileSync } from "node:fs";

const mk = (kind: string, over: Record<string, unknown> = {}): any => ({
  kind, label: kind, source: "detected", posture: "passive",
  links: {}, uplink_visible: true, can_block_frames: false, can_send_counter_commands: false, reasons: [], ...over,
});

test("bridge preferred over backend", () => {
  const s = selectTopology(mk("A"), mk("A+B"))!;
  assert.equal(s.origin, "bridge");
  assert.equal(s.info.kind, "A+B");
  assert.equal(describe(s).originText, "from the inline bridge");
});

test("fallback to backend, and none", () => {
  assert.equal(selectTopology(mk("A"), null)!.origin, "backend");
  assert.equal(selectTopology(mk("A"), undefined)!.info.kind, "A");
  assert.equal(selectTopology(null, null), null);
  assert.equal(selectTopology(undefined, {} as any), null);
});

test("modelled is never shown as detected", () => {
  const v = describe(selectTopology(mk("SIM", { source: "modelled" }), null)!);
  assert.equal(v.sourceText, "modelled");
  assert.equal(describe(selectTopology(mk("UNKNOWN", { source: "bogus" }), null)!).sourceText, "none");
});

test("badge per kind", () => {
  const b = (k: string) => describe(selectTopology(mk(k), null)!).badge;
  assert.equal(b("A"), "A — sidecar monitor");
  assert.equal(b("A+B"), "A+B — inline bridge");
  assert.equal(b("SIM"), "SIM — modelled");
  assert.equal(b("REPLAY"), "REPLAY — no wiring");
  assert.equal(b("UNKNOWN"), "UNKNOWN");
  assert.equal(b("weird"), "UNKNOWN");
});

test("capability rows follow flags", () => {
  const v = describe(selectTopology(mk("A+B", { uplink_visible: true, can_block_frames: true, can_send_counter_commands: false }), null)!);
  assert.deepEqual(v.caps.map((c) => c.text), ["yes", "yes", "no"]);
  const u = describe(selectTopology(mk("UNKNOWN", { uplink_visible: null }), null)!);
  assert.equal(u.caps[0].text, "unknown");
});

test("link rows and reasons", () => {
  const v = describe(selectTopology(mk("A", {
    links: { fc: { connected: true, name: "/dev/ttyS1" }, gcs: { connected: false, name: null } },
    reasons: ["x"],
  }), null)!);
  assert.deepEqual(v.links.map((l) => [l.id, l.state, l.name]), [["fc", "connected", "/dev/ttyS1"], ["gcs", "disconnected", null]]);
  assert.deepEqual(v.reasons, ["x"]);
  assert.equal(describe(selectTopology(mk("A"), null)!).links.length, 0);
});

test("no selector exports remain", () => {
  const src = readFileSync(new URL("../src/services/api.ts", import.meta.url), "utf8");
  assert.ok(!/setTopology|\/api\/topology/.test(src));
  for (const k of Object.keys(topo)) assert.ok(!/^set/i.test(k), k);
});
