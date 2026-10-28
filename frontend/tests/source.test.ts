// Display-logic tests for src/lib/source.ts with Node's built-in runner (no extra dependency; Node >= 23.6
// strips the TypeScript types):  npm --prefix frontend test
import assert from "node:assert/strict";
import { test } from "node:test";

import { envView, gpsNote, linkView } from "../src/lib/source.ts";

const ENVS = ["SIM", "REPLAY", "SITL", "BENCH"];
const NON_SIM = ["REPLAY", "SITL", "BENCH"];

function link(state, extra = {}) {
  return {
    state, frames: 120, last_frame_age_s: 0.1, stale_after_s: 3, messages: {}, transport: null,
    gps: { fix_type: null, fix_name: null, satellites: null, valid_fix: null, gps_raw_age_s: null,
      position_age_s: null, position_zero: null },
    error: null, ...extra,
  };
}

test("the badge is the backend-reported environment; unknown until reported", () => {
  for (const env of ENVS) assert.equal(envView(env).badge, env);
  assert.equal(envView(null).badge, "—");
  assert.equal(envView(undefined).label, "Connecting…");
});

test("only SIM enables the control / attack panel", () => {
  assert.equal(envView("SIM").controls, true);
  for (const env of NON_SIM) assert.equal(envView(env).controls, false, env);
  assert.equal(envView(null).controls, false);
});

test("non-SIM sources are never worded as a simulation; BENCH is never flight data", () => {
  for (const env of NON_SIM) {
    const v = envView(env);
    for (const text of [v.label, v.footer, v.telemetryNote, v.trackNote, v.distanceNote, v.emptyAlerts]) {
      assert.doesNotMatch(text, /simulat/i, `${env}: ${text}`);
    }
  }
  const bench = envView("BENCH");
  for (const text of [bench.footer, bench.telemetryNote, bench.trackNote, bench.distanceNote]) {
    assert.match(text, /not flight/i, text);
  }
  assert.match(envView("SIM").footer, /simulation/i);
});

test("every backend link state maps to its own label and tone", () => {
  const want = {
    simulated: ["Simulated", "sim"], live: ["Live", "on"], waiting: ["Waiting for data", "warn"],
    stale: ["Stale", "warn"], disconnected: ["Disconnected", "off"], ended: ["Ended", "idle"],
    error: ["Source error", "off"],
  };
  for (const [state, [label, tone]] of Object.entries(want)) {
    const v = linkView(link(state), true, 0.1);
    assert.deepEqual([v.label, v.tone], [label, tone], state);
  }
});

test("stale shows the frame age against the threshold", () => {
  const v = linkView(link("stale", { last_frame_age_s: 7.4 }), true, 0.1);
  assert.match(v.detail, /7\.4 s/);
  assert.match(v.detail, /3\.0 s/);
});

test("error and disconnected carry the backend's cause", () => {
  const msg = "RuntimeError: cannot open serial port 'COM7'";
  assert.equal(linkView(link("error", { error: msg }), true, 0.1).detail, msg);
  const d = linkView(link("disconnected", { transport: { connected: false, open_failures: 4 } }), true, 0.1);
  assert.match(d.detail, /4 open failures/);
});

test("backend silence overrides a live-looking state, never a final one", () => {
  for (const state of ["live", "stale", "waiting", "simulated"]) {
    assert.equal(linkView(link(state), true, 10).label, "No updates", state);
  }
  assert.equal(linkView(link("live"), true, 2).label, "Live"); // within the 3 s window
  assert.equal(linkView(link("ended"), true, 100).label, "Ended");
  assert.equal(linkView(link("error", { error: "x" }), true, 100).label, "Source error");
});

test("no link reported yet", () => {
  assert.equal(linkView(null, true, null).label, "No data");
  assert.equal(linkView(null, false, null).label, "Backend offline");
});

test("a 3D fix is never the only thing shown when the vehicle says its position is unconfirmed", () => {
  const gps = (extra) => ({ fix_type: 3, fix_name: "3D_FIX", satellites: 7, valid_fix: true, gps_raw_age_s: 0.1,
    position_age_s: 0.1, position_zero: false, ...extra });
  assert.equal(gpsNote(gps({ horizontal_solution: false, gps_healthy: false })),
    "autopilot reports no horizontal position solution · autopilot marks the GPS sensor unhealthy — treat this position as unconfirmed");
  assert.match(gpsNote(gps({ horizontal_solution: false })), /no horizontal position solution/);
  assert.match(gpsNote(gps({ gps_healthy: false })), /GPS sensor unhealthy/);
});

test("no note when the vehicle reports a solution, or when it is unknown (unknown is not a warning)", () => {
  assert.equal(gpsNote({ fix_type: 3, horizontal_solution: true, gps_healthy: true }), null);
  assert.equal(gpsNote({ fix_type: 3, horizontal_solution: null, gps_healthy: null }), null);
  assert.equal(gpsNote({ fix_type: 3 }), null); // older backend: keys absent
  assert.equal(gpsNote(null), null);
  assert.equal(gpsNote(undefined), null);
});
