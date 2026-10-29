import assert from "node:assert/strict";
import { test } from "node:test";
import { acceptFix, extentOf, fitExtent, isValidFix, lonDelta, nextOrigin, niceScale, projectTrack, toLocal } from "../src/lib/geo.ts";

const near = (a, b, tol) => assert.ok(Math.abs(a - b) <= tol, `${a} !~ ${b}`);

test("projection scales east by cos(latitude) at 0/19/60/-45", () => {
  for (const lat of [0, 19, 60, -45]) {
    const [x, y] = toLocal([lat, 10], lat, 10.001);
    near(x, 111.32 * Math.cos((lat * Math.PI) / 180), 0.01);
    near(y, 0, 1e-9);
    const [, y2] = toLocal([lat, 10], lat + 0.001, 10);
    near(y2, 111.32, 0.01);
  }
});

test("longitude is normalised across the antimeridian", () => {
  near(lonDelta(-179.999, 179.999), 0.002, 1e-9);
  near(lonDelta(179.999, -179.999), -0.002, 1e-9);
  const [x] = toLocal([0.5, 179.999], 0.5, -179.999);
  assert.ok(x > 0 && x < 300);
});

test("invalid fixes are rejected", () => {
  for (const [a, b] of [[0, 0], [NaN, 1], [1, Infinity], [91, 0], [0, 181], [null, 5], [undefined, undefined]]) {
    assert.equal(isValidFix(a, b), false, `${a},${b}`);
  }
  assert.equal(isValidFix(0, 5), true);
  assert.equal(isValidFix(19.4, -99.1), true);
  assert.equal(acceptFix(19.4, -99.1, false), false);
  assert.equal(acceptFix(19.4, -99.1, null), true);
});

test("origin is the first valid fix and resets on a new run", () => {
  let s = { origin: null, runId: null };
  s = nextOrigin(s, "a", 0, 0);
  assert.equal(s.origin, null);
  s = nextOrigin(s, "a", NaN, 1);
  assert.equal(s.origin, null);
  s = nextOrigin(s, "a", 10, 20);
  assert.deepEqual(s.origin, [10, 20]);
  s = nextOrigin(s, "a", 11, 21);
  assert.deepEqual(s.origin, [10, 20]);
  s = nextOrigin(s, "b", 30, 40);
  assert.deepEqual(s.origin, [30, 40]);
  s = nextOrigin(s, "c", 0, 0);
  assert.equal(s.origin, null);
});

test("fit is equal-aspect, north-up and auto-scaled", () => {
  const pts = projectTrack([[19, -99], [19.001, -99], [19.001, -98.998]], [19, -99]);
  const e = extentOf(pts);
  const fit = fitExtent(e, 680, 410, 34);
  assert.ok(fit.pxPerM > 0);
  assert.ok(fit.sy(pts[1][1]) < fit.sy(pts[0][1])); // north is up
  const dx = fit.sx(pts[2][0]) - fit.sx(pts[1][0]);
  near(dx / fit.pxPerM, pts[2][0] - pts[1][0], 1e-6);
  for (const p of pts) {
    assert.ok(fit.sx(p[0]) >= 34 && fit.sx(p[0]) <= 646 && fit.sy(p[1]) >= 34 && fit.sy(p[1]) <= 376);
  }
  assert.equal(extentOf([[0, 0]]).span, 20);
  assert.equal(niceScale(130), 100);
  assert.equal(niceScale(0), 0);
});
