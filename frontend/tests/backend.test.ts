import assert from "node:assert/strict";
import { test } from "node:test";
import { isHttpUrl, resolveBackend, resolveWsUrl } from "../src/services/backend.ts";

test("precedence: window > stored > vite > tauri > same-origin", () => {
  const all = { win: "http://a:1/", stored: "http://b:2", vite: "http://c:3", protocol: "tauri:" };
  assert.equal(resolveBackend(all), "http://a:1");
  assert.equal(resolveBackend({ ...all, win: null }), "http://b:2");
  assert.equal(resolveBackend({ ...all, win: null, stored: "" }), "http://c:3");
  assert.equal(resolveBackend({ protocol: "tauri:" }), "http://127.0.0.1:8000");
  assert.equal(resolveBackend({ protocol: "http:", hostname: "tauri.localhost" }), "http://127.0.0.1:8000");
  assert.equal(resolveBackend({ protocol: "http:", hostname: "localhost" }), "");
});

test("invalid overrides are ignored", () => {
  assert.equal(isHttpUrl("ftp://x"), false);
  assert.equal(isHttpUrl("nonsense"), false);
  assert.equal(resolveBackend({ stored: "javascript:1", protocol: "https:" }), "");
});

test("ws scheme follows base", () => {
  assert.equal(resolveWsUrl("http://127.0.0.1:8000", "tauri:", "x"), "ws://127.0.0.1:8000/ws/telemetry");
  assert.equal(resolveWsUrl("https://h.example", "http:", "x"), "wss://h.example/ws/telemetry");
  assert.equal(resolveWsUrl("", "https:", "dash:443"), "wss://dash:443/ws/telemetry");
  assert.equal(resolveWsUrl("", "http:", "localhost:5173"), "ws://localhost:5173/ws/telemetry");
});
