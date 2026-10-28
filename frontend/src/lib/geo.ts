// Pure geometry for the flight-track graphic: fix validation, local-frame projection and fitting.
// No React, no DOM — unit tested in frontend/tests/geo.test.ts.
export type LatLon = [number, number];
export type XY = [number, number];

export const M_PER_DEG_LAT = 111_320;

/** A fix is usable only if finite, in range and not the (0,0) "no GPS" placeholder. */
export function isValidFix(lat: unknown, lon: unknown): boolean {
  if (typeof lat !== "number" || typeof lon !== "number") return false;
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return false;
  if (Math.abs(lat) > 90 || Math.abs(lon) > 180) return false;
  if (lat === 0 && lon === 0) return false;
  return true;
}

/** isValidFix plus the link's own GPS report (`false` = the receiver says there is no valid fix). */
export function acceptFix(lat: unknown, lon: unknown, gpsValidFix?: boolean | null): boolean {
  if (gpsValidFix === false) return false;
  return isValidFix(lat, lon);
}

/** Longitude difference lon - lon0 in degrees, normalised to (-180, 180] (antimeridian safe). */
export function lonDelta(lon: number, lon0: number): number {
  let d = (lon - lon0) % 360;
  if (d > 180) d -= 360;
  else if (d <= -180) d += 360;
  return d;
}

export function metresPerDegLon(latDeg: number): number {
  return M_PER_DEG_LAT * Math.cos((latDeg * Math.PI) / 180);
}

/** Local east/north metres of (lat, lon) relative to origin; north up, cos(origin latitude). */
export function toLocal(origin: LatLon, lat: number, lon: number): XY {
  return [lonDelta(lon, origin[1]) * metresPerDegLon(origin[0]), (lat - origin[0]) * M_PER_DEG_LAT];
}

export function projectTrack(track: LatLon[], origin: LatLon): XY[] {
  return track.map((p) => toLocal(origin, p[0], p[1]));
}

/** Origin bookkeeping: first VALID fix of a run; a new run id re-origins. */
export interface OriginState { origin: LatLon | null; runId: string | null }
export function nextOrigin(prev: OriginState, runId: string | null, lat: unknown, lon: unknown, gpsValid?: boolean | null): OriginState {
  const base: OriginState = runId && runId !== prev.runId ? { origin: null, runId } : { origin: prev.origin, runId: runId ?? prev.runId };
  if (!base.origin && acceptFix(lat, lon, gpsValid)) base.origin = [lat as number, lon as number];
  return base;
}

export interface Extent { minX: number; maxX: number; minY: number; maxY: number; span: number }
export function extentOf(points: XY[], minSpan = 20): Extent {
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const [x, y] of points) {
    if (x < minX) minX = x; if (x > maxX) maxX = x;
    if (y < minY) minY = y; if (y > maxY) maxY = y;
  }
  if (!Number.isFinite(minX)) { minX = maxX = minY = maxY = 0; }
  return { minX, maxX, minY, maxY, span: Math.max(maxX - minX, maxY - minY, minSpan) };
}

export interface Fit { pxPerM: number; sx: (x: number) => number; sy: (y: number) => number }
/** Equal-aspect fit (same px/m on both axes), extent centred in the plot box, north up. */
export function fitExtent(e: Extent, W: number, H: number, pad: number): Fit {
  const pw = W - 2 * pad, ph = H - 2 * pad;
  const pxPerM = Math.min(pw, ph) / e.span;
  const cx = (e.minX + e.maxX) / 2, cy = (e.minY + e.maxY) / 2;
  return {
    pxPerM,
    sx: (x) => pad + pw / 2 + (x - cx) * pxPerM,
    sy: (y) => H - pad - ph / 2 - (y - cy) * pxPerM,
  };
}

/** Round to a clean 1/2/5 x 10^n value (scale bar). */
export function niceScale(x: number): number {
  if (!(x > 0)) return 0;
  const pow = Math.pow(10, Math.floor(Math.log10(x)));
  const f = x / pow;
  return (f >= 5 ? 5 : f >= 2 ? 2 : 1) * pow;
}
