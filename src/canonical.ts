/**
 * Canonicalization for OES v1.0 — the `sorted-keys-2space` algorithm (spec §4.2).
 *
 * The algorithm is exactly: recursively sort object keys at every depth,
 * serialize as JSON with 2-space
 * indentation, encode UTF-8. A single divergent byte fails every signature
 * check, so this file is intentionally minimal and dependency-free.
 */

/** Recursively sort object keys at all nesting levels. Arrays keep order. */
export function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    out[key] = sortKeys(obj[key]);
  }
  return out;
}

/**
 * Canonical UTF-8 bytes of `value` per spec §4.2 (`sorted-keys-2space`).
 * This is the exact byte sequence a signature is computed over.
 */
export function canonicalize(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(sortKeys(value), null, 2), 'utf-8');
}
