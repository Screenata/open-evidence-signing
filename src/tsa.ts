/**
 * Portable RFC 3161 timestamp client (spec §6) — zero-dependency.
 *
 * Requests a TimeStampToken over the envelope/manifest signature from one or
 * more Time Stamping Authorities, with fallback. The request DER is built by
 * hand; the response is parsed with the package's own DER reader. The whole
 * `TimeStampResp` is stored as `proof.timestamp.token` (the verifier walks it
 * for the `TSTInfo`), matching the reference implementation.
 */
import crypto from 'node:crypto';
import { parseDer, walk, decodeAsn1Time, TAG } from './asn1';
import { extractTstInfo } from './timestamp';
import type { EnvelopeTimestamp } from './types';

export interface TsaOptions {
  /** TSA endpoint URLs, tried in order until one succeeds. */
  urls: string[];
  /** Per-request timeout in ms (default 10000). */
  timeoutMs?: number;
}

// ── minimal DER encoders (shippable; the test-only encoder lives in __tests__) ──
function len(n: number): Buffer {
  if (n < 128) return Buffer.from([n]);
  const b: number[] = [];
  let v = n;
  while (v > 0) {
    b.unshift(v & 0xff);
    v >>>= 8;
  }
  return Buffer.from([0x80 | b.length, ...b]);
}
const tlv = (tag: number, c: Buffer) => Buffer.concat([Buffer.from([tag]), len(c.length), c]);
const seq = (...p: Buffer[]) => tlv(0x30, Buffer.concat(p));
const octet = (b: Buffer) => tlv(0x04, b);
function intFromBytes(bytes: Buffer): Buffer {
  const b = bytes[0] & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes;
  return tlv(0x02, b);
}
function oid(s: string): Buffer {
  const parts = s.split('.').map(Number);
  const body = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const enc = [v & 0x7f];
    v >>>= 7;
    while (v > 0) {
      enc.unshift((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    body.push(...enc);
  }
  return tlv(0x06, Buffer.from(body));
}

/** Build an RFC 3161 TimeStampReq over the SHA-256 of `signatureBytes`. */
export function buildTimeStampReq(signatureBytes: Buffer): Buffer {
  const hash = crypto.createHash('sha256').update(signatureBytes).digest();
  const algId = seq(oid('2.16.840.1.101.3.4.2.1'), Buffer.from([0x05, 0x00])); // SHA-256 + NULL
  const messageImprint = seq(algId, octet(hash));
  const nonce = intFromBytes(crypto.randomBytes(8));
  const certReq = Buffer.from([0x01, 0x01, 0xff]); // BOOLEAN TRUE
  return seq(intFromBytes(Buffer.from([1])), messageImprint, nonce, certReq);
}

/** A TimeStampResp's status must be granted(0) or grantedWithMods(1). */
function isGranted(respBytes: Buffer): boolean {
  try {
    const root = parseDer(respBytes); // TimeStampResp SEQUENCE
    const statusInfo = root.children[0]; // PKIStatusInfo SEQUENCE
    const status = statusInfo?.children?.[0]; // status INTEGER
    if (!status || status.tagNumber !== TAG.INTEGER) return false;
    const v = status.content.length ? status.content[status.content.length - 1] : 0;
    return v === 0 || v === 1;
  } catch {
    return false;
  }
}

/**
 * Request a timestamp for a base64 signature value. Tries each URL in order;
 * returns the first valid `EnvelopeTimestamp`, or null if all fail.
 */
export async function requestTimestamp(
  signatureValueB64: string,
  opts: TsaOptions
): Promise<EnvelopeTimestamp | null> {
  const signatureBytes = Buffer.from(signatureValueB64, 'base64');
  const req = buildTimeStampReq(signatureBytes);
  const expected = crypto.createHash('sha256').update(signatureBytes).digest();

  for (const url of opts.urls) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/timestamp-query', Accept: 'application/timestamp-reply' },
        // Node's fetch accepts a Buffer body at runtime, but the DOM `BodyInit`
        // type used by tsc here excludes typed arrays — cast through unknown.
        body: req as unknown as BodyInit,
        signal: AbortSignal.timeout(opts.timeoutMs ?? 10000),
      });
      if (!res.ok) continue;
      const respBytes = Buffer.from(await res.arrayBuffer());
      if (!isGranted(respBytes)) continue;

      const tst = extractTstInfo(respBytes);
      if (!tst || !tst.hashedMessage.equals(expected)) continue; // self-check the imprint

      return {
        type: 'RFC3161',
        token: respBytes.toString('base64'),
        authority: url,
        timestampedAt: tst.genTime ?? new Date().toISOString(),
        serialNumber: tst.serialNumber ?? '',
      };
    } catch {
      // try the next TSA
    }
  }
  return null;
}

// Re-exported helpers used by tests / advanced callers.
export { parseDer, walk, decodeAsn1Time };
