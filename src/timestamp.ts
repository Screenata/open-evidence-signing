/**
 * RFC 3161 timestamp verification (spec §6.3) — zero-dependency.
 *
 * Verifies the binding between the envelope signature and the TSA token by
 * checking `TSTInfo.messageImprint.hashedMessage == SHA-256(signature bytes)`
 * and that `genTime` is not in the future. This is the same binding the
 * reference implementation enforces.
 *
 * NOT in scope: validating the TSA's CMS signature against a trusted TSA root
 * certificate. That requires shipping a root store and is left to the caller;
 * the timestamp still proves the imprint was certified at `genTime`.
 */
import crypto from 'node:crypto';
import { parseDer, walk, decodeAsn1Time, TAG, type DerNode } from './asn1';
import type { VerificationCheck } from './types';

const CLOCK_SKEW_MS = 5 * 60 * 1000;

interface TstInfo {
  hashedMessage: Buffer;
  genTime: string | null;
  serialNumber: string | null;
}

/** Locate and decode the TSTInfo inside a DER TimeStampToken. */
export function extractTstInfo(token: Buffer): TstInfo | null {
  let root: DerNode;
  try {
    root = parseDer(token);
  } catch {
    return null;
  }

  // The eContent OCTET STRING wraps the TSTInfo SEQUENCE. Find the octet
  // string whose content parses as a SEQUENCE carrying a genTime — that
  // disambiguates it from the messageImprint hash octet string.
  for (const node of walk(root)) {
    if (node.tagNumber !== TAG.OCTET_STRING) continue;
    let inner: DerNode;
    try {
      inner = parseDer(node.content);
    } catch {
      continue;
    }
    if (inner.tagNumber !== TAG.SEQUENCE) continue;

    const timeNode = [...walk(inner)].find(
      (n) => n.tagNumber === TAG.GENERALIZED_TIME || n.tagNumber === TAG.UTC_TIME
    );
    if (!timeNode) continue;

    const messageImprint = inner.children.find(
      (c) =>
        c.tagNumber === TAG.SEQUENCE &&
        c.children.length >= 2 &&
        c.children[0].tagNumber === TAG.SEQUENCE &&
        c.children[1].tagNumber === TAG.OCTET_STRING
    );
    if (!messageImprint) continue;

    const serial = inner.children.find((c) => c.tagNumber === TAG.INTEGER);
    return {
      hashedMessage: Buffer.from(messageImprint.children[1].content),
      genTime: decodeAsn1Time(timeNode),
      serialNumber: serial ? serial.content.toString('hex') : null,
    };
  }
  return null;
}

/**
 * Verify an RFC 3161 timestamp over a base64 signature value.
 *
 * @param tokenB64        base64 DER TimeStampToken (`proof.timestamp.token`)
 * @param signatureValueB64  the base64 signature the timestamp covers
 * @param now             current time in ms (injectable for deterministic tests)
 */
export function verifyTimestamp(
  tokenB64: string,
  signatureValueB64: string,
  now: number = Date.now()
): VerificationCheck & { timestampedAt: string | null } {
  let tokenBuf: Buffer;
  try {
    tokenBuf = Buffer.from(tokenB64, 'base64');
  } catch {
    return { name: 'TSA Timestamp', passed: false, details: 'Token is not valid base64', timestampedAt: null };
  }
  if (tokenBuf.length === 0) {
    return { name: 'TSA Timestamp', passed: false, details: 'Empty timestamp token', timestampedAt: null };
  }

  const tst = extractTstInfo(tokenBuf);
  if (!tst) {
    return { name: 'TSA Timestamp', passed: false, details: 'Could not parse TimeStampToken', timestampedAt: null };
  }

  const expected = crypto
    .createHash('sha256')
    .update(Buffer.from(signatureValueB64, 'base64'))
    .digest();
  if (!tst.hashedMessage.equals(expected)) {
    return {
      name: 'TSA Timestamp',
      passed: false,
      details: 'messageImprint does not match SHA-256 of the signature',
      timestampedAt: tst.genTime,
    };
  }

  if (tst.genTime) {
    const t = new Date(tst.genTime).getTime();
    if (Number.isNaN(t)) {
      return { name: 'TSA Timestamp', passed: false, details: 'Invalid genTime', timestampedAt: tst.genTime };
    }
    if (t > now + CLOCK_SKEW_MS) {
      return { name: 'TSA Timestamp', passed: false, details: 'genTime is in the future', timestampedAt: tst.genTime };
    }
  }

  return {
    name: 'TSA Timestamp',
    passed: true,
    details: `Imprint matches; certified at ${tst.genTime ?? 'unknown'} (TSA certificate chain not validated)`,
    timestampedAt: tst.genTime,
  };
}
