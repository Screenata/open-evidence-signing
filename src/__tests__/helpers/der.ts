/**
 * Tiny DER encoder + a synthetic RFC 3161 TimeStampToken builder.
 * TEST-ONLY — used to fabricate timestamp fixtures whose messageImprint binds
 * to a known signature. The token carries no real TSA certificate (the
 * verifier deliberately does not validate the TSA cert chain), so this is a
 * legitimate fixture for the imprint + genTime checks.
 */
import crypto from 'node:crypto';

function len(n: number): Buffer {
  if (n < 128) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), len(content.length), content]);
}
const seq = (...p: Buffer[]) => tlv(0x30, Buffer.concat(p));
const set = (...p: Buffer[]) => tlv(0x31, Buffer.concat(p));
const octet = (b: Buffer) => tlv(0x04, b);
const nullVal = () => Buffer.from([0x05, 0x00]);
const explicit = (n: number, content: Buffer) => tlv(0xa0 | n, content);
function int(n: number): Buffer {
  const bytes: number[] = [];
  let v = n;
  if (v === 0) bytes.push(0);
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
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
function generalizedTime(d: Date): Buffer {
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  const s = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x18, Buffer.from(s, 'ascii'));
}

function tokenBytes(signatureValueB64: string, genTime: Date, serial: number): Buffer {
  const imprint = crypto.createHash('sha256').update(Buffer.from(signatureValueB64, 'base64')).digest();
  const messageImprint = seq(seq(oid('2.16.840.1.101.3.4.2.1'), nullVal()), octet(imprint));
  const tstInfo = seq(int(1), oid('1.2.3.4.1'), messageImprint, int(serial), generalizedTime(genTime));
  const encapContentInfo = seq(oid('1.2.840.113549.1.9.16.1.4'), explicit(0, octet(tstInfo)));
  const signedData = seq(int(3), set(), encapContentInfo);
  return seq(oid('1.2.840.113549.1.7.2'), explicit(0, signedData));
}

/** Build a synthetic DER TimeStampToken binding `signatureValueB64` at `genTime`. */
export function buildTimeStampToken(signatureValueB64: string, genTime: Date, serial = 4242): string {
  return tokenBytes(signatureValueB64, genTime, serial).toString('base64');
}

/** Build a synthetic RFC 3161 TimeStampResp (status granted + token) bytes. */
export function buildTimeStampResp(signatureValueB64: string, genTime: Date, serial = 4242): Buffer {
  const pkiStatusInfo = seq(int(0)); // status: granted(0)
  return seq(pkiStatusInfo, tokenBytes(signatureValueB64, genTime, serial));
}
