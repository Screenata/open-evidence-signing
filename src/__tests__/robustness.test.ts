/**
 * Adversarial-input hardening: the hand-rolled ZIP and DER parsers must fail
 * cleanly (clear error / invalid result) on hostile input rather than crash,
 * hang, or exhaust memory.
 */
import { describe, it, expect } from 'vitest';
import { readZip } from '../zip';
import { parseDer } from '../asn1';
import { verifyTimestamp } from '../timestamp';

function wrapSeq(inner: Buffer): Buffer {
  const len = inner.length;
  let lenBytes: Buffer;
  if (len < 128) {
    lenBytes = Buffer.from([len]);
  } else {
    const b: number[] = [];
    let v = len;
    while (v > 0) {
      b.unshift(v & 0xff);
      v >>>= 8;
    }
    lenBytes = Buffer.from([0x80 | b.length, ...b]);
  }
  return Buffer.concat([Buffer.from([0x30]), lenBytes, inner]);
}

describe('ZIP reader robustness', () => {
  it('throws a clean error (not a RangeError) on an EOCD with an out-of-bounds central directory', () => {
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(1, 10); // totalEntries
    eocd.writeUInt32LE(10, 12); // cdSize
    eocd.writeUInt32LE(0xfffffff0, 16); // cdOffset — way past the buffer
    expect(() => readZip(eocd)).toThrow(/Corrupt|ZIP/i);
  });

  it('rejects a non-ZIP buffer without scanning forever', () => {
    expect(() => readZip(Buffer.from('definitely not a zip file'))).toThrow(/ZIP/i);
  });
});

describe('DER parser robustness', () => {
  it('rejects pathologically deep nesting instead of overflowing the stack', () => {
    let der = Buffer.from([0x05, 0x00]); // NULL leaf
    for (let i = 0; i < 200; i++) der = wrapSeq(der);
    expect(() => parseDer(der)).toThrow(/too deep/i);
  });

  it('a deeply nested timestamp token degrades to an invalid result, not a crash', () => {
    let der = Buffer.from([0x05, 0x00]);
    for (let i = 0; i < 200; i++) der = wrapSeq(der);
    const r = verifyTimestamp(der.toString('base64'), 'AAAA');
    expect(r.passed).toBe(false);
  });
});
