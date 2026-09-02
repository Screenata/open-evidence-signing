import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { verifyTimestamp, extractTstInfo } from '../timestamp';
import { buildTimeStampToken } from './helpers/der';

const sig = crypto.randomBytes(256).toString('base64');

describe('verifyTimestamp (RFC 3161, spec §6.3)', () => {
  it('accepts a token whose imprint matches the signature', () => {
    const genTime = new Date('2026-04-20T10:30:06Z');
    const token = buildTimeStampToken(sig, genTime);
    const r = verifyTimestamp(token, sig);
    expect(r.passed).toBe(true);
    expect(r.timestampedAt).toBe('2026-04-20T10:30:06Z');
  });

  it('rejects a token bound to a different signature', () => {
    const token = buildTimeStampToken('AAAA', new Date('2026-04-20T10:30:06Z'));
    const r = verifyTimestamp(token, sig);
    expect(r.passed).toBe(false);
    expect(r.details).toMatch(/messageImprint/i);
  });

  it('rejects a token dated in the future', () => {
    const future = new Date(Date.now() + 3600_000);
    const token = buildTimeStampToken(sig, future);
    const r = verifyTimestamp(token, sig);
    expect(r.passed).toBe(false);
    expect(r.details).toMatch(/future/i);
  });

  it('rejects an unparseable token', () => {
    const r = verifyTimestamp('bm90IGEgdG9rZW4=', sig);
    expect(r.passed).toBe(false);
  });

  it('extracts the messageImprint hash from a token', () => {
    const token = buildTimeStampToken(sig, new Date('2026-04-20T10:30:06Z'));
    const tst = extractTstInfo(Buffer.from(token, 'base64'));
    const expected = crypto.createHash('sha256').update(Buffer.from(sig, 'base64')).digest();
    expect(tst?.hashedMessage.equals(expected)).toBe(true);
  });
});
