import { describe, it, expect, vi, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { buildTimeStampReq, requestTimestamp } from '../tsa';
import { parseDer, TAG } from '../asn1';
import { buildTimeStampResp } from './helpers/der';

describe('buildTimeStampReq', () => {
  it('produces a well-formed RFC 3161 TimeStampReq SEQUENCE', () => {
    const sig = crypto.randomBytes(256);
    const req = parseDer(buildTimeStampReq(sig));
    expect(req.tagNumber).toBe(TAG.SEQUENCE);
    // version INTEGER, messageImprint SEQUENCE, nonce INTEGER, certReq BOOLEAN
    expect(req.children[0].tagNumber).toBe(TAG.INTEGER);
    expect(req.children[1].tagNumber).toBe(TAG.SEQUENCE);
  });
});

describe('requestTimestamp', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('parses a granted response and binds the signature imprint', async () => {
    const sig = crypto.randomBytes(256).toString('base64');
    const genTime = new Date('2026-04-20T10:30:06Z');
    const resp = buildTimeStampResp(sig, genTime);
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, async arrayBuffer() { return resp.buffer.slice(resp.byteOffset, resp.byteOffset + resp.byteLength); } })));
    const ts = await requestTimestamp(sig, { urls: ['http://tsa.test'] });
    expect(ts).not.toBeNull();
    expect(ts!.timestampedAt).toBe('2026-04-20T10:30:06Z');
    expect(ts!.authority).toBe('http://tsa.test');
  });

  it('rejects a response whose imprint binds a different signature', async () => {
    const resp = buildTimeStampResp('AAAA', new Date('2026-04-20T10:30:06Z'));
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, async arrayBuffer() { return resp.buffer.slice(resp.byteOffset, resp.byteOffset + resp.byteLength); } })));
    const ts = await requestTimestamp(crypto.randomBytes(256).toString('base64'), { urls: ['http://tsa.test'] });
    expect(ts).toBeNull();
  });

  it('returns null when all TSAs are unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down'); }));
    const ts = await requestTimestamp(crypto.randomBytes(64).toString('base64'), { urls: ['http://a.test', 'http://b.test'] });
    expect(ts).toBeNull();
  });
});
