import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { signEnvelope, signManifest, localSigner, type Signer } from '../sign';
import { verifyEnvelope } from '../envelope';
import { verifyManifest } from '../manifest';
import { resolverFromPems } from '../discovery';
import { createTestEnvelope, generateTestKeyPair, type TestKeyPair } from '../testkey';
import { buildTimeStampResp } from './helpers/der';

const ISSUER = { id: 'https://issuer.example', name: 'Example' };
const content = Buffer.from('signed evidence payload', 'utf-8');
const metadata = { title: 'AWS IAM export', collectedAt: '2026-04-20T10:30:00Z', framework: 'SOC 2', controlRef: 'CC6.1' };

describe('signEnvelope', () => {
  let key: TestKeyPair;
  beforeAll(() => {
    key = generateTestKeyPair('RSA-SHA256');
  });

  it('round-trips signEnvelope → verifyEnvelope', async () => {
    const env = await signEnvelope(localSigner(key.privateKeyPem), { content, metadata, issuer: ISSUER });
    const r = await verifyEnvelope(env, content, resolverFromPems([key.publicKeyPem]));
    expect(r.valid).toBe(true);
    expect(r.contentHashVerified).toBe(true);
    expect(env.proof.publicKeyFingerprint).toBe(key.fingerprint);
  });

  it('works with a BYOK Signer where the private key never enters the package', async () => {
    // The "KMS": only its sign() is exposed; the package only sees a Signer.
    const kms = localSigner(key.privateKeyPem);
    let sawPrivateKey = false;
    const byok: Signer = {
      algorithm: 'RSA-SHA256',
      fingerprint: key.fingerprint,
      async sign(bytes) {
        // package passes only the bytes to sign — no key material
        sawPrivateKey = bytes.toString().includes('PRIVATE KEY');
        return kms.sign(bytes);
      },
    };
    const env = await signEnvelope(byok, { content, metadata, issuer: ISSUER });
    const r = await verifyEnvelope(env, content, resolverFromPems([key.publicKeyPem]));
    expect(r.valid).toBe(true);
    expect(sawPrivateKey).toBe(false);
  });

  it('produces the same bytes as the test helper for identical inputs (one signing core)', async () => {
    const fixed = { content, metadata, issuer: ISSUER, id: 'env_fixed_1', created: '2026-04-20T10:30:05Z' };
    const viaSign = await signEnvelope(localSigner(key.privateKeyPem), fixed);
    const viaHelper = createTestEnvelope(fixed, key);
    expect(viaSign.proof.signatureValue).toBe(viaHelper.proof.signatureValue);
    expect(viaSign.subject).toEqual(viaHelper.subject);
  });

  it('signs an ECDSA envelope', async () => {
    const ec = generateTestKeyPair('ECDSA-SHA256');
    const env = await signEnvelope(localSigner(ec.privateKeyPem, 'ECDSA-SHA256'), { content, metadata, issuer: ISSUER });
    expect(env.proof.algorithm).toBe('ECDSA-SHA256');
    const r = await verifyEnvelope(env, content, resolverFromPems([ec.publicKeyPem]));
    expect(r.valid).toBe(true);
  });
});

describe('signManifest', () => {
  it('round-trips with files.manifest self-entry filled', async () => {
    const key = generateTestKeyPair();
    const manifest = await signManifest(localSigner(key.privateKeyPem), {
      version: '4.0',
      title: 'Pack',
      files: { manifest: { filename: 'manifest.json', sha256: '', size_bytes: 0 }, screenshots: [] },
    });
    const sig = manifest.cryptographic_signature as { algorithm: string };
    expect(sig.algorithm).toBe('RSA-SHA256');
    const selfEntry = (manifest.files as any).manifest;
    expect(selfEntry.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(selfEntry.size_bytes).toBeGreaterThan(0);

    const r = await verifyManifest(JSON.stringify(manifest), resolverFromPems([key.publicKeyPem]));
    expect(r.valid).toBe(true);
  });
});

describe('signEnvelope with TSA', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('attaches a verifiable RFC 3161 timestamp from a (mocked) TSA', async () => {
    const key = generateTestKeyPair();
    const genTime = new Date('2026-04-20T10:30:06Z');
    const signer = localSigner(key.privateKeyPem);
    const fixed = { content, metadata, issuer: ISSUER, id: 'env_tsa_1', created: genTime.toISOString() };

    // RSA PKCS#1 v1.5 is deterministic, so signing the same subject twice gives
    // the same signature. Pre-compute it (no TSA call), then mock the TSA to
    // return a synthetic granted response binding exactly that signature.
    const env0 = await signEnvelope(signer, fixed);
    const resp = buildTimeStampResp(env0.proof.signatureValue, genTime);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: true, async arrayBuffer() { return resp.buffer.slice(resp.byteOffset, resp.byteOffset + resp.byteLength); } }))
    );

    const env = await signEnvelope(signer, { ...fixed, tsa: { urls: ['http://tsa.test'] } });
    expect(env.proof.timestamp).toBeDefined();
    expect(env.proof.timestamp!.authority).toBe('http://tsa.test');

    const r = await verifyEnvelope(env, content, resolverFromPems([key.publicKeyPem]));
    expect(r.valid).toBe(true);
    expect(r.details.timestampedAt).toBe('2026-04-20T10:30:06Z');
  });

  it('returns no timestamp when every TSA fails (and the envelope is still valid)', async () => {
    const key = generateTestKeyPair();
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, async arrayBuffer() { return new ArrayBuffer(0); } })));
    const env = await signEnvelope(localSigner(key.privateKeyPem), { content, metadata, issuer: ISSUER, tsa: { urls: ['http://down.test'] } });
    expect(env.proof.timestamp).toBeUndefined();
    const r = await verifyEnvelope(env, content, resolverFromPems([key.publicKeyPem]));
    expect(r.valid).toBe(true);
  });
});
