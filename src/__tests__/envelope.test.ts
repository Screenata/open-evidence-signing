import { describe, it, expect, beforeAll } from 'vitest';
import { verifyEnvelope } from '../envelope';
import { resolverFromDiscovery, resolverFromPems } from '../discovery';
import { generateTestKeyPair, createTestEnvelope, type TestKeyPair } from '../testkey';
import { buildTimeStampToken } from './helpers/der';
import type { DiscoveryDocument, KeyResolver, ResolvedKey } from '../types';

const ISSUER = { id: 'https://issuer.example', name: 'Example', keyDiscovery: 'https://issuer.example/.well-known/oes-signing' };
const content = Buffer.from('evidence bytes', 'utf-8');
const metadata = { title: 'AWS MFA Config', collectedAt: '2026-04-20T10:30:00Z', framework: 'SOC 2', controlRef: 'CC6.1' };

function discoveryFor(key: TestKeyPair): DiscoveryDocument {
  return {
    issuer: ISSUER.id,
    specVersion: '1.0',
    keys: [{ fingerprint: key.fingerprint, algorithm: key.algorithm, publicKeyPem: key.publicKeyPem, revoked: false, validTo: null }],
  };
}

describe('verifyEnvelope (spec §7)', () => {
  let key: TestKeyPair;
  let resolver: KeyResolver;

  beforeAll(() => {
    key = generateTestKeyPair('RSA-SHA256');
    resolver = resolverFromDiscovery(discoveryFor(key));
  });

  it('verifies a valid envelope with evidence bytes', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    const r = await verifyEnvelope(env, content, resolver);
    expect(r.valid).toBe(true);
    expect(r.contentHashVerified).toBe(true);
    expect(r.details.keyFingerprint).toBe(key.fingerprint);
    expect(r.details.issuer).toBe(ISSUER.id);
  });

  it('verifies without evidence bytes but reports contentHashVerified=false (§7.2)', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    const r = await verifyEnvelope(JSON.stringify(env), undefined, resolver);
    expect(r.valid).toBe(true);
    expect(r.contentHashVerified).toBe(false);
    expect(r.warnings.some((w) => /content hash not verified/i.test(w))).toBe(true);
  });

  it('fails on content hash mismatch', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    const r = await verifyEnvelope(env, Buffer.from('other bytes'), resolver);
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/content hash mismatch/i);
  });

  it('fails on tampered subject metadata', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    const tampered = JSON.parse(JSON.stringify(env));
    tampered.subject.metadata.controlRef = 'CC7.2';
    const r = await verifyEnvelope(tampered, content, resolver);
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/invalid signature/i);
  });

  it('rejects an unsupported algorithm rather than skipping (§15.3)', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    const altered = JSON.parse(JSON.stringify(env));
    altered.proof.algorithm = 'Ed25519';
    const r = await verifyEnvelope(altered, content, resolver);
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/unsupported algorithm/i);
  });

  it('rejects a bad @context / version / canonicalization / signedFields', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    for (const mut of [
      (e: any) => (e['@context'] = 'https://evil.example/v1'),
      (e: any) => (e.version = '2.0'),
      (e: any) => (e.proof.canonicalization = 'jcs'),
      (e: any) => (e.proof.signedFields = 'everything'),
    ]) {
      const bad = JSON.parse(JSON.stringify(env));
      mut(bad);
      const r = await verifyEnvelope(bad, content, resolver);
      expect(r.valid).toBe(false);
    }
  });

  it('fails on unknown signing key', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    const altered = JSON.parse(JSON.stringify(env));
    altered.proof.publicKeyFingerprint = 'ffffffffffffffff';
    const r = await verifyEnvelope(altered, content, resolver);
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/not found/i);
    // Content integrity was established before key resolution failed — the
    // result must not contradict its own checks.
    expect(r.contentHashVerified).toBe(true);
    expect(r.details.issuer).toBe(ISSUER.id);
  });

  it('fails on a revoked key', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    const revokedResolver: KeyResolver = () => ({ pem: key.publicKeyPem, fingerprint: key.fingerprint, revoked: true });
    const r = await verifyEnvelope(env, content, revokedResolver);
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/revoked/i);
    expect(r.contentHashVerified).toBe(true);
    expect(r.details.issuer).toBe(ISSUER.id);
  });

  it('warns (but still passes) on an expired key with no timestamp', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    const expired: KeyResolver = () => ({ pem: key.publicKeyPem, fingerprint: key.fingerprint, validTo: '2020-01-01T00:00:00Z' });
    const r = await verifyEnvelope(env, content, expired);
    expect(r.valid).toBe(true);
    expect(r.warnings.some((w) => /expired/i.test(w))).toBe(true);
  });

  it('rejects invalid JSON', async () => {
    const r = await verifyEnvelope('not json', undefined, resolver);
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/invalid json/i);
  });

  it('verifies an ECDSA-signed envelope', async () => {
    const ecKey = generateTestKeyPair('ECDSA-SHA256');
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, ecKey);
    const r = await verifyEnvelope(env, content, resolverFromPems([ecKey.publicKeyPem]));
    expect(r.valid).toBe(true);
    expect(r.details.algorithm).toBe('ECDSA-SHA256');
  });

  describe('RFC 3161 timestamp binding', () => {
    it('accepts a valid timestamp and reports timestampedAt', async () => {
      const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
      const genTime = new Date('2026-04-20T10:30:06Z');
      env.proof.timestamp = {
        type: 'RFC3161',
        token: buildTimeStampToken(env.proof.signatureValue, genTime),
        authority: 'http://timestamp.test',
        timestampedAt: genTime.toISOString(),
        serialNumber: '4242',
      };
      const r = await verifyEnvelope(env, content, resolver);
      expect(r.valid).toBe(true);
      expect(r.details.timestampedAt).toBe('2026-04-20T10:30:06Z');
    });

    it('rejects a timestamp whose imprint does not match the signature', async () => {
      const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
      env.proof.timestamp = {
        type: 'RFC3161',
        token: buildTimeStampToken('AAAA', new Date('2026-04-20T10:30:06Z')),
        authority: 'http://timestamp.test',
        timestampedAt: '2026-04-20T10:30:06Z',
        serialNumber: '4242',
      };
      const r = await verifyEnvelope(env, content, resolver);
      expect(r.valid).toBe(false);
      expect(r.errors.join(' ')).toMatch(/messageImprint|timestamp/i);
    });

    it('rejects a future timestamp', async () => {
      const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
      const future = new Date(Date.now() + 60 * 60 * 1000);
      env.proof.timestamp = {
        type: 'RFC3161',
        token: buildTimeStampToken(env.proof.signatureValue, future),
        authority: 'http://timestamp.test',
        timestampedAt: future.toISOString(),
        serialNumber: '4242',
      };
      const r = await verifyEnvelope(env, content, resolver);
      expect(r.valid).toBe(false);
      expect(r.errors.join(' ')).toMatch(/future/i);
    });
  });

  it('clears the expiry warning when a timestamp predates key expiry (§7.5.8)', async () => {
    const env = createTestEnvelope({ content, metadata, issuer: ISSUER }, key);
    const genTime = new Date('2026-04-20T10:30:06Z');
    env.proof.timestamp = {
      type: 'RFC3161',
      token: buildTimeStampToken(env.proof.signatureValue, genTime),
      authority: 'http://timestamp.test',
      timestampedAt: genTime.toISOString(),
      serialNumber: '4242',
    };
    const expired: KeyResolver = (): ResolvedKey => ({
      pem: key.publicKeyPem,
      fingerprint: key.fingerprint,
      validTo: '2026-05-01T00:00:00Z', // expires AFTER the timestamp
    });
    const r = await verifyEnvelope(env, content, expired);
    expect(r.valid).toBe(true);
    expect(r.warnings.some((w) => /expired/i.test(w))).toBe(false);
  });
});
