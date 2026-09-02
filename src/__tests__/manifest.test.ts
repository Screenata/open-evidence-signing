import { describe, it, expect, beforeAll } from 'vitest';
import { verifyManifest } from '../manifest';
import { resolverFromPems } from '../discovery';
import { generateTestKeyPair, signTestManifest, type TestKeyPair } from '../testkey';

describe('verifyManifest (v4.0)', () => {
  let key: TestKeyPair;
  let resolver: ReturnType<typeof resolverFromPems>;

  beforeAll(() => {
    key = generateTestKeyPair('RSA-SHA256');
    resolver = resolverFromPems([key.publicKeyPem]);
  });

  const base = () => ({
    version: '4.0',
    title: 'Q1 Access Control Evidence',
    files: { manifest: { filename: 'manifest.json', sha256: '', size_bytes: 0 }, screenshots: [] },
  });

  it('verifies a freshly signed manifest', async () => {
    const signed = signTestManifest(base(), key);
    const r = await verifyManifest(JSON.stringify(signed), resolver);
    expect(r.valid).toBe(true);
    expect(r.checks[0].passed).toBe(true);
    expect(r.details.manifestVersion).toBe('4.0');
  });

  it('fails when the manifest is tampered after signing', async () => {
    const signed = signTestManifest(base(), key) as Record<string, unknown>;
    const tampered = JSON.parse(JSON.stringify(signed));
    tampered.title = 'Renamed';
    const r = await verifyManifest(tampered, resolver);
    expect(r.valid).toBe(false);
  });

  it('rejects a manifest with no signature', async () => {
    const r = await verifyManifest(JSON.stringify(base()), resolver);
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/no cryptographic signature/i);
  });

  it('rejects a legacy v3.0 manifest', async () => {
    const r = await verifyManifest(
      JSON.stringify({ version: '3.0', cryptographic_signature: { signature: 'x', algorithm: 'RSA-SHA256', publicKeyFingerprint: key.fingerprint } }),
      resolver
    );
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/no longer supported/i);
  });

  it('fails when the signing key is unknown', async () => {
    const signed = signTestManifest(base(), key);
    const r = await verifyManifest(JSON.stringify(signed), resolverFromPems([generateTestKeyPair().publicKeyPem]));
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/not found/i);
  });
});
