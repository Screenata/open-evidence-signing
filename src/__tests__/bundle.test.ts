import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import { verifyZipPack, verifyEnvelopeBundleFiles } from '../bundle';
import { readZip } from '../zip';
import { resolverFromPems } from '../discovery';
import { generateTestKeyPair, signTestManifest, signBytes, createTestEnvelope, type TestKeyPair } from '../testkey';
import { makeZip } from './helpers/zipwriter';

const sha256 = (b: Buffer) => crypto.createHash('sha256').update(b).digest('hex');

describe('zip reader', () => {
  it('round-trips STORE and DEFLATE entries', () => {
    const data = Buffer.from('x'.repeat(5000)); // compressible
    const zip = makeZip([{ name: 'a.txt', data: Buffer.from('hello') }, { name: 'dir/b.bin', data }]);
    const entries = readZip(zip);
    expect(entries.get('a.txt')?.toString()).toBe('hello');
    expect(entries.get('dir/b.bin')?.equals(data)).toBe(true);
  });

  it('throws on a non-ZIP buffer', () => {
    expect(() => readZip(Buffer.from('not a zip'))).toThrow(/ZIP/i);
  });
});

describe('verifyZipPack (v4.0 evidence pack)', () => {
  let key: TestKeyPair;
  let resolver: ReturnType<typeof resolverFromPems>;

  beforeAll(() => {
    key = generateTestKeyPair('RSA-SHA256');
    resolver = resolverFromPems([key.publicKeyPem]);
  });

  function buildPack(tamper = false): Buffer {
    const png = Buffer.from('PNG-bytes-1');
    const entry = { filename: 'screenshots/01.png', sha256: sha256(png), size_bytes: png.length, signature: signBytes(png, key) };
    const manifest = { version: '4.0', title: 'Pack', files: { screenshots: [entry] } };
    const signed = signTestManifest(manifest, key);
    const fileData = tamper ? Buffer.from('PNG-bytes-TAMPERED') : png;
    return makeZip([
      { name: 'manifest.json', data: Buffer.from(JSON.stringify(signed)) },
      { name: 'screenshots/01.png', data: fileData },
    ]);
  }

  it('verifies a valid pack: manifest signature + per-file hash + per-file signature', async () => {
    const r = await verifyZipPack(buildPack(), resolver);
    expect(r.valid).toBe(true);
    expect(r.details.filesVerified).toBe(1);
    expect(r.details.filesTotal).toBe(1);
  });

  it('fails when a file inside the pack was swapped', async () => {
    const r = await verifyZipPack(buildPack(true), resolver);
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/hash mismatch/i);
  });

  it('verifies generic artifacts and rejects a swapped artifact', async () => {
    const csv = Buffer.from('user,decision\nalice@example.com,CERTIFY');
    const manifest = {
      version: '4.0',
      title: 'Access review',
      files: {
        artifacts: [
          {
            filename: 'decisions.csv',
            sha256: sha256(csv),
            size_bytes: csv.length,
          },
        ],
      },
    };
    const signed = signTestManifest(manifest, key);
    const valid = await verifyZipPack(
      makeZip([
        { name: 'manifest.json', data: Buffer.from(JSON.stringify(signed)) },
        { name: 'decisions.csv', data: csv },
      ]),
      resolver,
    );
    const tampered = await verifyZipPack(
      makeZip([
        { name: 'manifest.json', data: Buffer.from(JSON.stringify(signed)) },
        { name: 'decisions.csv', data: Buffer.from('tampered') },
      ]),
      resolver,
    );

    expect(valid.valid).toBe(true);
    expect(valid.details.filesVerified).toBe(1);
    expect(valid.details.filesTotal).toBe(1);
    expect(tampered.valid).toBe(false);
    expect(tampered.errors.join(' ')).toMatch(/hash mismatch/i);
  });

  it('fails when there is no manifest.json', async () => {
    const zip = makeZip([{ name: 'foo.txt', data: Buffer.from('x') }]);
    const r = await verifyZipPack(zip, resolver);
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toMatch(/no manifest/i);
  });
});

describe('verifyEnvelopeBundleFiles (subject.files[])', () => {
  it('passes when every file hash matches and fails when one is swapped', () => {
    const key = generateTestKeyPair();
    const png = Buffer.from('PNG-bytes-1');
    const files = [{ filename: 'screenshots/01.png', contentHash: { algorithm: 'SHA-256', value: sha256(png) }, size: png.length }];
    const zip = makeZip([{ name: 'screenshots/01.png', data: png }]);
    const env = createTestEnvelope(
      { content: zip, type: 'compliance-evidence:bundle', files, metadata: { title: 'Bundle' }, issuer: { id: 'https://issuer.example' } },
      key
    );
    expect(verifyEnvelopeBundleFiles(env, zip).every((c) => c.passed)).toBe(true);

    const swapped = makeZip([{ name: 'screenshots/01.png', data: Buffer.from('different') }]);
    expect(verifyEnvelopeBundleFiles(env, swapped).every((c) => c.passed)).toBe(false);
  });
});
