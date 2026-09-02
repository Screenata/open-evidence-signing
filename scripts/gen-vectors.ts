/**
 * Generate the committed OES test vectors.
 *
 * Run: `bun run scripts/gen-vectors.ts` (from the package root).
 *
 * The vectors are signed with the committed RSA test key in
 * `test-vectors/test-key.private.pem`. RSA PKCS#1 v1.5 signatures are
 * deterministic, so regenerating produces byte-identical output — a clean diff
 * means nothing drifted. A companion continuous-integration parity test proves
 * these vectors are byte-equivalent to what the reference signer emits.
 *
 * The §4 timestamp vector uses a SYNTHETIC RFC 3161 token (no real TSA cert);
 * it exercises the imprint + genTime binding the verifier checks (the verifier
 * does not validate the TSA certificate chain — see SPEC.md §6.3 step 7).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeFingerprint } from '../src/discovery';
import { createTestEnvelope, signTestManifest, signBytes, type TestKeyPair } from '../src/testkey';
import { makeZip } from '../src/__tests__/helpers/zipwriter';
import { buildTimeStampToken } from '../src/__tests__/helpers/der';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'test-vectors');
const ISSUER = { id: 'https://app.screenata.example', name: 'Screenata (test)', keyDiscovery: 'https://app.screenata.example/.well-known/oes-signing' };
const CREATED = '2026-04-20T10:30:00.000Z';
const sha256 = (b: Buffer) => crypto.createHash('sha256').update(b).digest('hex');

const privateKeyPem = fs.readFileSync(path.join(DIR, 'test-key.private.pem'), 'utf-8');
const publicKeyPem = fs.readFileSync(path.join(DIR, 'test-key.public.pem'), 'utf-8');
const key: TestKeyPair = { privateKeyPem, publicKeyPem, fingerprint: computeFingerprint(publicKeyPem), algorithm: 'RSA-SHA256' };

function writeCase(name: string, files: Record<string, string | Buffer>, expected: unknown) {
  const dir = path.join(DIR, name);
  fs.mkdirSync(dir, { recursive: true });
  for (const [f, data] of Object.entries(files)) fs.writeFileSync(path.join(dir, f), data);
  fs.writeFileSync(path.join(dir, 'expected.json'), JSON.stringify(expected, null, 2) + '\n');
  console.log(`  ✓ ${name}`);
}

function stable(o: unknown): string {
  return JSON.stringify(o, null, 2) + '\n';
}

console.log('Generating OES test vectors with key', key.fingerprint);

// Discovery document (the offline key source for every vector).
fs.writeFileSync(
  path.join(DIR, 'issuer-discovery.json'),
  stable({
    issuer: ISSUER.id,
    specVersion: '1.0',
    keys: [{ fingerprint: key.fingerprint, algorithm: 'RSA-SHA256', publicKeyPem, validFrom: '2026-01-01T00:00:00Z', validTo: null, revoked: false }],
    supportedAlgorithms: ['RSA-SHA256', 'ECDSA-SHA256'],
  })
);

// 01 — plain single-file envelope.
{
  const content = Buffer.from('MFA is enforced for all IAM users with console access.\n', 'utf-8');
  const env = createTestEnvelope(
    { content, id: 'env_vec_plain_0001', created: CREATED, issuer: ISSUER, metadata: { title: 'AWS IAM MFA export', collectedAt: CREATED, framework: 'SOC 2', controlRef: 'CC6.1' } },
    key
  );
  writeCase('01-plain-envelope', { 'evidence.txt': content, 'envelope.oes.json': stable(env) }, {
    description: 'A single text evidence file with a plain (no-TSA) envelope.',
    artifact: 'envelope', target: 'envelope.oes.json', content: 'evidence.txt', keys: '../issuer-discovery.json',
    expect: { valid: true, contentHashVerified: true, timestamped: false },
  });
}

// 02 — multi-file bundle envelope (subject.files[] over a ZIP).
{
  const shot = Buffer.from('PNG\x89 screenshot of MFA settings page', 'binary');
  const cfg = Buffer.from(JSON.stringify({ mfa: 'enforced', users: 12 }, null, 2), 'utf-8');
  const bundle = makeZip([
    { name: 'screenshots/01_mfa_settings.png', data: shot },
    { name: 'attachments/iam-policy.json', data: cfg },
  ]);
  const files = [
    { filename: 'screenshots/01_mfa_settings.png', contentHash: { algorithm: 'SHA-256', value: sha256(shot) }, size: shot.length, mediaType: 'image/png' },
    { filename: 'attachments/iam-policy.json', contentHash: { algorithm: 'SHA-256', value: sha256(cfg) }, size: cfg.length, mediaType: 'application/json' },
  ];
  const env = createTestEnvelope(
    { content: bundle, id: 'env_vec_bundle_0002', created: CREATED, type: 'compliance-evidence:bundle', files, issuer: ISSUER, metadata: { title: 'MFA bundle', collectedAt: CREATED, framework: 'SOC 2', controlRef: 'CC6.1' } },
    key
  );
  writeCase('02-bundle-envelope', { 'bundle.zip': bundle, 'envelope.oes.json': stable(env) }, {
    description: 'A multi-file ZIP bundle. Whole-bundle content hash + per-file subject.files[] hashes.',
    artifact: 'envelope', target: 'envelope.oes.json', content: 'bundle.zip', keys: '../issuer-discovery.json',
    expect: { valid: true, contentHashVerified: true, bundleFiles: true },
  });
}

// 03 — standalone v4.0 evidence-pack ZIP (signed manifest + per-file signatures).
{
  const shot = Buffer.from('PNG\x89 access review screenshot', 'binary');
  const entry = { filename: 'screenshots/01.png', sha256: sha256(shot), size_bytes: shot.length, mediaType: 'image/png', signature: signBytes(shot, key) };
  // Include the production-shaped files.manifest self-entry so signing exercises
  // the size/hash self-fill path (sign.ts) — covered by the parity test.
  const manifest = signTestManifest(
    { version: '4.0', title: 'Access Review Pack', files: { manifest: { filename: 'manifest.json', sha256: '', size_bytes: 0 }, screenshots: [entry] } },
    key
  );
  const pack = makeZip([
    { name: 'manifest.json', data: Buffer.from(stable(manifest)) },
    { name: 'screenshots/01.png', data: shot },
  ]);
  writeCase('03-manifest-pack', { 'pack.zip': pack }, {
    description: 'A standalone v4.0 evidence-pack ZIP: signed manifest plus a hashed, signed file.',
    artifact: 'zip', target: 'pack.zip', keys: '../issuer-discovery.json',
    expect: { valid: true },
  });
}

// 04 — envelope with a (synthetic) RFC 3161 timestamp.
{
  const content = Buffer.from('Timestamped attestation payload\n', 'utf-8');
  const env = createTestEnvelope(
    { content, id: 'env_vec_tsa_0004', created: CREATED, issuer: ISSUER, metadata: { title: 'Timestamped evidence', collectedAt: CREATED } },
    key
  );
  const genTime = new Date('2026-04-20T10:30:06Z');
  env.proof.timestamp = {
    type: 'RFC3161',
    token: buildTimeStampToken(env.proof.signatureValue, genTime),
    authority: 'http://timestamp.test (synthetic)',
    timestampedAt: genTime.toISOString(),
    serialNumber: '4242',
  };
  writeCase('04-envelope-tsa', { 'evidence.txt': content, 'envelope.oes.json': stable(env) }, {
    description: 'Envelope carrying a SYNTHETIC RFC 3161 timestamp (no real TSA cert) — exercises the imprint + genTime binding.',
    artifact: 'envelope', target: 'envelope.oes.json', content: 'evidence.txt', keys: '../issuer-discovery.json', syntheticTimestamp: true,
    expect: { valid: true, contentHashVerified: true, timestamped: true },
  });
}

// 05 — tampered envelope (metadata altered after signing).
{
  const content = Buffer.from('Original evidence text\n', 'utf-8');
  const env = createTestEnvelope(
    { content, id: 'env_vec_tamper_0005', created: CREATED, issuer: ISSUER, metadata: { title: 'Original title', collectedAt: CREATED, controlRef: 'CC6.1' } },
    key
  );
  (env.subject.metadata as Record<string, unknown>).controlRef = 'CC7.2'; // tamper after signing
  writeCase('05-tampered-envelope', { 'evidence.txt': content, 'envelope.oes.json': stable(env) }, {
    description: 'Subject metadata altered after signing — signature must fail.',
    artifact: 'envelope', target: 'envelope.oes.json', content: 'evidence.txt', keys: '../issuer-discovery.json',
    expect: { valid: false, errorsMatch: 'Invalid signature' },
  });
}

// 06 — tampered pack (file bytes swapped, manifest hash no longer matches).
{
  const shot = Buffer.from('PNG\x89 original file', 'binary');
  const entry = { filename: 'screenshots/01.png', sha256: sha256(shot), size_bytes: shot.length, signature: signBytes(shot, key) };
  const manifest = signTestManifest({ version: '4.0', title: 'Tamper Pack', files: { screenshots: [entry] } }, key);
  const pack = makeZip([
    { name: 'manifest.json', data: Buffer.from(stable(manifest)) },
    { name: 'screenshots/01.png', data: Buffer.from('PNG\x89 SWAPPED file', 'binary') },
  ]);
  writeCase('06-tampered-pack', { 'pack.zip': pack }, {
    description: 'A pack whose file bytes were swapped after the manifest was signed — file hash check must fail.',
    artifact: 'zip', target: 'pack.zip', keys: '../issuer-discovery.json',
    expect: { valid: false, errorsMatch: 'hash mismatch' },
  });
}

// 07 — envelope signed by an unknown key (not in discovery).
{
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs1', format: 'pem' } });
  const otherKey: TestKeyPair = { privateKeyPem: other.privateKey, publicKeyPem: other.publicKey, fingerprint: computeFingerprint(other.publicKey), algorithm: 'RSA-SHA256' };
  const content = Buffer.from('Evidence signed by an unlisted key\n', 'utf-8');
  const env = createTestEnvelope(
    { content, id: 'env_vec_unknown_0007', created: CREATED, issuer: ISSUER, metadata: { title: 'Unknown key', collectedAt: CREATED } },
    otherKey
  );
  writeCase('07-unknown-key', { 'evidence.txt': content, 'envelope.oes.json': stable(env) }, {
    description: 'Envelope signed by a key absent from the discovery document — key resolution must fail.',
    artifact: 'envelope', target: 'envelope.oes.json', content: 'evidence.txt', keys: '../issuer-discovery.json',
    expect: { valid: false, errorsMatch: 'not found' },
  });
}

console.log('Done.');
