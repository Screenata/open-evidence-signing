/**
 * Test-key helpers for fixtures and self-checking a verifier.
 *
 * These wrap the real signing primitives in {@link import('./sign')} with a
 * generated in-process key and test-only id defaults. For production / BYOK
 * signing use `signEnvelope` + a KMS-backed `Signer` directly — do not generate
 * throwaway keys to sign real evidence.
 */
import crypto from 'node:crypto';
import { canonicalize } from './canonical';
import { computeFingerprint } from './discovery';
import { buildSubject, assembleEnvelope, fillManifestSelfEntry, type SubjectInput, type IssuerInput } from './sign';
import type { EvidenceSigningEnvelope, SigningAlgorithm } from './types';

export interface TestKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
  fingerprint: string;
  algorithm: SigningAlgorithm;
}

/** Generate an in-memory test key pair. RSA-2048 or EC P-256. */
export function generateTestKeyPair(algorithm: SigningAlgorithm = 'RSA-SHA256'): TestKeyPair {
  const { privateKey, publicKey } =
    algorithm === 'ECDSA-SHA256'
      ? crypto.generateKeyPairSync('ec', {
          namedCurve: 'prime256v1',
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        })
      : crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
        });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey, fingerprint: computeFingerprint(publicKey), algorithm };
}

function nodeSignAlgorithm(algorithm: SigningAlgorithm): string {
  return algorithm === 'ECDSA-SHA256' ? 'SHA256' : 'RSA-SHA256';
}

/** Sign arbitrary bytes with a test key (raw-bytes scheme). */
export function signBytes(data: Buffer, key: TestKeyPair): string {
  const sign = crypto.createSign(nodeSignAlgorithm(key.algorithm));
  sign.update(data);
  return sign.sign(key.privateKeyPem, 'base64');
}

export interface CreateTestEnvelopeInput extends SubjectInput {
  issuer: IssuerInput;
  created?: string;
  /** Fixed envelope id (for reproducible fixtures). Random if omitted. */
  id?: string;
}

/** Build a TEST OES envelope (no TSA). Signature is real and verifiable. */
export function createTestEnvelope(input: CreateTestEnvelopeInput, key: TestKeyPair): EvidenceSigningEnvelope {
  const created = input.created ?? new Date().toISOString();
  const subject = buildSubject(input, created);
  const signatureValue = signBytes(canonicalize(subject), key);
  const id = input.id ?? `env_test_${crypto.randomBytes(8).toString('hex')}`;
  return assembleEnvelope(subject, signatureValue, { algorithm: key.algorithm, fingerprint: key.fingerprint }, {
    id,
    issuer: input.issuer,
    created,
  });
}

/** Attach a TEST `cryptographic_signature` to a v4.0 manifest (no TSA). */
export function signTestManifest(manifest: Record<string, unknown>, key: TestKeyPair): Record<string, unknown> {
  const { cryptographic_signature: _drop, ...rest } = manifest;
  fillManifestSelfEntry(rest);
  const signature = signBytes(canonicalize(rest), key);
  return {
    ...rest,
    cryptographic_signature: {
      signature,
      signedAt: new Date().toISOString(),
      publicKeyFingerprint: key.fingerprint,
      algorithm: key.algorithm,
      canonicalization: 'sorted-keys-2space',
      signed_fields: '*except:cryptographic_signature',
    },
  };
}
