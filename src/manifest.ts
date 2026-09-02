/**
 * v4.0 evidence-pack manifest verification (spec §8.6 inner signature /
 * Appendix D). The signature covers the canonical bytes of the manifest with
 * `cryptographic_signature` removed — matching the reference implementation's
 * `finalizeAndSignManifest` / `verifyManifestSignature`.
 */
import crypto from 'node:crypto';
import { canonicalize } from './canonical';
import { verifyTimestamp } from './timestamp';
import type { KeyResolver, ResolvedKey, VerificationCheck, VerificationResult } from './types';

/** A manifest key resolver — manifests carry a fingerprint, not a discovery URL. */
export type ManifestKeyResolver = (
  fingerprint: string,
  publicKeyUrl?: string
) => Promise<ResolvedKey | null> | ResolvedKey | null;

interface CryptographicSignature {
  signature: string;
  signedAt?: string;
  publicKeyFingerprint: string;
  algorithm: string;
  publicKeyUrl?: string;
  tsaTimestamp?: { token: string; timestampedAt: string; tsaUrl: string; serialNumber: string };
}

function nodeVerifyAlgorithm(algorithm: string): string {
  return algorithm === 'ECDSA-SHA256' ? 'SHA256' : 'RSA-SHA256';
}

function fail(errors: string[]): VerificationResult {
  return { valid: false, contentHashVerified: false, checks: [], errors, warnings: [], details: {} };
}

/**
 * Verify a v4.0 manifest's `cryptographic_signature`. Returns both the result
 * and the parsed manifest so callers (bundle verification) can reuse it.
 */
export async function verifyManifest(
  manifestInput: string | Record<string, unknown>,
  resolveKey: ManifestKeyResolver,
  now: number = Date.now()
): Promise<VerificationResult & { manifest?: Record<string, unknown> }> {
  let manifest: Record<string, unknown>;
  try {
    manifest = typeof manifestInput === 'string' ? JSON.parse(manifestInput) : manifestInput;
  } catch {
    return fail(['Invalid JSON in manifest']);
  }

  const version = manifest.version as string | undefined;
  if (version === '3.0') {
    return fail([
      'Manifest version 3.0 used a deprecated signing scheme that is no longer supported. Re-export to obtain a v4.0 signature.',
    ]);
  }

  const sig = manifest.cryptographic_signature as CryptographicSignature | undefined;
  if (!sig?.signature) {
    return { ...fail(['Manifest has no cryptographic signature']), manifest };
  }
  if (sig.algorithm !== 'RSA-SHA256' && sig.algorithm !== 'ECDSA-SHA256') {
    return { ...fail([`Unsupported algorithm: ${sig.algorithm}`]), manifest };
  }

  const key = await resolveKey(sig.publicKeyFingerprint, sig.publicKeyUrl);
  if (!key) return { ...fail([`Signing key ${sig.publicKeyFingerprint} not found`]), manifest };
  if (key.revoked) return { ...fail([`Signing key ${sig.publicKeyFingerprint} has been revoked`]), manifest };

  const { cryptographic_signature: _omit, ...manifestToVerify } = manifest;
  let signatureValid: boolean;
  try {
    const verifier = crypto.createVerify(nodeVerifyAlgorithm(sig.algorithm));
    verifier.update(canonicalize(manifestToVerify));
    signatureValid = verifier.verify(key.pem, sig.signature, 'base64');
  } catch {
    signatureValid = false;
  }

  const checks: VerificationCheck[] = [
    {
      name: 'Manifest Signature',
      passed: signatureValid,
      details: signatureValid
        ? `Verified with key ${sig.publicKeyFingerprint}`
        : 'Signature verification failed — manifest may have been altered',
    },
  ];
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!signatureValid) errors.push('Manifest signature verification failed');

  let timestampedAt: string | null = null;
  if (sig.tsaTimestamp) {
    const tsCheck = verifyTimestamp(sig.tsaTimestamp.token, sig.signature, now);
    checks.push(tsCheck);
    timestampedAt = tsCheck.timestampedAt;
    if (!tsCheck.passed) warnings.push(`TSA timestamp verification failed: ${tsCheck.details}`);
  } else {
    warnings.push('No TSA timestamp present');
  }

  return {
    valid: signatureValid,
    contentHashVerified: false,
    checks,
    errors,
    warnings,
    details: {
      signedAt: sig.signedAt,
      timestampedAt,
      publicKeyFingerprint: sig.publicKeyFingerprint,
      algorithm: sig.algorithm,
      manifestVersion: version,
    } as VerificationResult['details'],
    manifest,
  };
}
