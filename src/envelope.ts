/**
 * OES Evidence Signing Envelope verification — the normative procedure in
 * spec §7. Pure function over an envelope, optional evidence bytes, and a
 * {@link KeyResolver}; no I/O of its own beyond what the resolver does.
 */
import crypto from 'node:crypto';
import { canonicalize } from './canonical';
import { verifyTimestamp } from './timestamp';
import { verifyEnvelopeBundleFiles } from './bundle';
import {
  OES_CONTEXT,
  OES_LEGACY_CONTEXTS,
  type EvidenceSigningEnvelope,
  type KeyResolver,
  type SigningAlgorithm,
  type VerificationCheck,
  type VerificationResult,
} from './types';

const SUPPORTED_ALGORITHMS: SigningAlgorithm[] = ['RSA-SHA256', 'ECDSA-SHA256'];

/** Map an OES algorithm id to the Node `crypto.createVerify` algorithm name. */
function nodeVerifyAlgorithm(algorithm: string): string {
  return algorithm === 'ECDSA-SHA256' ? 'SHA256' : 'RSA-SHA256';
}

function fail(errors: string[]): VerificationResult {
  return { valid: false, contentHashVerified: false, checks: [], errors, warnings: [], details: {} };
}

/**
 * Verify an OES envelope per spec §7.
 *
 * @param envelopeInput  the envelope as a JSON string or parsed object
 * @param evidenceBytes  raw evidence bytes; omit to skip content-hash checks
 *                       (`contentHashVerified` will be false — spec §7.2)
 * @param resolveKey     resolves `proof.publicKeyFingerprint` to a public key
 * @param now            current time in ms (injectable for deterministic tests)
 */
export async function verifyEnvelope(
  envelopeInput: string | Record<string, unknown>,
  evidenceBytes: Buffer | undefined,
  resolveKey: KeyResolver,
  now: number = Date.now()
): Promise<VerificationResult> {
  // Step 1: parse + structural validation (spec §7.1 step 1)
  let envelope: EvidenceSigningEnvelope;
  try {
    envelope =
      typeof envelopeInput === 'string'
        ? JSON.parse(envelopeInput)
        : (envelopeInput as unknown as EvidenceSigningEnvelope);
  } catch {
    return fail(['Invalid JSON in envelope']);
  }

  if (envelope['@context'] !== OES_CONTEXT && !OES_LEGACY_CONTEXTS.includes(envelope['@context'])) {
    return fail([`Unsupported @context: ${envelope['@context']}`]);
  }
  if (envelope.version !== '1.0') {
    return fail([`Unsupported envelope version: ${envelope.version}`]);
  }
  if (!envelope.subject?.contentHash?.value || !envelope.proof?.signatureValue) {
    return fail(['Envelope is missing required fields']);
  }
  if (!SUPPORTED_ALGORITHMS.includes(envelope.proof.algorithm as SigningAlgorithm)) {
    // Spec §15.3: reject unknown algorithms rather than skip verification.
    return fail([`Unsupported algorithm: ${envelope.proof.algorithm}`]);
  }
  if (envelope.proof.canonicalization !== 'sorted-keys-2space') {
    return fail([`Unsupported canonicalization: ${envelope.proof.canonicalization}`]);
  }
  if (envelope.proof.signedFields !== 'subject') {
    return fail([`Unsupported signedFields: ${envelope.proof.signedFields}`]);
  }

  const checks: VerificationCheck[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];
  let contentHashVerified = false;

  if (OES_LEGACY_CONTEXTS.includes(envelope['@context'])) {
    warnings.push(`Envelope uses legacy @context "${envelope['@context']}" (pre-openevidence.dev namespace)`);
  }

  // Step 2: content integrity (spec §7.1 step 2; skipped without bytes per §7.2)
  if (evidenceBytes) {
    const actual = crypto.createHash('sha256').update(evidenceBytes).digest('hex');
    const match = actual === envelope.subject.contentHash.value;
    checks.push({
      name: 'Content Hash',
      passed: match,
      details: match ? 'SHA-256 of evidence matches subject.contentHash' : 'Content hash mismatch',
    });
    if (!match) {
      return {
        valid: false,
        contentHashVerified: false,
        checks,
        errors: ['Content hash mismatch'],
        warnings,
        details: { issuer: envelope.issuer?.id },
      };
    }
    contentHashVerified = true;

    // Spec §7.1 step 2.4 — when subject.files[] is present, verify each file's
    // hash individually. Part of the REQUIRED content-integrity procedure, so
    // it belongs here in the library, not only in the CLI.
    if (envelope.subject.files?.length) {
      const fileChecks = verifyEnvelopeBundleFiles(envelope, evidenceBytes);
      checks.push(...fileChecks);
      const failed = fileChecks.filter((c) => !c.passed);
      if (failed.length) {
        return {
          valid: false,
          contentHashVerified,
          checks,
          errors: failed.map((c) => `Bundle file failed: ${c.name}`),
          warnings,
          details: { issuer: envelope.issuer?.id },
        };
      }
    }
  } else {
    warnings.push('Evidence bytes not provided; content hash not verified');
  }

  // Step 3: obtain public key (spec §7.1 step 3)
  const fingerprint = envelope.proof.publicKeyFingerprint;
  const key = await resolveKey(fingerprint, envelope);
  // Preserve the content-hash result and issuer the way the signature-failure
  // return below does — these returns happen AFTER content integrity was
  // established, so fail() (which zeroes them) would contradict `checks`.
  if (!key) {
    return { valid: false, contentHashVerified, checks, errors: [`Signing key ${fingerprint} not found`], warnings, details: { issuer: envelope.issuer?.id } };
  }
  if (key.revoked) {
    return { valid: false, contentHashVerified, checks, errors: [`Signing key ${fingerprint} has been revoked`], warnings, details: { issuer: envelope.issuer?.id } };
  }
  let keyExpired = false;
  if (key.validTo) {
    const validToMs = new Date(key.validTo).getTime();
    if (!Number.isNaN(validToMs) && validToMs < now) keyExpired = true;
  }

  // Step 4: verify signature over the canonical subject (spec §7.1 step 4)
  const canonical = canonicalize(envelope.subject);
  let signatureValid: boolean;
  try {
    const verifier = crypto.createVerify(nodeVerifyAlgorithm(envelope.proof.algorithm));
    verifier.update(canonical);
    signatureValid = verifier.verify(key.pem, envelope.proof.signatureValue, 'base64');
  } catch {
    signatureValid = false;
  }
  checks.push({
    name: 'Signature',
    passed: signatureValid,
    details: signatureValid
      ? `Verified with key ${fingerprint}`
      : 'Signature verification failed — subject may have been altered',
  });
  if (!signatureValid) {
    errors.push('Invalid signature');
    return { valid: false, contentHashVerified, checks, errors, warnings, details: { issuer: envelope.issuer?.id } };
  }

  // Step 5: verify timestamp, if present (spec §7.1 step 5)
  let timestampedAt: string | null = null;
  if (envelope.proof.timestamp) {
    const tsCheck = verifyTimestamp(envelope.proof.timestamp.token, envelope.proof.signatureValue, now);
    checks.push(tsCheck);
    if (!tsCheck.passed) {
      errors.push(`TSA timestamp verification failed: ${tsCheck.details}`);
      return { valid: false, contentHashVerified, checks, errors, warnings, details: { issuer: envelope.issuer?.id } };
    }
    timestampedAt = tsCheck.timestampedAt;
    // Spec §7.3.5 / §7.5.8: a timestamp predating key expiry clears the warning.
    if (keyExpired && timestampedAt && key.validTo) {
      if (new Date(timestampedAt).getTime() < new Date(key.validTo).getTime()) {
        keyExpired = false;
      }
    }
  } else {
    warnings.push('No TSA timestamp present — time of signing cannot be independently verified');
  }

  if (keyExpired) {
    warnings.push('Signing key is expired and no timestamp proves the signature predates expiry');
  }

  return {
    valid: true,
    contentHashVerified,
    checks,
    errors,
    warnings,
    details: {
      issuer: envelope.issuer?.id,
      signedAt: envelope.proof.created,
      timestampedAt,
      keyFingerprint: fingerprint,
      algorithm: envelope.proof.algorithm,
    },
  };
}
