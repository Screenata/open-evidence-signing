/**
 * Type definitions for the Open Evidence Signing (OES) v1.0 format.
 *
 * Mirrors OPEN-EVIDENCE-SPEC-v1 §3 (envelope), §5 (discovery), and §8.4
 * (bundle manifest). Kept deliberately structural — a verifier only needs to
 * read these shapes, never construct them.
 */

export const OES_CONTEXT = 'https://openevidence.org/signing/v1' as const;

export type SigningAlgorithm = 'RSA-SHA256' | 'ECDSA-SHA256';

/** OES Evidence Signing Envelope (ESE) — spec §3.1. */
export interface EvidenceSigningEnvelope {
  '@context': string;
  version: string;
  id?: string;
  issuer: {
    id: string;
    name?: string;
    keyDiscovery: string;
  };
  subject: EnvelopeSubject;
  proof: EnvelopeProof;
}

export interface EnvelopeSubject {
  type: string;
  contentHash: { algorithm: string; value: string };
  files?: EnvelopeFile[];
  metadata?: Record<string, unknown>;
}

export interface EnvelopeFile {
  filename: string;
  contentHash: { algorithm: string; value: string };
  size: number;
  mediaType?: string;
}

export interface EnvelopeProof {
  type: string;
  created: string;
  algorithm: string;
  publicKeyFingerprint: string;
  signatureValue: string;
  canonicalization: string;
  signedFields: string;
  timestamp?: EnvelopeTimestamp;
}

export interface EnvelopeTimestamp {
  type: 'RFC3161';
  token: string;
  authority: string;
  timestampedAt: string;
  serialNumber: string;
}

/** Discovery document served at `{issuer}/.well-known/oes-signing` — spec §5.2. */
export interface DiscoveryDocument {
  issuer: string;
  specVersion?: string;
  keys: DiscoveryKey[];
  verificationEndpoint?: string;
  supportedAlgorithms?: SigningAlgorithm[];
  /** Reference-implementation extension; ignored by the spec verifier. */
  signing?: { enabled: boolean; algorithm: string; tsaConfigured: boolean };
}

export interface DiscoveryKey {
  fingerprint: string;
  algorithm: SigningAlgorithm;
  publicKeyPem: string;
  validFrom?: string;
  validTo?: string | null;
  revoked?: boolean;
}

/**
 * A resolved public key the verifier will check a signature against.
 * `validTo`/`revoked` carry through so the verifier can apply spec §7.3.4–7.3.5.
 */
export interface ResolvedKey {
  pem: string;
  fingerprint: string;
  validTo?: string | null;
  revoked?: boolean;
}

/**
 * A key source. Returns the key matching `fingerprint`, or null if it cannot
 * be resolved. Implementations: cached discovery doc (`--keys`), a live HTTPS
 * fetch of `issuer.keyDiscovery`, or an in-memory map.
 */
export type KeyResolver = (
  fingerprint: string,
  envelope?: EvidenceSigningEnvelope
) => Promise<ResolvedKey | null> | ResolvedKey | null;

/** Result of a single named check (signature, content hash, timestamp, …). */
export interface VerificationCheck {
  name: string;
  passed: boolean;
  details?: string;
}

/** Normalized verification result returned by every `verify*` entrypoint. */
export interface VerificationResult {
  /** Overall verdict. True only when every REQUIRED check passed. */
  valid: boolean;
  /** True when the original evidence bytes were supplied and hashed (spec §7.2). */
  contentHashVerified: boolean;
  checks: VerificationCheck[];
  errors: string[];
  warnings: string[];
  /** Populated on success / partial success. */
  details: {
    issuer?: string;
    signedAt?: string;
    timestampedAt?: string | null;
    keyFingerprint?: string;
    algorithm?: string;
    manifestVersion?: string;
    filesVerified?: number;
    filesTotal?: number;
  };
}
