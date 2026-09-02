/**
 * oes-verify — a zero-dependency verifier for the Open Evidence Signing (OES)
 * v1.0 format. Verify signed compliance evidence without trusting (or even
 * contacting) the issuer.
 *
 * Spec: OPEN-EVIDENCE-SPEC-v1 (https://openevidence.dev/signing/v1).
 * Apache-2.0. No runtime dependencies — Node built-ins only.
 *
 * @example
 * ```ts
 * import { verifyEnvelope, resolverFromDiscovery } from 'oes-verify';
 * const result = await verifyEnvelope(envelopeJson, evidenceBytes, resolverFromDiscovery(discoveryDoc));
 * if (!result.valid) throw new Error(result.errors.join('; '));
 * ```
 */

// ── Verify ──────────────────────────────────────────────────────────────────
export { verifyEnvelope } from './envelope';
export { verifyManifest, type ManifestKeyResolver } from './manifest';
export { verifyZipPack, verifyEnvelopeBundleFiles } from './bundle';
export {
  computeFingerprint,
  resolverFromDiscovery,
  resolverFromPems,
  resolverFromNetwork,
} from './discovery';
export { verifyTimestamp, extractTstInfo } from './timestamp';
export { canonicalize, sortKeys } from './canonical';
export { readZip } from './zip';

// ── Sign (BYOK-friendly — bring your own KMS-backed Signer) ──────────────────
export {
  signEnvelope,
  signManifest,
  localSigner,
  // shared OES-format primitives
  buildSubject,
  assembleEnvelope,
  fillManifestSelfEntry,
  type Signer,
  type SignEnvelopeOptions,
  type SubjectInput,
  type IssuerInput,
  type EnvelopeMetadata,
} from './sign';
export { requestTimestamp, buildTimeStampReq, type TsaOptions } from './tsa';

// Test-key helpers (generated throwaway keys — NOT for signing real evidence).
export {
  generateTestKeyPair,
  createTestEnvelope,
  signTestManifest,
  signBytes,
  type TestKeyPair,
  type CreateTestEnvelopeInput,
} from './testkey';

export type {
  EvidenceSigningEnvelope,
  EnvelopeSubject,
  EnvelopeFile,
  EnvelopeProof,
  EnvelopeTimestamp,
  DiscoveryDocument,
  DiscoveryKey,
  ResolvedKey,
  KeyResolver,
  SigningAlgorithm,
  VerificationResult,
  VerificationCheck,
} from './types';

export { OES_CONTEXT } from './types';
