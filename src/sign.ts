/**
 * OES signing (spec §4) — produce Evidence Signing Envelopes and v4.0 manifest
 * signatures. Issuer-side counterpart to the verifier, so any party (not just
 * Screenata) can mint OES evidence.
 *
 * BYOK / KMS by design: signing is driven through the {@link Signer} interface,
 * which only exposes `sign(bytes)`. A customer implements it over AWS/GCP KMS or
 * an HSM and the private key never enters this package. {@link localSigner} is a
 * convenience for the in-process PEM case.
 *
 * The envelope/manifest bytes produced here are byte-identical to the reference
 * implementation's `createEnvelope` / `finalizeAndSignManifest`, so the same
 * verifier (and the same test vectors) cover both.
 */
import crypto from 'node:crypto';
import { canonicalize } from './canonical';
import { computeFingerprint } from './discovery';
import { requestTimestamp, type TsaOptions } from './tsa';
import type {
  EvidenceSigningEnvelope,
  EnvelopeFile,
  EnvelopeTimestamp,
  SigningAlgorithm,
} from './types';

/**
 * A signing key handle. `sign` returns the base64 signature over `bytes` using
 * `algorithm`. Implement this over a KMS/HSM for BYOK — the private key stays in
 * the customer's control.
 */
export interface Signer {
  readonly algorithm: SigningAlgorithm;
  /** Spec §4.5 fingerprint of the corresponding public key. */
  readonly fingerprint: string;
  sign(bytes: Buffer): Promise<string> | string;
}

function nodeSignAlgorithm(a: SigningAlgorithm): string {
  return a === 'ECDSA-SHA256' ? 'SHA256' : 'RSA-SHA256';
}

/** In-process signer from a private key PEM. NOT for KMS/BYOK (use your own Signer). */
export function localSigner(privateKeyPem: string, algorithm: SigningAlgorithm = 'RSA-SHA256'): Signer {
  const publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }).toString();
  const fingerprint = computeFingerprint(publicKeyPem);
  return {
    algorithm,
    fingerprint,
    sign(bytes: Buffer): string {
      const s = crypto.createSign(nodeSignAlgorithm(algorithm));
      s.update(bytes);
      return s.sign(privateKeyPem, 'base64');
    },
  };
}

export interface EnvelopeMetadata {
  title: string;
  collectedAt?: string;
  collector?: string;
  framework?: string;
  controlRef?: string;
  description?: string;
}

export interface SubjectInput {
  content: Buffer;
  type?: string;
  files?: EnvelopeFile[];
  metadata: EnvelopeMetadata;
}

export interface IssuerInput {
  id: string;
  name?: string;
  keyDiscovery?: string;
}

export interface SignEnvelopeOptions extends SubjectInput {
  issuer: IssuerInput;
  /** Fixed envelope id (else a random `env_<uuid>`). */
  id?: string;
  /** Signature-creation timestamp (else now). */
  created?: string;
  /** Request an RFC 3161 timestamp from these TSAs. */
  tsa?: TsaOptions;
}

/** Build the canonical `subject` per spec §3/§4.3 — shared with the test helpers. */
export function buildSubject(input: SubjectInput, created: string): EvidenceSigningEnvelope['subject'] {
  const m = input.metadata;
  return {
    type: input.type ?? 'compliance-evidence',
    contentHash: { algorithm: 'SHA-256', value: crypto.createHash('sha256').update(input.content).digest('hex') },
    ...(input.files?.length ? { files: input.files } : {}),
    metadata: {
      title: m.title,
      collectedAt: m.collectedAt || created,
      ...(m.collector && { collector: m.collector }),
      ...(m.framework && { framework: m.framework }),
      ...(m.controlRef && { controlRef: m.controlRef }),
      ...(m.description && { description: m.description }),
    },
  };
}

/** Assemble a full envelope from a signed subject — shared with the test helpers. */
export function assembleEnvelope(
  subject: EvidenceSigningEnvelope['subject'],
  signatureValue: string,
  signer: Pick<Signer, 'algorithm' | 'fingerprint'>,
  meta: { id: string; issuer: IssuerInput; created: string; timestamp?: EnvelopeTimestamp }
): EvidenceSigningEnvelope {
  return {
    '@context': 'https://openevidence.org/signing/v1',
    version: '1.0',
    id: meta.id,
    issuer: {
      id: meta.issuer.id,
      name: meta.issuer.name ?? meta.issuer.id,
      keyDiscovery: meta.issuer.keyDiscovery ?? `${meta.issuer.id}/.well-known/oes-signing`,
    },
    subject,
    proof: {
      type: signer.algorithm === 'ECDSA-SHA256' ? 'EcdsaSignature2024' : 'RsaSignature2024',
      created: meta.created,
      algorithm: signer.algorithm,
      publicKeyFingerprint: signer.fingerprint,
      signatureValue,
      canonicalization: 'sorted-keys-2space',
      signedFields: 'subject',
      ...(meta.timestamp ? { timestamp: meta.timestamp } : {}),
    },
  };
}

/** Sign an OES Evidence Signing Envelope (spec §4). */
export async function signEnvelope(signer: Signer, opts: SignEnvelopeOptions): Promise<EvidenceSigningEnvelope> {
  const created = opts.created ?? new Date().toISOString();
  const subject = buildSubject(opts, created);
  const signatureValue = await signer.sign(canonicalize(subject));
  const timestamp = opts.tsa ? (await requestTimestamp(signatureValue, opts.tsa)) ?? undefined : undefined;
  const id = opts.id ?? `env_${crypto.randomUUID()}`;
  return assembleEnvelope(subject, signatureValue, signer, { id, issuer: opts.issuer, created, timestamp });
}

/**
 * Fill a v4.0 manifest's `files.manifest` self-entry in place (a hash can't
 * cover itself, so size_bytes is over the placeholder serialization and sha256
 * over the size-filled, sha-empty one). Shared by sign + the test helper.
 */
export function fillManifestSelfEntry(rest: Record<string, unknown>): void {
  const files = rest.files as { manifest?: { size_bytes?: number; sha256?: string } } | undefined;
  if (files?.manifest) {
    files.manifest.size_bytes = canonicalize(rest).length;
    files.manifest.sha256 = crypto.createHash('sha256').update(canonicalize(rest)).digest('hex');
  }
}

/** Sign a v4.0 evidence-pack manifest, returning it with `cryptographic_signature`. */
export async function signManifest(
  signer: Signer,
  manifest: Record<string, unknown>,
  tsa?: TsaOptions
): Promise<Record<string, unknown>> {
  const { cryptographic_signature: _drop, ...rest } = manifest;
  fillManifestSelfEntry(rest);
  const signature = await signer.sign(canonicalize(rest));
  const timestamp = tsa ? await requestTimestamp(signature, tsa) : null;
  return {
    ...rest,
    cryptographic_signature: {
      signature,
      signedAt: new Date().toISOString(),
      publicKeyFingerprint: signer.fingerprint,
      algorithm: signer.algorithm,
      canonicalization: 'sorted-keys-2space',
      signed_fields: '*except:cryptographic_signature',
      ...(timestamp
        ? { tsaTimestamp: { token: timestamp.token, timestampedAt: timestamp.timestampedAt, tsaUrl: timestamp.authority, serialNumber: timestamp.serialNumber } }
        : {}),
    },
  };
}
