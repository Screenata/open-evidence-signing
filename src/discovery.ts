/**
 * Key discovery (spec §5) — turn a discovery document or a live HTTPS fetch
 * into a {@link KeyResolver} the verifier can call.
 */
import crypto from 'node:crypto';
import type {
  DiscoveryDocument,
  DiscoveryKey,
  EvidenceSigningEnvelope,
  KeyResolver,
  ResolvedKey,
} from './types';

/**
 * Fingerprint of a PEM public key — spec §4.5 (first 16 hex of SHA-256).
 * The spec defines the input as the PEM with LF line endings, so normalize
 * CRLF→LF first; a key loaded from a CRLF file otherwise mis-fingerprints.
 */
export function computeFingerprint(pem: string): string {
  return crypto.createHash('sha256').update(pem.replace(/\r\n/g, '\n')).digest('hex').slice(0, 16);
}

function keyToResolved(k: DiscoveryKey): ResolvedKey {
  return { pem: k.publicKeyPem, fingerprint: k.fingerprint, validTo: k.validTo, revoked: k.revoked };
}

/** Build a resolver from an already-loaded discovery document (offline). */
export function resolverFromDiscovery(doc: DiscoveryDocument): KeyResolver {
  return (fingerprint: string) => {
    const match = doc.keys?.find((k) => k.fingerprint === fingerprint);
    return match ? keyToResolved(match) : null;
  };
}

/** Build a resolver from one or more raw PEM strings (keys matched by fingerprint). */
export function resolverFromPems(pems: string[]): KeyResolver {
  const byFp = new Map<string, ResolvedKey>();
  for (const pem of pems) {
    const fp = computeFingerprint(pem);
    byFp.set(fp, { pem, fingerprint: fp });
  }
  return (fingerprint: string) => byFp.get(fingerprint) ?? null;
}

/**
 * Build a resolver that fetches `envelope.issuer.keyDiscovery` over HTTPS and
 * caches the document per-issuer for the lifetime of the resolver. Requires a
 * global `fetch` (Node 18+ / Bun). Use {@link resolverFromDiscovery} for the
 * `--offline` path.
 */
export function resolverFromNetwork(opts: { allowHttp?: boolean } = {}): KeyResolver {
  const cache = new Map<string, DiscoveryDocument>();
  return async (fingerprint: string, envelope?: EvidenceSigningEnvelope) => {
    const url = envelope?.issuer?.keyDiscovery;
    if (!url) return null;
    if (!opts.allowHttp && !url.startsWith('https://')) {
      throw new Error(`Refusing to fetch discovery over non-HTTPS URL: ${url} (pass allowHttp for dev)`);
    }
    let doc = cache.get(url);
    if (!doc) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Discovery fetch failed: ${res.status} ${res.statusText}`);
      doc = (await res.json()) as DiscoveryDocument;
      cache.set(url, doc);
    }
    const match = doc.keys?.find((k) => k.fingerprint === fingerprint);
    return match ? keyToResolved(match) : null;
  };
}
