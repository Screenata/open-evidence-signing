# Verifying

A verifier confirms that a piece of evidence is intact and provably came from a
known signer. OES verification answers four questions, in order:

1. **Integrity** — does the evidence still hash to what was signed?
2. **Authenticity** — was the signature produced by the claimed key?
3. **Time** — (if a timestamp is present) did an independent authority attest
   when the signature existed?
4. **Key standing** — is the signing key known, unrevoked, and unexpired?

If any REQUIRED check fails, the result is `valid: false`.

## The three things you can verify

| Input | Function | Notes |
|---|---|---|
| An OES envelope (`*.oes.json`) | `verifyEnvelope` | The primary artifact. Optionally pass the evidence bytes for a content-hash check. |
| A v4.0 evidence-pack manifest (`manifest.json`) | `verifyManifest` | Verifies the manifest's `cryptographic_signature`. |
| A v4.0 evidence-pack ZIP (`pack.zip`) | `verifyZipPack` | Reads `manifest.json` from the ZIP, then verifies every file's hash + per-file signature. |

## Resolving the signer's public key

Every verify function takes a **key resolver** — the thing that turns a
`publicKeyFingerprint` into a public key. You choose where keys come from:

```ts
import { resolverFromDiscovery, resolverFromPems, resolverFromNetwork } from 'open-evidence-signing';

// 1. From a cached discovery document (fully offline — recommended for audits)
const r1 = resolverFromDiscovery(JSON.parse(readFileSync('issuer-discovery.json', 'utf-8')));

// 2. From one or more raw PEM public keys
const r2 = resolverFromPems([readFileSync('issuer.pub.pem', 'utf-8')]);

// 3. By fetching the issuer's discovery URL over HTTPS (caches per-resolver)
const r3 = resolverFromNetwork();          // refuses non-HTTPS by default
const r3dev = resolverFromNetwork({ allowHttp: true }); // local dev only
```

A resolver is just a function — you can write your own (e.g. backed by a
database or a key-management service):

```ts
import type { KeyResolver } from 'open-evidence-signing';

const myResolver: KeyResolver = (fingerprint) => {
  const row = db.signingKeys.find(fingerprint);
  return row ? { pem: row.publicKeyPem, fingerprint, revoked: row.revoked, validTo: row.validTo } : null;
};
```

The verifier enforces key standing from what the resolver returns: a `revoked`
key fails; an expired key (`validTo` in the past) warns unless a timestamp
proves the signature predates expiry (spec §7.3.5).

## Verifying an envelope

```ts
import { verifyEnvelope, resolverFromDiscovery } from 'open-evidence-signing';

const result = await verifyEnvelope(envelopeJsonOrObject, evidenceBytes, resolver);
```

- `evidenceBytes` is **optional**. Omit it to verify the signature alone; the
  result then reports `contentHashVerified: false` (spec §7.2).
- If the envelope is a bundle (`subject.files[]` present) and you pass the
  bundle ZIP as `evidenceBytes`, each file's individual hash is checked too.

```ts
const result = await verifyEnvelope(envelope, undefined, resolver); // signature-only
// result.contentHashVerified === false, result.valid can still be true
```

## Verifying a v4.0 pack

```ts
import { verifyZipPack, resolverFromDiscovery } from 'open-evidence-signing';
import { readFileSync } from 'node:fs';

const result = await verifyZipPack(readFileSync('pack.zip'), resolver);
console.log(`${result.details.filesVerified}/${result.details.filesTotal} files verified`);
```

`verifyZipPack` finds `manifest.json` (at the ZIP root or under a single top
folder), verifies its signature over the canonical manifest bytes, then for
each listed file checks the SHA-256 and any per-file signature.

## The result shape

Every verify function returns the same normalized object:

```ts
interface VerificationResult {
  valid: boolean;               // overall verdict (all REQUIRED checks passed)
  contentHashVerified: boolean; // false when evidence bytes weren't supplied
  checks: { name: string; passed: boolean; details?: string }[];
  errors: string[];             // why it failed
  warnings: string[];           // e.g. no timestamp, expired key
  details: {
    issuer?: string;
    signedAt?: string;          // proof.created
    timestampedAt?: string | null;
    keyFingerprint?: string;
    algorithm?: string;
    manifestVersion?: string;
    filesVerified?: number;
    filesTotal?: number;
  };
}
```

Read `valid` for the gate, `checks` for a human-readable breakdown, and
`errors`/`warnings` for the reasons.

## What a verifier does *not* do

- It does **not** validate the TSA's certificate chain against a trusted root
  store. The timestamp still proves the imprint was certified at `genTime`
  (`messageImprint == SHA-256(signature)`), but trust in the TSA itself is the
  caller's policy. (Spec §6.3 step 7 marks chain validation optional.)
- It does **not** decide whether the *issuer* is trustworthy — only that the
  evidence was signed by the key the issuer published. Trust anchoring (which
  issuers you accept) is your policy.

## Offline verification

After you have the issuer's discovery document, verification needs no network:

```bash
# Save the discovery doc once
curl -s https://issuer.example/.well-known/oes-signing > issuer-discovery.json

# Then verify anything offline, forever
npx oes evidence.oes.json --content evidence.zip \
  --keys issuer-discovery.json --offline
```

See the [CLI reference](./cli.md) for exit codes and flags.
