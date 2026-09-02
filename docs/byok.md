# BYOK & key discovery

The point of OES is that **your private key never has to leave your control** and
**verifiers never have to trust you** — they fetch your public key and check the
math themselves. This guide covers signing with a key held in a KMS/HSM
(Bring-Your-Own-Key) and publishing keys so others can verify.

## The `Signer` interface

Signing goes through one small interface:

```ts
interface Signer {
  readonly algorithm: 'RSA-SHA256' | 'ECDSA-SHA256';
  readonly fingerprint: string;        // spec §4.5: first 16 hex of SHA-256(public PEM, LF endings)
  sign(bytes: Buffer): Promise<string> | string;  // base64 signature over `bytes`
}
```

The library only ever hands `sign()` the bytes to sign and reads `algorithm` +
`fingerprint`. It never sees, asks for, or stores a private key. That's what
makes BYOK safe: implement `sign()` over your KMS and the key stays in the KMS.

## Example: AWS KMS

```ts
import crypto from 'node:crypto';
import { KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { computeFingerprint, signEnvelope, type Signer } from 'open-evidence-signing';

const kms = new KMSClient({});
const KEY_ID = 'arn:aws:kms:us-east-1:…:key/…';

// You publish this PEM in your discovery doc; KMS keeps the private half.
const publicKeyPem = await loadPublicKeyPemFromKms(KEY_ID); // SPKI PEM, LF endings

const kmsSigner: Signer = {
  algorithm: 'RSA-SHA256',
  fingerprint: computeFingerprint(publicKeyPem),
  async sign(bytes) {
    // Hash locally and sign the DIGEST — OES signs over the canonical bytes,
    // and DIGEST mode avoids KMS's 4 KB RAW-message limit for large subjects.
    const digest = crypto.createHash('sha256').update(bytes).digest();
    const out = await kms.send(new SignCommand({
      KeyId: KEY_ID,
      Message: digest,
      MessageType: 'DIGEST',
      SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
    }));
    return Buffer.from(out.Signature!).toString('base64');
  },
};

const envelope = await signEnvelope(kmsSigner, {
  content: evidence,
  metadata: { title: 'Access review' },
  issuer: { id: 'https://compliance.acme.example' },
  tsa: { urls: ['http://timestamp.digicert.com'] },
});
```

For **ECDSA P-256**, set `algorithm: 'ECDSA-SHA256'` and KMS
`SigningAlgorithm: 'ECDSA_SHA_256'`. KMS returns a DER-encoded ECDSA signature,
which is exactly what the OES verifier expects — no re-encoding needed.

> The same pattern works for GCP Cloud KMS, Azure Key Vault, or a PKCS#11 HSM:
> compute the fingerprint from the public key once, and forward `sign()` to the
> provider.

## Publishing your keys (the discovery document)

Verifiers resolve a signature's `publicKeyFingerprint` to a public key by
fetching a **discovery document** at your well-known endpoint:

```
GET https://compliance.acme.example/.well-known/oes-signing
```

```json
{
  "issuer": "https://compliance.acme.example",
  "specVersion": "1.0",
  "keys": [
    {
      "fingerprint": "a1b2c3d4e5f6a7b8",
      "algorithm": "RSA-SHA256",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----",
      "validFrom": "2026-01-01T00:00:00Z",
      "validTo": null,
      "revoked": false
    }
  ],
  "supportedAlgorithms": ["RSA-SHA256", "ECDSA-SHA256"]
}
```

Rules (spec §5):

- Serve it over **HTTPS** in production. The `fingerprint` must match what
  `computeFingerprint(publicKeyPem)` produces (the library uses LF line
  endings — normalize CRLF before publishing).
- Set a `Cache-Control` header; verifiers cache for 1–24h.
- The envelope's `issuer.keyDiscovery` must point at this URL (it defaults to
  `${issuer.id}/.well-known/oes-signing`).

You can generate the entry programmatically:

```ts
import { computeFingerprint } from 'open-evidence-signing';
const entry = {
  fingerprint: computeFingerprint(publicKeyPem),
  algorithm: 'RSA-SHA256',
  publicKeyPem,
  validFrom: new Date().toISOString(),
  validTo: null,
  revoked: false,
};
```

## Key rotation

When you rotate keys (spec §5.4):

1. Add the new key to `keys[]` and start signing with it.
2. **Keep the old key** in `keys[]` so evidence signed with it stays verifiable.
   Set its `validTo` to the rotation time.
3. Don't delete decommissioned keys while any evidence signed by them is still
   within your retention window.

An expired key (`validTo` in the past) does **not** invalidate old signatures if
a TSA timestamp proves the signature was created while the key was valid — which
is exactly why timestamping at signing time matters.

## Revocation

To invalidate a compromised key, set `"revoked": true` on its entry. Verifiers
will fail any signature made with it immediately. Revocation is strictly
stronger than expiry: a revoked key fails even with a valid timestamp.

## Offline distribution

Auditors often work air-gapped. Ship the discovery document alongside the
evidence (the spec recommends `issuer-discovery.json` next to the envelopes),
and they verify with `--keys issuer-discovery.json --offline` — no network path
back to you at all.
