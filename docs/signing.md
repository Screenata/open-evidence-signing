# Signing

Signing produces an **Evidence Signing Envelope** (ESE) — a small JSON document
that binds a hash of your evidence to a cryptographic signature (and optionally
a trusted timestamp). Anyone can later verify it against your published key,
with no account or API access to you.

The signing API is built around a **`Signer`** — a tiny interface so the private
key can live wherever you want (in a PEM, or in a KMS/HSM that this library never
sees). See [BYOK & key discovery](./byok.md) for the KMS path; this guide uses
the simple in-process key.

## Sign an envelope

```ts
import { signEnvelope, localSigner } from 'open-evidence-signing';
import { readFileSync, writeFileSync } from 'node:fs';

const signer = localSigner(readFileSync('signing-key.private.pem', 'utf-8'));

const envelope = await signEnvelope(signer, {
  content: readFileSync('evidence.zip'),       // raw evidence bytes (hashed for you)
  type: 'compliance-evidence:bundle',          // a registered type (spec §3.3)
  metadata: {
    title: 'Q1 2026 Access Review',
    framework: 'SOC 2',
    controlRef: 'CC6.1',
    collector: 'acme-grc/2.1.0',
  },
  issuer: {
    id: 'https://compliance.acme.example',     // your origin
    name: 'Acme Corp',
    // keyDiscovery defaults to `${issuer.id}/.well-known/oes-signing`
  },
});

writeFileSync('evidence.oes.json', JSON.stringify(envelope, null, 2));
```

What you get back is a complete, spec-conformant envelope:

```jsonc
{
  "@context": "https://openevidence.org/signing/v1",
  "version": "1.0",
  "id": "env_…",
  "issuer": { "id": "https://compliance.acme.example", "name": "Acme Corp",
              "keyDiscovery": "https://compliance.acme.example/.well-known/oes-signing" },
  "subject": {
    "type": "compliance-evidence:bundle",
    "contentHash": { "algorithm": "SHA-256", "value": "…" },
    "metadata": { "title": "Q1 2026 Access Review", "collectedAt": "…", "framework": "SOC 2", "controlRef": "CC6.1" }
  },
  "proof": {
    "type": "RsaSignature2024", "created": "…", "algorithm": "RSA-SHA256",
    "publicKeyFingerprint": "…", "signatureValue": "…",
    "canonicalization": "sorted-keys-2space", "signedFields": "subject"
  }
}
```

## Multi-file bundles

To record per-file hashes (so a single artifact can be checked without the
whole bundle), pass `files[]`. The envelope's top-level `contentHash` still
covers the entire ZIP; `subject.files[]` carries each file's hash:

```ts
import crypto from 'node:crypto';
const sha = (b: Buffer) => crypto.createHash('sha256').update(b).digest('hex');

const envelope = await signEnvelope(signer, {
  content: zipBytes,
  type: 'compliance-evidence:bundle',
  files: [
    { filename: 'screenshots/01.png', contentHash: { algorithm: 'SHA-256', value: sha(png) }, size: png.length, mediaType: 'image/png' },
    { filename: 'attachments/iam.json', contentHash: { algorithm: 'SHA-256', value: sha(cfg) }, size: cfg.length, mediaType: 'application/json' },
  ],
  metadata: { title: 'MFA evidence' },
  issuer: { id: 'https://compliance.acme.example' },
});
```

A verifier given the ZIP will check both the whole-bundle hash and each file.

## Trusted timestamps (RFC 3161)

Pass `tsa` to anchor the signature in time via an independent Time Stamping
Authority. The library requests a token over the **signature** and embeds it in
`proof.timestamp`:

```ts
const envelope = await signEnvelope(signer, {
  content: evidence,
  metadata: { title: 'Timestamped evidence' },
  issuer: { id: 'https://compliance.acme.example' },
  tsa: { urls: ['http://timestamp.digicert.com', 'http://timestamp.sectigo.com'], timeoutMs: 10000 },
});
```

- URLs are tried in order; the first success wins (fallback).
- If **all** TSAs fail, signing still succeeds — the envelope just has no
  `proof.timestamp`. Check `envelope.proof.timestamp` if a timestamp is required
  by your policy.
- RFC 3161 timestamps from recognized authorities (DigiCert, Sectigo, …) carry
  legal weight under eIDAS and are what Big-4 auditors recognize.

You can also request a timestamp on its own:

```ts
import { requestTimestamp } from 'open-evidence-signing';
const ts = await requestTimestamp(envelope.proof.signatureValue, { urls: ['http://freetsa.org/tsr'] });
```

## Signing a v4.0 evidence-pack manifest

If you produce evidence-pack ZIPs with an internal `manifest.json`, sign the
manifest with `signManifest`:

```ts
import { signManifest, localSigner } from 'open-evidence-signing';

const manifest = await signManifest(signer, {
  version: '4.0',
  title: 'Access Review Pack',
  files: {
    manifest: { filename: 'manifest.json', sha256: '', size_bytes: 0 }, // self-entry placeholder; filled for you
    screenshots: [{ filename: 'screenshots/01.png', sha256: '…', size_bytes: 145230, signature: '…' }],
  },
});
// manifest.cryptographic_signature is now populated; write it into the ZIP.
```

## Algorithms & keys

| `algorithm` | Key type | Notes |
|---|---|---|
| `RSA-SHA256` (default) | RSA 2048-bit min, 4096 recommended | Deterministic signatures. |
| `ECDSA-SHA256` | EC P-256 (`prime256v1`) | Smaller signatures; non-deterministic. |

```ts
const signer = localSigner(privateKeyPem, 'ECDSA-SHA256');
```

`localSigner` derives the public key + fingerprint from the private key, so the
envelope's `publicKeyFingerprint` is computed for you. To make your evidence
verifiable by others, publish that public key in a discovery document — see
[BYOK & key discovery](./byok.md).

## Generating a key (quick start)

```bash
# RSA
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing-key.private.pem
openssl pkey -in signing-key.private.pem -pubout -out signing-key.public.pem

# EC P-256
openssl ecparam -name prime256v1 -genkey -noout -out ec.private.pem
openssl ec -in ec.private.pem -pubout -out ec.public.pem
```

> For anything beyond local experiments, keep the private key in a KMS/HSM and
> implement a `Signer` over it instead of loading a PEM — see
> [BYOK & key discovery](./byok.md).
