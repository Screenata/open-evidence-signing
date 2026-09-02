# API reference

All exports are available from the package root:

```ts
import { verifyEnvelope, signEnvelope, resolverFromDiscovery /* … */ } from 'open-evidence-signing';
```

Everything is async-or-sync as noted; nothing throws on a *failed verification*
(you get `valid: false`) — exceptions are reserved for programmer/IO errors.

## Verify

### `verifyEnvelope(envelope, evidenceBytes?, resolveKey, now?) → Promise<VerificationResult>`
Verify an OES envelope per spec §7.
- `envelope`: JSON string or parsed object.
- `evidenceBytes?`: `Buffer` of the raw evidence. Omit to skip the content-hash
  check (`contentHashVerified: false`). If the envelope has `subject.files[]`
  and you pass the bundle ZIP, each file's hash is checked.
- `resolveKey`: a `KeyResolver`.
- `now?`: current time in ms (injectable for deterministic tests).

### `verifyManifest(manifest, resolveKey, now?) → Promise<VerificationResult & { manifest? }>`
Verify a v4.0 manifest's `cryptographic_signature`. Returns the parsed manifest
alongside the result.

### `verifyZipPack(zipBytes, resolveKey, now?) → Promise<VerificationResult>`
Verify a v4.0 evidence-pack ZIP: locate `manifest.json`, verify its signature,
then verify every listed file's hash and per-file signature.

### `verifyEnvelopeBundleFiles(envelope, zipBytes) → VerificationCheck[]`
Per-file hash checks for an envelope's `subject.files[]` against bundle bytes.
(Called internally by `verifyEnvelope`; exported for advanced use.)

### `verifyTimestamp(tokenB64, signatureValueB64, now?) → VerificationCheck & { timestampedAt }`
Verify an RFC 3161 timestamp binding: `messageImprint == SHA-256(signature)` and
`genTime` not in the future. Does not validate the TSA certificate chain.

## Sign

### `signEnvelope(signer, options) → Promise<EvidenceSigningEnvelope>`
Produce a signed envelope. `options`:
| Field | Type | Notes |
|---|---|---|
| `content` | `Buffer` | Raw evidence bytes (hashed for `subject.contentHash`). |
| `type?` | `string` | Registered type (spec §3.3). Default `compliance-evidence`. |
| `files?` | `EnvelopeFile[]` | Per-file entries for bundles. |
| `metadata` | `EnvelopeMetadata` | `{ title, collectedAt?, collector?, framework?, controlRef?, description? }`. |
| `issuer` | `{ id, name?, keyDiscovery? }` | `keyDiscovery` defaults to `${id}/.well-known/oes-signing`. |
| `id?` | `string` | Envelope id (default random `env_<uuid>`). |
| `created?` | `string` | Signature-creation time (default now). |
| `tsa?` | `TsaOptions` | `{ urls: string[]; timeoutMs? }` to request an RFC 3161 timestamp. |

### `signManifest(signer, manifest, tsa?) → Promise<manifest>`
Attach `cryptographic_signature` to a v4.0 manifest (fills the `files.manifest`
self-entry for you).

### `localSigner(privateKeyPem, algorithm?) → Signer`
A `Signer` backed by an in-process PEM. Derives the public key + fingerprint.
For KMS/HSM keys implement `Signer` yourself — see [BYOK](./byok.md).

### `requestTimestamp(signatureValueB64, options) → Promise<EnvelopeTimestamp | null>`
Request an RFC 3161 timestamp over a signature. `options`: `{ urls, timeoutMs? }`.
Tries URLs in order; returns null if all fail.

### `buildTimeStampReq(signatureBytes) → Buffer`
Build the DER `TimeStampReq` (advanced/testing).

## Keys & discovery

### `resolverFromDiscovery(doc) → KeyResolver`
Resolve keys from a loaded discovery document (offline).

### `resolverFromPems(pems) → KeyResolver`
Resolve keys from raw PEM strings, indexed by fingerprint.

### `resolverFromNetwork(options?) → KeyResolver`
Fetch `issuer.keyDiscovery` over HTTPS and cache per-resolver.
`options`: `{ allowHttp? }` (default refuses non-HTTPS).

### `computeFingerprint(pem) → string`
Spec §4.5 fingerprint (first 16 hex of SHA-256 of the LF-normalized PEM).

## Low-level helpers

| Export | Purpose |
|---|---|
| `canonicalize(value) → Buffer` | `sorted-keys-2space` canonical UTF-8 bytes (spec §4.2). |
| `sortKeys(value)` | Recursively key-sorted clone. |
| `readZip(buffer) → Map<string, Buffer>` | Read a ZIP (STORE/DEFLATE; capped against zip bombs). |
| `extractTstInfo(tokenBytes)` | Pull `messageImprint`/`genTime`/`serial` from a TimeStampToken. |

## Test-key helpers (not for real evidence)

`generateTestKeyPair`, `createTestEnvelope`, `signTestManifest`, `signBytes` —
throwaway-key helpers for fixtures and self-checking a verifier. Use a real
`Signer` for production. See [Conformance](./conformance.md).

## Types

`EvidenceSigningEnvelope`, `EnvelopeSubject`, `EnvelopeFile`, `EnvelopeProof`,
`EnvelopeTimestamp`, `DiscoveryDocument`, `DiscoveryKey`, `ResolvedKey`,
`KeyResolver`, `Signer`, `SigningAlgorithm`, `VerificationResult`,
`VerificationCheck`, and the constant `OES_CONTEXT`.
