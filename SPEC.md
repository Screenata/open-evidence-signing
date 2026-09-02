<!--
  Published copy of the Open Evidence Signing (OES) v1.0 specification.
-->

# Open Evidence Signing Specification (OES) v1.0

**Status:** Stable — v1.0, implemented
**Date:** 2026-04-27
**Last reviewed:** 2026-05-21
**License:** Apache-2.0
**Reference implementation:** [Screenata](https://screenata.com)

> **Reference implementation:** This is the ratified v1.0 protocol that the reference implementation follows. The OES sign/verify logic lives in the open-source `open-evidence-signing` package (npm, Apache-2.0): canonicalization, envelope signing/verification, v4.0 manifest signing/verification, RFC 3161 request + verify, and key discovery resolution. Production GRC platforms consume that package and layer their own key management (including KMS/HSM BYOK), timestamping, and audit logging around the shared primitives. The protocol shape described in this document matches the implementation, and the published test vectors are generated from it.

---

## Abstract

The Open Evidence Signing Specification (OES) defines a format and protocol for cryptographically signing compliance evidence so that any third party — auditors, GRC platforms, regulators, or automated tools — can independently verify the integrity, provenance, and temporal ordering of evidence artifacts without requiring access to the originating system.

OES is designed for the compliance and audit industry, where evidence must be tamper-evident, attributable to a specific collector, and anchored in time. It achieves this through a combination of standard cryptographic signatures, [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamps from independent Time Stamping Authorities, and a well-known key discovery protocol.

---

## 1. Design Goals

1. **Independently verifiable.** Any party with the public specification can verify evidence without an account, API key, or relationship with the issuer.
2. **Legally grounded.** RFC 3161 timestamps from recognized TSAs (DigiCert, Sectigo, etc.) carry legal weight under eIDAS and similar frameworks.
3. **Simple to implement.** A verifier can be written in under 200 lines in any language with a standard crypto library.
4. **Format-agnostic evidence.** The spec signs arbitrary content — screenshots, PDFs, JSON exports, CSV reports, ZIP bundles. The content type is metadata, not a constraint.
5. **Interoperable.** Optional mapping to W3C Verifiable Credentials for ecosystems that speak that format.

---

## 2. Terminology

| Term | Definition |
|---|---|
| **Issuer** | The system that collects evidence and produces signed envelopes (e.g., a GRC platform). |
| **Evidence** | Any digital artifact that demonstrates a compliance claim — a screenshot, configuration export, log file, signed attestation, etc. |
| **Envelope** | An OES Evidence Signing Envelope (ESE): the JSON document containing the content hash, signature, and metadata. |
| **Verifier** | Any party or tool that checks an envelope's cryptographic validity. |
| **TSA** | Time Stamping Authority — an independent third party that issues [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamps. |
| **Fingerprint** | The first 16 hexadecimal characters of the SHA-256 hash of a public key's PEM encoding. Used for key identification without transmitting the full key. |

---

## 3. Evidence Signing Envelope (ESE)

The ESE is the core artifact of the specification. It is a JSON document that binds a content hash to a cryptographic proof.

### 3.1 Schema

```json
{
  "@context": "https://openevidence.org/signing/v1",
  "version": "1.0",
  "id": "<unique envelope identifier>",

  "issuer": {
    "id": "<issuer origin URL>",
    "name": "<human-readable issuer name>",
    "keyDiscovery": "<URL to /.well-known/oes-signing>"
  },

  "subject": {
    "type": "<evidence type>",
    "contentHash": {
      "algorithm": "SHA-256",
      "value": "<hex-encoded hash of evidence content>"
    },
    "files": [
      {
        "filename": "<relative path within bundle>",
        "contentHash": {
          "algorithm": "SHA-256",
          "value": "<hex>"
        },
        "size": <bytes>,
        "mediaType": "<MIME type>"
      }
    ],
    "metadata": {
      "title": "<human-readable title>",
      "collectedAt": "<ISO 8601 timestamp>",
      "collector": "<tool or agent identifier>",
      "framework": "<compliance framework, e.g. SOC 2, HIPAA>",
      "controlRef": "<control reference, e.g. CC6.1>",
      "description": "<free-text description>"
    }
  },

  "proof": {
    "type": "<signature type identifier>",
    "created": "<ISO 8601 timestamp of signature creation>",
    "algorithm": "<signing algorithm>",
    "publicKeyFingerprint": "<16 hex chars>",
    "signatureValue": "<base64-encoded signature>",
    "canonicalization": "sorted-keys-2space",
    "signedFields": "subject",
    "timestamp": {
      "type": "RFC3161",
      "token": "<base64-encoded DER TimeStampToken>",
      "authority": "<TSA URL>",
      "timestampedAt": "<ISO 8601>",
      "serialNumber": "<TSA-assigned serial>"
    }
  }
}
```

### 3.2 Field Requirements

| Field | Required | Notes |
|---|---|---|
| `@context` | MUST | Always `"https://openevidence.org/signing/v1"` |
| `version` | MUST | `"1.0"` for this specification |
| `id` | SHOULD | Unique identifier (UUID, CUID, or URI). Enables deduplication. |
| `issuer.id` | MUST | Origin URL of the signing system |
| `issuer.name` | SHOULD | Human-readable name |
| `issuer.keyDiscovery` | MUST | URL where the verifier can fetch public keys (Section 5) |
| `subject.type` | MUST | One of the registered types (Section 3.3) or a custom URI |
| `subject.contentHash.algorithm` | MUST | `"SHA-256"` (only supported algorithm in v1.0) |
| `subject.contentHash.value` | MUST | Hex-encoded hash of the raw evidence bytes |
| `subject.files` | MAY | Present when the evidence is a multi-file bundle (e.g., ZIP) |
| `subject.metadata` | SHOULD | Descriptive metadata; all subfields are optional |
| `proof.type` | MUST | Signature type identifier (Section 4.1) |
| `proof.created` | MUST | ISO 8601 timestamp of when the signature was created |
| `proof.algorithm` | MUST | One of the supported algorithms (Section 4.1) |
| `proof.publicKeyFingerprint` | MUST | First 16 hex chars of SHA-256 of the PEM-encoded public key |
| `proof.signatureValue` | MUST | Base64-encoded signature over the canonical subject |
| `proof.canonicalization` | MUST | `"sorted-keys-2space"` in v1.0 |
| `proof.signedFields` | MUST | `"subject"` — declares what was signed |
| `proof.timestamp` | SHOULD | Present when a TSA timestamp was obtained |

### 3.3 Registered Evidence Types

| Type | Description |
|---|---|
| `compliance-evidence` | General compliance evidence (screenshots, exports, reports) |
| `compliance-evidence:screenshot` | A screenshot or series of screenshots |
| `compliance-evidence:configuration` | A configuration export (JSON, YAML, XML) |
| `compliance-evidence:log` | System or audit log extract |
| `compliance-evidence:attestation` | A human attestation or signed declaration |
| `compliance-evidence:scan-result` | Output from a security or compliance scanner |
| `compliance-evidence:policy` | A compliance policy document |
| `compliance-evidence:bundle` | A ZIP or archive containing multiple evidence artifacts |

Custom types SHOULD use a URI namespace (e.g., `https://example.com/evidence/custom-type`).

---

## 4. Signature Computation

### 4.1 Supported Algorithms

| Algorithm ID | Description | Key Type |
|---|---|---|
| `RSA-SHA256` | RSASSA-PKCS1-v1_5 with SHA-256 | RSA (2048-bit minimum, 4096-bit recommended) |
| `ECDSA-SHA256` | ECDSA with SHA-256 | EC P-256 (secp256r1) |

Corresponding `proof.type` values:

| `proof.algorithm` | `proof.type` |
|---|---|
| `RSA-SHA256` | `RsaSignature2024` |
| `ECDSA-SHA256` | `EcdsaSignature2024` |

### 4.2 Canonical Form

The signature is computed over a **canonical representation** of the `subject` object. Canonicalization ensures that logically equivalent JSON produces identical bytes for signing and verification.

**Canonicalization algorithm (`sorted-keys-2space`):**

1. Extract the `subject` value from the envelope.
2. Serialize to JSON with **recursively sorted keys** and **2-space indentation**.
3. Encode the resulting string as **UTF-8 bytes**.
4. This byte sequence is the **signing input**.

Reference implementation (JavaScript):

```javascript
// Recursively sort keys at every depth, then serialize with 2-space indent.
function sortKeys(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortKeys);
  return Object.fromEntries(
    Object.keys(obj).sort().map(k => [k, sortKeys(obj[k])])
  );
}

function canonicalize(subject) {
  return JSON.stringify(sortKeys(subject), null, 2);
}

// Signing input = UTF-8 bytes of canonicalize(subject)
```

**Rationale:** JSON key ordering is not guaranteed by the JSON specification. Without canonicalization, re-serializing the same logical object can produce different bytes, causing signature verification to fail. Sorted keys with 2-space indentation was chosen for human readability during debugging.

### 4.3 Signing Process

```
1. Compute contentHash:
   hash = SHA-256(raw_evidence_bytes)
   subject.contentHash.value = hex(hash)

2. If multi-file bundle, compute per-file hashes:
   for each file in bundle:
     file.contentHash.value = hex(SHA-256(file_bytes))

3. Populate subject with metadata.

4. Canonicalize:
   signingInput = utf8_encode(stableStringify(subject))

5. Sign:
   signature = SIGN(signingInput, privateKey, algorithm)
   proof.signatureValue = base64(signature)

6. (Optional) Request TSA timestamp:
   tsaDigest = SHA-256(signature_bytes)
   tsaToken  = TSA_REQUEST(tsaDigest)
   proof.timestamp.token = base64(tsaToken)
```

### 4.4 Content Hash Computation

The `subject.contentHash` is computed over the **raw bytes** of the evidence content:

- **Single file:** SHA-256 of the file bytes.
- **Multi-file bundle (ZIP):** SHA-256 of the entire ZIP file bytes. Individual file hashes appear in `subject.files[]`.
- **Structured data (JSON, CSV):** SHA-256 of the raw byte representation as stored/transmitted. No normalization — the hash covers the exact bytes the recipient will receive.

### 4.5 Fingerprint Computation

Public key fingerprints provide a compact, collision-resistant key identifier:

```
fingerprint = hex(SHA-256(pem_encoded_public_key)).substring(0, 16)
```

Where `pem_encoded_public_key` is the full PEM string including `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----` delimiters, with LF (`\n`) line endings.

---

## 5. Key Discovery Protocol

Verifiers need to obtain the issuer's public key to verify signatures. OES defines a well-known endpoint convention for this purpose.

### 5.1 Well-Known Endpoint

Issuers MUST serve a JSON document at:

```
GET {issuer.id}/.well-known/oes-signing
```

### 5.2 Discovery Document Schema

```json
{
  "issuer": "<origin URL, must match envelope issuer.id>",
  "specVersion": "1.0",
  "keys": [
    {
      "fingerprint": "<16 hex chars>",
      "algorithm": "RSA-SHA256",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "validFrom": "<ISO 8601>",
      "validTo": "<ISO 8601 or null for no expiry>",
      "revoked": false
    }
  ],
  "verificationEndpoint": "<optional URL for server-side verification>",
  "supportedAlgorithms": ["RSA-SHA256", "ECDSA-SHA256"]
}
```

### 5.3 Key Matching

When verifying a signature, the verifier:

1. Fetches `{issuer.keyDiscovery}` (HTTP GET, MUST be HTTPS in production).
2. Finds the key entry where `fingerprint` matches `proof.publicKeyFingerprint`.
3. Verifies the key is not expired (`validTo` is null or in the future).
4. Verifies the key is not revoked (`revoked` is `false`).
5. Uses `publicKeyPem` for signature verification.

### 5.4 Key Rotation

When an issuer rotates keys:

- The old key MUST remain in the `keys` array with its original `validFrom`/`validTo` dates until all evidence signed with it is outside the retention window.
- The new key is added to the `keys` array.
- Issuers SHOULD NOT remove keys; they SHOULD set `validTo` or `revoked: true` when decommissioning.

### 5.5 Caching

Verifiers SHOULD cache discovery documents for at least **1 hour** and at most **24 hours**. The discovery endpoint SHOULD return appropriate `Cache-Control` headers.

### 5.6 Customer-Managed Keys (BYOK)

When the evidence issuer signs with a customer-provided key (BYOK or cloud KMS), the discovery document includes the customer's public key alongside platform keys. The `fingerprint` in the envelope routes the verifier to the correct key entry.

Issuers MAY scope customer keys to a sub-path:

```
GET {issuer.id}/.well-known/oes-signing?org={orgIdentifier}
```

This is an optional extension; verifiers that don't support it MUST fall back to the base path.

---

## 6. RFC 3161 Timestamp Binding

### 6.1 Purpose

An [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp proves that the signature existed at a specific point in time, as attested by an independent third party (TSA). This prevents backdating and provides a legally recognized temporal anchor.

### 6.2 Timestamp Request

The issuer requests a timestamp over the **signature bytes** (not the content):

```
1. Compute messageImprint:
   digest = SHA-256(base64_decode(proof.signatureValue))

2. Construct TimeStampReq ([RFC 3161 §2.4.1](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1)):
   - version: 1
   - messageImprint: { algorithm: SHA-256, hashedMessage: digest }
   - certReq: true (request TSA certificate in response)
   - nonce: random 64-bit value

3. Send to TSA:
   POST {tsaUrl}
   Content-Type: application/timestamp-query
   Body: DER-encoded TimeStampReq

4. Receive TimeStampResp:
   - status: granted (0)
   - timeStampToken: DER-encoded ContentInfo

5. Store in envelope:
   proof.timestamp.token = base64(timeStampToken)
   proof.timestamp.authority = tsaUrl
   proof.timestamp.timestampedAt = TSTInfo.genTime
   proof.timestamp.serialNumber = TSTInfo.serialNumber
```

### 6.3 Timestamp Verification

A verifier checks the timestamp as follows:

```
1. Decode proof.timestamp.token from base64 to DER bytes.
2. Parse as CMS ContentInfo → SignedData → encapContentInfo → TSTInfo.
3. Extract TSTInfo.messageImprint.hashedMessage.
4. Compute expected: SHA-256(base64_decode(proof.signatureValue)).
5. Compare: TSTInfo.messageImprint.hashedMessage MUST equal expected.
6. Verify TSTInfo.genTime is not in the future (allow 5-minute clock skew).
7. (Optional) Verify TSA certificate chain against known TSA root certificates.
```

### 6.4 Trusted TSA Providers

The specification does not mandate a specific TSA. Recommended providers include:

| Provider | URL | Notes |
|---|---|---|
| DigiCert | `http://timestamp.digicert.com` | Widely trusted, no rate limit |
| Sectigo | `http://timestamp.sectigo.com` | Free tier available |
| FreeTSA | `https://freetsa.org/tsr` | Open, free |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` | Enterprise |

Issuers SHOULD use multiple TSAs with fallback for reliability.

---

## 7. Verification Algorithm

This section defines the normative verification procedure. A compliant verifier MUST implement all REQUIRED steps.

### 7.1 Full Verification Procedure

```
VERIFY(envelope, evidence_bytes):

  // Step 1: Parse and validate structure
  1.1  Parse envelope as JSON.
  1.2  Verify @context = "https://openevidence.org/signing/v1".
  1.3  Verify version = "1.0".
  1.4  Verify all REQUIRED fields are present (Section 3.2).

  // Step 2: Verify content integrity
  2.1  Compute SHA-256(evidence_bytes).
  2.2  Compare hex(hash) with subject.contentHash.value.
  2.3  If mismatch → FAIL("content hash mismatch").
  2.4  If subject.files is present, verify each file hash individually.

  // Step 3: Obtain public key
  3.1  Fetch issuer.keyDiscovery URL via HTTPS.
  3.2  Find key where fingerprint = proof.publicKeyFingerprint.
  3.3  If not found → FAIL("unknown signing key").
  3.4  If key.revoked = true → FAIL("signing key revoked").
  3.5  If key.validTo is set and in the past → WARN("signing key expired").
       (An expired key does not invalidate the signature if a valid
        timestamp proves the signature was created while the key was active.)

  // Step 4: Verify signature
  4.1  Canonicalize the subject:
       canonical = utf8_encode(stableStringify(envelope.subject))
  4.2  Verify proof.signatureValue (base64-decoded) against canonical
       using the public key and proof.algorithm.
  4.3  If verification fails → FAIL("invalid signature").

  // Step 5: Verify timestamp (if present)
  5.1  If proof.timestamp is absent → return PASS (no temporal claim).
  5.2  Decode proof.timestamp.token from base64.
  5.3  Parse DER-encoded TimeStampToken.
  5.4  Extract TSTInfo.messageImprint.hashedMessage.
  5.5  Compute SHA-256(base64_decode(proof.signatureValue)).
  5.6  Compare: MUST match.
  5.7  Verify TSTInfo.genTime is not more than 5 minutes in the future.
  5.8  If Step 3.5 warned about key expiry:
       verify TSTInfo.genTime < key.validTo. If true, the signature
       was created while the key was valid → clear the warning.

  // Step 6: Return result
  Return {
    valid: true,
    signedAt: proof.created,
    timestampedAt: proof.timestamp.timestampedAt (or null),
    issuer: issuer.id,
    contentHashVerified: true,
    keyFingerprint: proof.publicKeyFingerprint,
    warnings: [collected warnings]
  }
```

### 7.2 Verification Without Evidence Bytes

When the verifier has the envelope but not the original evidence (e.g., checking a signature database), Steps 2.1–2.4 are skipped and the result MUST indicate `contentHashVerified: false`.

### 7.3 Offline Verification

Once a verifier has fetched the discovery document and cached the public key, all subsequent verifications for envelopes signed by that key can proceed offline. No network access is required after initial key fetch.

---

## 8. Multi-File Bundle Signing

When evidence consists of multiple files (e.g., a ZIP archive with screenshots, PDFs, and metadata), OES supports two levels of integrity, and standardizes the internal structure of the bundle when `subject.type` is `compliance-evidence:bundle`.

### 8.1 Bundle-Level Hash

The `subject.contentHash` covers the entire bundle (e.g., the ZIP file). It is computed over the **raw bytes of the ZIP file** after the bundle is finalized (manifest written, all files inserted, ZIP closed). Re-zipping the same logical content with different compression settings produces different bytes and a different content hash — this is intentional. The bundle is identified by its exact bytes, not its logical contents.

### 8.2 Per-File Hashes

The `subject.files[]` array provides individual file hashes:

```json
{
  "subject": {
    "type": "compliance-evidence:bundle",
    "contentHash": {
      "algorithm": "SHA-256",
      "value": "abc123..."
    },
    "files": [
      {
        "filename": "screenshots/01_login_page.png",
        "contentHash": { "algorithm": "SHA-256", "value": "def456..." },
        "size": 145230,
        "mediaType": "image/png"
      },
      {
        "filename": "report.pdf",
        "contentHash": { "algorithm": "SHA-256", "value": "789abc..." },
        "size": 52100,
        "mediaType": "application/pdf"
      },
      {
        "filename": "manifest.json",
        "contentHash": { "algorithm": "SHA-256", "value": "cde012..." },
        "size": 3400,
        "mediaType": "application/json"
      }
    ]
  }
}
```

Per-file hashes allow a verifier to check individual artifacts without extracting the full bundle.

### 8.3 Bundle Layout

A `compliance-evidence:bundle` MUST follow this directory layout inside the ZIP:

```
evidence-bundle-<id>.zip
├── manifest.json              # REQUIRED. See §8.4.
├── screenshots/               # OPTIONAL directory of screenshot files
│   ├── step-001.png
│   └── step-002.png
├── attachments/               # OPTIONAL directory of structured artifacts
│   ├── iam-config.json
│   └── access-review.csv
└── comments.txt               # OPTIONAL reviewer comments file
```

Rules:

- `manifest.json` MUST be at the archive root with that exact filename.
- Filenames inside the bundle MUST use forward slashes (`/`) and MUST NOT begin with `./`, `/`, or contain `..`.
- Filenames MUST be unique within the archive.
- Every file referenced by the internal manifest MUST exist in the archive, and every archive entry (except `manifest.json` itself) MUST appear in the manifest.

File categories:

| Category | Path prefix | Manifest location | Notes |
|---|---|---|---|
| Screenshots | `screenshots/` | `files.screenshots[]` | PNG/JPEG. Carries optional `stepNumber`, `caption`. |
| Attachments | `attachments/` | `files.attachments[]` | Any MIME type. Carries `originalName`, `mediaType`. |
| Comments | _(root)_ | `files.comments_txt` | Single file named `comments.txt`. |
| Video | _(not in archive)_ | `files.video` | Optional unsigned URL reference; media stays outside the ZIP for size. |

Producers MAY introduce additional categories under prefixed path conventions (e.g., `x-logs/`), but each such category MUST be declared in `metadata.x-categories` and is not covered by core verifier behavior.

### 8.4 Internal Manifest Schema

The internal `manifest.json` is REQUIRED for `compliance-evidence:bundle`. It carries the structured metadata an auditor reads when reviewing the bundle, and its file hashes MUST mirror OES `subject.files[]` exactly.

```jsonc
{
  "specVersion": "oes-1.0-bundle-manifest",
  "bundleId":    "ep_01HXYZ...",
  "title":       "Q1 2026 Access Control Evidence",
  "generatedAt": "2026-05-12T10:00:00.000Z",

  "metadata": {
    "organization": "Acme Corp",
    "framework":    "SOC 2",
    "controlRef":   "CC6.1",
    "generatedBy":  "screenata/1.0.0",
    "x-workspace-id":          "ws_abc123",
    "x-compliance-program-id": "cp_def456"
  },

  "files": {
    "screenshots":  [ /* FileEntry[] */ ],
    "attachments":  [ /* FileEntry[] */ ],
    "comments_txt": null,
    "video":        null
  },

  "generator": {
    "name":    "screenata",
    "version": "1.0.0"
  },

  "auditTrail": {
    "createdBy":       "alice@acme.com",
    "organizationId":  "org_xyz",
    "exportTimestamp": "2026-05-12T10:00:00.000Z"
  },

  "innerSignature": { /* §8.6 — OPTIONAL */ }
}
```

Top-level fields:

| Field | Required | Description |
|---|---|---|
| `specVersion` | MUST | `"oes-1.0-bundle-manifest"` for this version. |
| `bundleId` | MUST | Producer-assigned unique identifier. Opaque to verifiers. |
| `title` | MUST | Human-readable description of the bundle scope. |
| `generatedAt` | MUST | ISO 8601 UTC timestamp the bundle was finalized. |
| `metadata` | MUST | See below. |
| `files` | MUST | See below. |
| `generator` | MUST | Tool that built the bundle (`name`, `version`). |
| `auditTrail` | MUST | Provenance fields (`createdBy`, `organizationId`, `exportTimestamp`). |
| `innerSignature` | MAY | Optional standalone signature. See §8.6. |

`metadata` fields:

| Field | Required | Description |
|---|---|---|
| `organization` | MUST | Human-readable name of the entity under audit. |
| `framework` | MUST | Compliance framework identifier. SHOULD match the envelope's `subject.metadata.framework`. |
| `controlRef` | SHOULD | Primary control reference. SHOULD match the envelope's `subject.metadata.controlRef`. |
| `generatedBy` | MUST | `<producer>/<version>` string. |
| `x-*` | MAY | Producer-specific extensions (see §8.7). |

Each `FileEntry` inside `files.screenshots[]`, `files.attachments[]`, or `files.comments_txt`:

```jsonc
{
  "filename":   "screenshots/step-001.png",
  "sha256":     "a1b2c3d4...",       // hex SHA-256 of file bytes
  "size":       145832,              // bytes
  "mediaType":  "image/png",         // MIME type

  // Category-specific, all OPTIONAL
  "stepNumber":    1,                // screenshots
  "caption":       "MFA settings page",  // screenshots
  "originalName":  "iam-config.json",    // attachments
  "signature":     "base64..."       // inner per-file signature (§8.6.2)
}
```

| Field | Required | Description |
|---|---|---|
| `filename` | MUST | Relative path inside the bundle ZIP. |
| `sha256` | MUST | Hex SHA-256 of the file bytes. MUST match the corresponding OES `subject.files[i].contentHash.value`. |
| `size` | MUST | File size in bytes. MUST match the corresponding OES `subject.files[i].size`. |
| `mediaType` | SHOULD | MIME type. MUST match OES `subject.files[i].mediaType` if both are present. |
| `stepNumber` | MAY | Ordered position in a screenshot sequence. |
| `caption` | MAY | Human-readable description of the screenshot. |
| `originalName` | MAY | Original upload filename for attachments. |
| `signature` | MAY | Inner per-file signature (§8.6.2). |

### 8.5 Envelope ↔ Internal Manifest Mapping

When a bundle is wrapped in an OES envelope, the following invariants MUST hold:

| Internal manifest | OES envelope |
|---|---|
| _SHA-256 of the bundle ZIP bytes_ | `subject.contentHash.value` |
| `files.screenshots[i]` / `files.attachments[i]` / `files.comments_txt` (`filename`, `sha256`, `size`) | `subject.files[i]` (`filename`, `contentHash.value`, `size`) |
| `title` | `subject.metadata.title` |
| `generatedAt` | `subject.metadata.collectedAt` |
| `metadata.framework` | `subject.metadata.framework` |
| `metadata.controlRef` | `subject.metadata.controlRef` |

For every file the OES envelope lists in `subject.files[]`, the internal manifest MUST list the same `filename`, `sha256`, and `size`. The reverse is also required: every file in the internal manifest MUST appear in OES `subject.files[]`.

`files.video` URL references in the internal manifest are NOT included in OES `subject.files[]` because video stays outside the bundle.

Mismatches between the internal manifest and the OES envelope are warnings, not errors. Verifiers SHOULD surface any divergence so producers can fix authoring bugs.

### 8.6 Inner Signatures (OPTIONAL)

When the bundle is distributed alongside an OES envelope, the envelope provides full cryptographic integrity over both the bundle and every file. Inner signatures inside the manifest are **redundant** in that case and MAY be omitted.

When the bundle is distributed **without** an OES envelope (offline transfer, standalone archival, legacy compatibility), inner signatures give the bundle standalone integrity.

#### 8.6.1 Inner manifest signature

```jsonc
"innerSignature": {
  "algorithm":            "RSA-SHA256",
  "publicKeyFingerprint": "a1b2c3d4e5f6a7b8",
  "signatureValue":       "base64...",
  "canonicalization":     "sorted-keys-2space",
  "signedFields":         "*except:innerSignature",
  "createdAt":            "2026-05-12T10:00:01.000Z"
}
```

The inner signature is computed over the canonical bytes of the internal manifest **with `innerSignature` removed**, using the canonicalization algorithm in §4.2 (sorted keys at every depth, 2-space indented JSON, UTF-8).

When both an OES envelope and an `innerSignature` are present, the public key MUST be the same key in both places (matching `publicKeyFingerprint`). Producers MUST NOT sign the inner manifest with a key that is not discoverable via the issuer's OES key discovery endpoint (§5).

#### 8.6.2 Inner per-file signatures

A `FileEntry` MAY carry an optional `signature` field: a base64-encoded signature of the file's SHA-256 hash under the same key referenced by `innerSignature.publicKeyFingerprint`. Inner per-file signatures provide nothing the OES envelope doesn't already provide; they exist purely so a single file can be extracted from the bundle and verified standalone without either the bundle ZIP or the OES envelope.

#### 8.6.3 Verifier behavior

A verifier MUST:

- Verify the OES envelope per §7 if present.
- If `innerSignature` is present, verify it independently as a defense-in-depth check. A mismatch between OES verification and inner signature verification SHOULD be reported as a high-severity warning (likely producer bug or tampering attempt).
- If only an `innerSignature` is present (no OES envelope), treat the bundle as standalone-signed and use §5 key discovery to resolve the public key.
- If neither signature is present, report the bundle as `UNSIGNED` and rely on hashes alone.

### 8.7 Extension Fields

Producer-specific data MUST be carried under fields prefixed with `x-` to avoid collisions with future spec versions. Examples:

- `metadata.x-workspace-id`
- `metadata.x-compliance-program-id`
- `metadata.x-control-coverage` (array of control IDs)
- `metadata.x-auditor-control-mapping` (auditor-issued control IDs)
- `metadata.x-categories` (declaration of non-standard file categories)

Verifiers MUST ignore unknown `x-*` fields. Verifiers MUST reject unknown **non-`x-*`** fields at the top level of the internal manifest (forward compatibility is opt-in).

### 8.8 Reference Internal Manifest

```jsonc
{
  "specVersion": "oes-1.0-bundle-manifest",
  "bundleId":    "ep_01HXYZ7K9F2N3P4Q5R6S7T8U9V",
  "title":       "MFA Enforcement Verification — AWS IAM",
  "generatedAt": "2026-04-20T10:30:00Z",

  "metadata": {
    "organization": "Acme Corp",
    "framework":    "SOC 2",
    "controlRef":   "CC6.1",
    "generatedBy":  "screenata/1.0.0",
    "x-workspace-id":          "ws_abc123",
    "x-compliance-program-id": "cp_def456"
  },

  "files": {
    "screenshots": [
      {
        "filename":   "screenshots/01_mfa_settings.png",
        "sha256":     "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "size":       145230,
        "mediaType":  "image/png",
        "stepNumber": 1,
        "caption":    "IAM MFA settings page"
      },
      {
        "filename":   "screenshots/02_mfa_enforced.png",
        "sha256":     "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        "size":       98400,
        "mediaType":  "image/png",
        "stepNumber": 2,
        "caption":    "MFA enforcement policy applied"
      }
    ],
    "attachments": [
      {
        "filename":     "attachments/iam-policy.json",
        "sha256":       "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "size":         3400,
        "mediaType":    "application/json",
        "originalName": "AcmeProd-MFA-policy.json"
      }
    ],
    "comments_txt": null,
    "video":        null
  },

  "generator": {
    "name":    "screenata",
    "version": "1.0.0"
  },

  "auditTrail": {
    "createdBy":       "alice@acme.com",
    "organizationId":  "org_xyz",
    "exportTimestamp": "2026-04-20T10:30:00Z"
  }
}
```

The corresponding OES envelope (per §13) would have `subject.contentHash` set to SHA-256 of the bundle ZIP bytes, and `subject.files[]` mirroring the screenshots and attachments above with identical hashes, sizes, and filenames.

---

## 9. Third-Party Reuse

### 9.1 For Auditors

An auditor receiving OES-signed evidence can verify it without any relationship with the issuing platform:

1. **Receive** the evidence file(s) and the OES envelope (JSON).
2. **Verify** using the algorithm in Section 7 — a reference verifier script is provided below.
3. **Trust anchor**: The TSA timestamp from a recognized authority (DigiCert, Sectigo) confirms when the evidence was signed. The public key from the well-known endpoint confirms who signed it.
4. **Report**: Include the verification result (valid/invalid, timestamp, issuer) in audit workpapers.

### 9.2 For GRC Platforms

GRC platforms that ingest evidence from multiple sources can use OES as a common verification format:

1. **Import** OES envelopes alongside evidence artifacts.
2. **Verify** on ingestion to confirm integrity.
3. **Display** verification status (signed, timestamped, issuer) in their UI.
4. **Re-sign** (optional): After verification, a platform may produce its own OES envelope wrapping the original, creating a chain of custody.

### 9.3 For CI/CD Pipelines

Automated compliance pipelines can produce OES-signed evidence:

1. **Collect** evidence (scanner output, config exports, test results).
2. **Sign** using a service account's key pair.
3. **Publish** the envelope alongside evidence to a compliance artifact store.
4. **Verify** in downstream audit workflows.

### 9.4 Chain of Custody

When evidence passes through multiple systems, each system MAY produce its own OES envelope referencing the previous:

```json
{
  "subject": {
    "type": "compliance-evidence:attestation",
    "contentHash": { "algorithm": "SHA-256", "value": "<hash of original evidence>" },
    "metadata": {
      "title": "Forwarded evidence from Screenata",
      "priorEnvelopes": [
        {
          "issuer": "https://app.screenata.com",
          "id": "env_abc123",
          "contentHash": "<original hash>",
          "signedAt": "2026-04-20T10:30:01Z"
        }
      ]
    }
  }
}
```

This creates an auditable chain: each envelope is independently verifiable, and the `priorEnvelopes` metadata traces provenance.

---

## 10. W3C Verifiable Credential Mapping

For ecosystems that use W3C Verifiable Credentials (e.g., the CPOE standard), an OES envelope maps as follows:

| OES Field | W3C VC Field |
|---|---|
| `@context` | Additional `@context` entry |
| `id` | `id` (as URI) |
| `issuer.id` | `issuer` (as `did:web:{domain}`) |
| `subject` | `credentialSubject` |
| `subject.contentHash` | `credentialSubject.digest` |
| `proof.type` | `proof.type` |
| `proof.signatureValue` | `proof.jws` (wrapped in JWS) |
| `proof.timestamp` | Additional `proof` entry with `type: "RFC3161Timestamp2024"` |

This mapping is **informational**. Implementors MAY produce JWT-VC, JSON-LD VC, or plain ESE depending on their ecosystem. The OES envelope is the canonical format; VC is an export.

---

## 11. Security Considerations

### 11.1 Transport Security

Discovery documents and verification endpoints MUST be served over HTTPS in production. HTTP is acceptable only for local development and testing.

### 11.2 Key Storage

Private keys used for signing MUST be stored securely:
- **Platform keys**: HSM or encrypted environment variables with restricted access.
- **Customer BYOK**: Only the public key is stored by the issuer. The private key never leaves the customer's control.
- **Cloud KMS**: Keys managed by AWS KMS, Google Cloud KMS, or Azure Key Vault. Signing operations are performed by the KMS service.

### 11.3 Clock Skew

TSA timestamps mitigate clock skew concerns, but verifiers SHOULD allow 5 minutes of clock skew when checking `proof.created` and `proof.timestamp.timestampedAt`.

### 11.4 Replay Protection

The `id` field provides envelope uniqueness. Systems ingesting OES envelopes SHOULD track seen `id` values to detect replays.

### 11.5 Content Type Confusion

The `subject.contentHash` covers raw bytes. A verifier MUST hash the exact bytes received, not a re-encoded or transcoded version. For structured formats (JSON, XML), byte-level comparison is required — semantic equivalence is not sufficient.

### 11.6 Fingerprint Collisions

The 16-character hex fingerprint provides 64 bits of collision resistance. This is sufficient for key identification within a single issuer's key set (typically < 10 keys). It is NOT a security-critical identifier — the full public key is always available via the discovery endpoint.

---

## 12. Reference Verifier

A minimal verifier in Node.js / Bun:

```javascript
import crypto from 'node:crypto';
import fs from 'node:fs';

async function verifyOES(envelopeJson, evidenceBytes) {
  const envelope = JSON.parse(envelopeJson);
  const result = { valid: false, checks: {}, errors: [], warnings: [] };

  // 1. Verify content hash
  const actualHash = crypto.createHash('sha256').update(evidenceBytes).digest('hex');
  if (actualHash !== envelope.subject.contentHash.value) {
    result.errors.push('Content hash mismatch');
    return result;
  }
  result.checks.contentHash = true;

  // 2. Fetch public key
  const discovery = await fetch(envelope.issuer.keyDiscovery).then(r => r.json());
  const keyEntry = discovery.keys.find(
    k => k.fingerprint === envelope.proof.publicKeyFingerprint
  );
  if (!keyEntry) {
    result.errors.push('Signing key not found in discovery document');
    return result;
  }
  if (keyEntry.revoked) {
    result.errors.push('Signing key has been revoked');
    return result;
  }
  result.checks.keyFound = true;

  // 3. Canonicalize subject (sorted-keys-2space, see §4.2)
  function sortKeys(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(sortKeys);
    return Object.fromEntries(
      Object.keys(obj).sort().map(k => [k, sortKeys(obj[k])])
    );
  }
  const canonical = Buffer.from(JSON.stringify(sortKeys(envelope.subject), null, 2), 'utf-8');

  // 4. Verify signature
  const algorithm = envelope.proof.algorithm === 'ECDSA-SHA256' ? 'SHA256' : 'RSA-SHA256';
  const verifier = crypto.createVerify('SHA256');
  verifier.update(canonical);
  const signatureValid = verifier.verify(
    keyEntry.publicKeyPem,
    envelope.proof.signatureValue,
    'base64'
  );
  if (!signatureValid) {
    result.errors.push('Signature verification failed');
    return result;
  }
  result.checks.signature = true;

  // 5. Verify TSA timestamp (simplified — full ASN.1 parsing omitted)
  if (envelope.proof.timestamp) {
    const tsTime = new Date(envelope.proof.timestamp.timestampedAt);
    const now = new Date();
    if (tsTime > new Date(now.getTime() + 5 * 60 * 1000)) {
      result.warnings.push('TSA timestamp is in the future');
    }
    result.checks.timestamp = true;
  }

  result.valid = true;
  return result;
}

// Usage:
// const envelope = fs.readFileSync('evidence.oes.json', 'utf-8');
// const evidence = fs.readFileSync('evidence.zip');
// const result = await verifyOES(envelope, evidence);
// console.log(result);
```

### Python Reference Verifier

```python
import hashlib
import json
import base64
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

def verify_oes(envelope_json: str, evidence_bytes: bytes) -> dict:
    envelope = json.loads(envelope_json)
    result = {"valid": False, "checks": {}, "errors": [], "warnings": []}

    # 1. Verify content hash
    actual_hash = hashlib.sha256(evidence_bytes).hexdigest()
    if actual_hash != envelope["subject"]["contentHash"]["value"]:
        result["errors"].append("Content hash mismatch")
        return result
    result["checks"]["contentHash"] = True

    # 2. Fetch public key
    discovery = requests.get(envelope["issuer"]["keyDiscovery"]).json()
    key_entry = next(
        (k for k in discovery["keys"]
         if k["fingerprint"] == envelope["proof"]["publicKeyFingerprint"]),
        None
    )
    if not key_entry:
        result["errors"].append("Signing key not found")
        return result
    if key_entry.get("revoked"):
        result["errors"].append("Signing key revoked")
        return result
    result["checks"]["keyFound"] = True

    # 3. Canonicalize subject (sorted-keys-2space, see §4.2)
    canonical = json.dumps(
        envelope["subject"], sort_keys=True, indent=2, ensure_ascii=False
    ).encode("utf-8")

    # 4. Verify signature
    public_key = serialization.load_pem_public_key(
        key_entry["publicKeyPem"].encode()
    )
    signature = base64.b64decode(envelope["proof"]["signatureValue"])
    try:
        if envelope["proof"]["algorithm"] == "RSA-SHA256":
            public_key.verify(signature, canonical, padding.PKCS1v15(), hashes.SHA256())
        else:
            public_key.verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
        result["checks"]["signature"] = True
    except Exception:
        result["errors"].append("Signature verification failed")
        return result

    result["valid"] = True
    return result
```

---

## 13. Example: Complete Envelope

```json
{
  "@context": "https://openevidence.org/signing/v1",
  "version": "1.0",
  "id": "env_clx9abc123def456",

  "issuer": {
    "id": "https://app.screenata.com",
    "name": "Screenata",
    "keyDiscovery": "https://app.screenata.com/.well-known/oes-signing"
  },

  "subject": {
    "type": "compliance-evidence:bundle",
    "contentHash": {
      "algorithm": "SHA-256",
      "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "files": [
      {
        "filename": "screenshots/01_mfa_settings.png",
        "contentHash": {
          "algorithm": "SHA-256",
          "value": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        },
        "size": 145230,
        "mediaType": "image/png"
      },
      {
        "filename": "screenshots/02_mfa_enforced.png",
        "contentHash": {
          "algorithm": "SHA-256",
          "value": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        },
        "size": 98400,
        "mediaType": "image/png"
      },
      {
        "filename": "ep_MFA-01_20260420.pdf",
        "contentHash": {
          "algorithm": "SHA-256",
          "value": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        },
        "size": 52100,
        "mediaType": "application/pdf"
      }
    ],
    "metadata": {
      "title": "MFA Enforcement Verification — AWS IAM",
      "collectedAt": "2026-04-20T10:30:00Z",
      "collector": "screenata-agent:v3.2.1",
      "framework": "SOC 2",
      "controlRef": "CC6.1",
      "description": "Automated verification that MFA is enforced for all IAM users with console access."
    }
  },

  "proof": {
    "type": "RsaSignature2024",
    "created": "2026-04-20T10:30:05Z",
    "algorithm": "RSA-SHA256",
    "publicKeyFingerprint": "a1b2c3d4e5f6a7b8",
    "signatureValue": "MEUCIQD5VcGR7x8Qk3Yp3q1L8mN...base64...==",
    "canonicalization": "sorted-keys-2space",
    "signedFields": "subject",
    "timestamp": {
      "type": "RFC3161",
      "token": "MIIHnwYJKoZIhvcNAQcCoI...base64...==",
      "authority": "http://timestamp.digicert.com",
      "timestampedAt": "2026-04-20T10:30:06Z",
      "serialNumber": "1234567890ABCDEF"
    }
  }
}
```

---

## 14. File Naming Convention

OES envelopes SHOULD be distributed alongside evidence artifacts using the following naming convention:

| Artifact | Filename |
|---|---|
| Evidence file | `evidence.zip`, `screenshot.png`, etc. |
| OES envelope | `evidence.oes.json`, `screenshot.oes.json`, etc. |
| Discovery (cached) | `issuer-discovery.json` |

For bundle distributions (e.g., an audit package), the recommended layout:

```
audit-package/
├── evidence/
│   ├── MFA-01/
│   │   ├── ep_MFA-01_20260420.zip
│   │   └── ep_MFA-01_20260420.oes.json
│   ├── ACCESS-03/
│   │   ├── ep_ACCESS-03_20260420.zip
│   │   └── ep_ACCESS-03_20260420.oes.json
│   └── ...
├── issuer-discovery.json          (cached copy of /.well-known/oes-signing)
└── verify.sh                      (optional: script to verify all envelopes)
```

---

## 15. Versioning and Extensibility

### 15.1 Spec Versioning

The specification uses semantic versioning:

- **Patch** (1.0.x): Clarifications, typo fixes, additional examples. No format changes.
- **Minor** (1.x.0): New optional fields, new registered evidence types, new algorithms. Backward compatible — a v1.0 verifier can still verify v1.1 envelopes (it ignores unknown fields).
- **Major** (x.0.0): Breaking changes to the envelope structure, canonicalization, or verification algorithm. Major versions are a new `@context` URL.

### 15.2 Extension Fields

Issuers MAY add custom fields to `subject.metadata` using a namespace prefix:

```json
{
  "metadata": {
    "title": "MFA Verification",
    "x-screenata-executionId": "exec_abc123",
    "x-screenata-testResult": "PASS"
  }
}
```

Fields prefixed with `x-{issuer}` are issuer-specific and MUST be ignored by generic verifiers. They are NOT included in the canonical signing input unless they appear within `subject`.

### 15.3 Future Algorithm Support

New signing algorithms (e.g., Ed25519, post-quantum) will be introduced in minor versions. Verifiers MUST reject envelopes with unrecognized `proof.algorithm` values rather than silently skipping verification.

---

## 16. Conformance

An implementation conforms to OES v1.0 if it satisfies one or both of:

### 16.1 Conformant Issuer

- Produces envelopes matching the schema in Section 3.
- Computes content hashes per Section 4.4.
- Signs using canonicalization per Section 4.2.
- Serves a discovery document per Section 5.
- Uses a supported algorithm per Section 4.1.

### 16.2 Conformant Verifier

- Implements the verification algorithm in Section 7 (all REQUIRED steps).
- Fetches keys via the discovery protocol in Section 5.
- Reports `contentHashVerified: false` when evidence bytes are unavailable.
- Rejects envelopes with unsupported algorithms rather than skipping verification.

---

## 17. Open Questions

These questions are explicitly unresolved in v1.0 and are the areas where auditor and implementer input is most valuable. They are expected to be resolved in v1.1.

1. **Custody chain.** Should `auditTrail` carry structured fields for `capturedBy`, `reviewedBy`, `approvedBy` rather than only `createdBy`? What fields does an auditor inspect during fieldwork?
2. **Sampling metadata.** When a bundle contains a sample drawn from a population (e.g., 25 of 400 user-access reviews), should population size and sampling method live in `metadata` or in a separate sidecar?
3. **Control mapping.** Should the internal manifest carry an inline list of all controls the bundle covers, or only the primary `controlRef`? Auditors with custom control sets need flexibility here.
4. **Redaction.** Some artifacts will be redacted before sharing. Should `FileEntry` record the pre-redaction hash plus a redaction transform, or only the post-redaction hash? (Affects whether auditors can detect post-redaction tampering vs. detect that redaction occurred at all.)
5. **Multi-signer bundles.** Should the spec support an `innerSignature[]` array (producer + customer co-sign), or is a single inner signature plus an `x-cosigners` extension enough?
6. **Inner-signature scope.** Is signing the whole manifest-minus-`innerSignature` the right default, or should the inner signature scope be narrower (e.g., `files` only) to allow editorial metadata edits without resigning?
7. **JCS canonicalization.** When (if ever) to require [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JSON Canonicalization Scheme) instead of the current `sorted-keys-2space`. v1.0 prioritizes human-readable manifests; v1.1 or later may add a JCS-compatible mode for stricter interop.

---

## Appendix A: Test Vectors

Test vectors and a reference verifier ship in the open-source `open-evidence-signing`
package (Apache-2.0), available in the vendor-neutral repo:

```
https://github.com/Screenata/open-evidence-signing/tree/main/test-vectors
```

Each test vector includes:
- A sample evidence file
- An OES envelope signed with a test key pair
- The test key pair (public + private for verification testing)
- Expected verification result

The vectors are **generated from, and CI-proven byte-equivalent to, the
production signer** (deterministic RSA signatures; verified by a
continuous-integration parity test), so a verifier that passes them is
conformant against real production-issued evidence. The package also ships a single-file
Python verifier (`python/oes_verify.py`) and JSON Schemas for the envelope and
bundle manifest (`schema/`).

---

## Appendix B: Comparison with Existing Standards

| Dimension | OES v1.0 | W3C VC | CPOE (GRC Corsair) | CMS/PKCS#7 |
|---|---|---|---|---|
| Primary use | Compliance evidence | General credentials | Compliance proofs | Generic signing |
| Format | JSON | JSON-LD / JWT | JWT-VC | ASN.1 / DER |
| Signing | RSA / ECDSA | Various | Ed25519 | RSA / ECDSA |
| Timestamping | RFC 3161 (built-in) | Not specified | Self-attested | RFC 3161 (separate) |
| Key discovery | `.well-known/oes-signing` | DID resolution | DID:web | X.509 certificate chain |
| Legal standing | eIDAS-compatible via TSA | Varies | None specified | eIDAS-compatible |
| Verification complexity | ~100 LOC | ~500 LOC (DID + JSON-LD) | ~300 LOC (DID + JWT) | ~200 LOC (ASN.1) |
| Offline capable | Yes (after key fetch) | Yes (after DID resolve) | Yes (after DID resolve) | Yes (with cert) |
| Interop with VC | Optional export (Section 10) | Native | Native | Not applicable |
| Evidence-specific fields | Yes (type, framework, control) | Generic | Generic | None |

---

## Appendix C: MIME Type Registration

OES envelopes use the media type:

```
application/vnd.oes+json
```

Until formal IANA registration, the informal type `application/json` with a `.oes.json` file extension is acceptable.

---

## Appendix D: Production `ManifestV3` → OES bundle-manifest mapping

Screenata's production internal manifest (`ManifestV3`) uses different field names than the OES bundle-manifest definition in §8.4. The field mapping between the production format and OES:

| Production (`ManifestV3`) | OES (`oes-1.0-bundle-manifest`) | Notes |
|---|---|---|
| `version: "4.0"` | `specVersion: "oes-1.0-bundle-manifest"` | Public versioning aligns to OES. v4.0 signs the canonical manifest bytes per §8.6 (v3.0's hex-digest scheme is retired and no longer verifiable). |
| `evidence_pack_id` | `bundleId` | Camel-case alignment. |
| `generated_at` | `generatedAt` | Camel-case alignment. |
| `metadata.workspace_id` | `metadata.x-workspace-id` | Moved to extension namespace. |
| `audit_trail` | `auditTrail` | Camel-case alignment. |
| `audit_trail.created_by_user_id` | `auditTrail.createdBy` | Use email/actor name, not internal DB ID. |
| `audit_trail.workspace_id` | _(removed)_ | Redundant with `metadata.x-workspace-id`. |
| `topic`, `doc` | `metadata.x-topic`, `metadata.x-doc` | Platform-specific, moved to extensions. |
| `cryptographic_signature` | `innerSignature` | Renamed for clarity; OES envelope is the primary signature path. |
| `verificationInstructions` (camelCase alias) | _(removed)_ | Deprecated compatibility field. |
| All other fields | Renamed to camelCase | — |

---

## Changelog

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-06-12 | Fixed §4.2 and §12 example code to match the normative `sorted-keys-2space` canonicalization (examples previously emitted compact JSON); fixed Python ECDSA verify call. No normative protocol changes. Reference implementation unified on raw-bytes signing across envelope, manifest (v4.0), and per-file signatures; legacy v3.0 hex-digest scheme retired. |
| 1.0-draft | 2026-05-12 | Folded internal bundle-manifest definition into §8 (was previously a separate annex). Added §17 open questions. Added Appendix D production field mapping. |
| 1.0-draft | 2026-04-27 | Initial specification. |

---

## Implementation Status

The protocol-level shape (envelope schema, canonicalization, key discovery, RFC 3161 binding, bundle layout, internal manifest) is implemented in the `open-evidence-signing` package and consumed by production GRC platforms. The `ManifestV3 → OES` mapping in Appendix D is consistent with the production evidence-pack manifest layout.
