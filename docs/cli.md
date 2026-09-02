# CLI reference

```
oes <envelope.oes.json | manifest.json | pack.zip> [options]
```

The CLI verifies any OES artifact and exits with a CI-friendly status code. It
does **not** sign — signing is a library operation (see [Signing](./signing.md)).

## Options

| Option | Meaning |
|---|---|
| `--content <file>` | Raw evidence bytes for the content-hash check (spec §7.2). Omit to verify the signature only. For a bundle envelope, pass the bundle ZIP to also check each file. |
| `--keys <file>` | A cached discovery document (JSON) **or** a PEM public-key file — the offline key source. |
| `--offline` | Never touch the network. Requires `--keys`. |
| `--allow-http` | Permit non-HTTPS discovery URLs (local dev only). |
| `--json` | Emit a machine-readable `VerificationResult` to stdout. |
| `-h`, `--help` | Show usage. |

The artifact type is detected automatically: `.zip` → pack; JSON with
`@context` → envelope; JSON with `cryptographic_signature`/`version` → manifest.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Valid |
| `1` | Verification failed (tampering, bad signature, unknown/revoked key, …) |
| `2` | Usage or I/O error (bad args, unreadable file, `--offline` without `--keys`) |

Use it directly as a gate:

```bash
npx oes evidence.oes.json --content evidence.zip --keys discovery.json --offline \
  || { echo "evidence failed verification"; exit 1; }
```

## Examples

```bash
# Envelope + evidence, fetching the issuer key over HTTPS
npx oes evidence.oes.json --content evidence.zip

# Fully offline with a saved discovery document
npx oes evidence.oes.json --content evidence.zip --keys issuer-discovery.json --offline

# Verify with a bare PEM instead of a discovery doc
npx oes evidence.oes.json --content evidence.zip --keys issuer.pub.pem --offline

# A standalone v4.0 evidence-pack ZIP
npx oes pack.zip --keys issuer-discovery.json --offline

# Signature only (no evidence bytes) — reports contentHashVerified:false
npx oes evidence.oes.json --keys issuer-discovery.json --offline

# Machine-readable for a pipeline
npx oes evidence.oes.json --keys discovery.json --offline --json | jq '.valid'
```

## Human output

```
✓ VALID

  ✓ Content Hash — SHA-256 of evidence matches subject.contentHash
  ✓ Signature — Verified with key 549f3b9895b9b973

  issuer:      https://compliance.acme.example
  signed at:   2026-04-20T10:30:00.000Z
  timestamped: 2026-04-20T10:30:06Z
  key:         549f3b9895b9b973
  content hash verified: true
```

A failing run prints the failed checks and writes the reasons to stderr, with
exit code `1`.

## Dogfooding from the Screenata CLI

If you use the Screenata CLI, `screenata evidence verify --local` wraps this
package to verify a local file fully offline:

```bash
screenata evidence verify --file=evidence.oes.json --content=evidence.zip \
  --keys=issuer-discovery.json --local
```
