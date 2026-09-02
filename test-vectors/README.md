# OES test vectors

Sample artifacts for validating an Open Evidence Signing (OES) v1.0 **verifier**.
Each case directory has an `expected.json` describing the inputs and the verdict
a conformant verifier must produce.

> **Provenance.** These vectors are signed with the committed test key
> (`test-key.private.pem`) and are proven **byte-equivalent to the reference
> signer** by a continuous-integration parity test. RSA PKCS#1 v1.5 signatures
> are deterministic, so regenerating (`bun run scripts/gen-vectors.ts`) yields
> an identical diff.

## Files

| Path | Purpose |
|---|---|
| `test-key.public.pem` / `test-key.private.pem` | Test key pair. The **private key is published on purpose** so implementers can sign their own samples. It signs nothing real. |
| `issuer-discovery.json` | The issuer's discovery document — the offline key source (`--keys`). |
| `NN-*/` | One verification case each. |

## Cases

| Case | Expect | Exercises |
|---|---|---|
| `01-plain-envelope` | ✅ valid | Single-file envelope, content hash + signature, no TSA. |
| `02-bundle-envelope` | ✅ valid | Multi-file ZIP bundle; whole-bundle hash + per-file `subject.files[]`. |
| `03-manifest-pack` | ✅ valid | Standalone v4.0 evidence-pack ZIP: signed manifest + per-file signatures. |
| `04-envelope-tsa` | ✅ valid | RFC 3161 timestamp binding (synthetic token — see note). |
| `05-tampered-envelope` | ❌ invalid | Subject metadata altered after signing. |
| `06-tampered-pack` | ❌ invalid | A file inside the pack was swapped. |
| `07-unknown-key` | ❌ invalid | Signed by a key absent from discovery. |

> **`04-envelope-tsa` note.** The timestamp token is **synthetic** — it has no
> real TSA certificate. It binds `messageImprint = SHA-256(signature)` at a
> fixed `genTime`, which is exactly what the verifier checks (the verifier does
> not validate the TSA certificate chain — see `SPEC.md` §6.3 step 7). A
> production token from DigiCert/Sectigo/FreeTSA verifies the same way.

## Using them

```bash
# From the repository root
npx oes test-vectors/01-plain-envelope/envelope.oes.json \
  --content test-vectors/01-plain-envelope/evidence.txt \
  --keys test-vectors/issuer-discovery.json --offline
# → exit 0

npx oes test-vectors/05-tampered-envelope/envelope.oes.json \
  --content test-vectors/05-tampered-envelope/evidence.txt \
  --keys test-vectors/issuer-discovery.json --offline
# → exit 1 (Invalid signature)
```
