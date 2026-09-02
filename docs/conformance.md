# Conformance & test vectors

OES is a published format, so you can write your own signer or verifier in any
language and check it against shared fixtures. This package ships those fixtures
and is itself proven against the reference implementation.

## What "conformant" means

From spec §16:

- **A conformant verifier** implements every REQUIRED step of §7, fetches keys
  via §5 discovery, reports `contentHashVerified: false` when evidence bytes are
  absent, and **rejects** unknown algorithms rather than skipping them.
- **A conformant issuer** produces envelopes matching §3, hashes content per
  §4.4, signs using the §4.2 canonicalization, serves a §5 discovery document,
  and uses a §4.1 algorithm.

## Test vectors

The [`test-vectors/`](../test-vectors/) directory holds sample artifacts plus a
test key pair and an `expected.json` per case:

| Case | Expect | Exercises |
|---|---|---|
| `01-plain-envelope` | valid | Single-file envelope, content hash + signature. |
| `02-bundle-envelope` | valid | Multi-file ZIP bundle, whole-bundle + per-file hashes. |
| `03-manifest-pack` | valid | v4.0 pack: signed manifest + per-file signatures. |
| `04-envelope-tsa` | valid | RFC 3161 timestamp binding (synthetic token). |
| `05-tampered-envelope` | **invalid** | Subject altered after signing. |
| `06-tampered-pack` | **invalid** | A file in the pack was swapped. |
| `07-unknown-key` | **invalid** | Signed by a key absent from discovery. |

The test key pair's **private** key is published on purpose so you can sign your
own samples and check your verifier — it signs nothing real.

### Verify the vectors with the CLI

```bash
cd test-vectors
npx oes 01-plain-envelope/envelope.oes.json \
  --content 01-plain-envelope/evidence.txt \
  --keys issuer-discovery.json --offline      # exit 0

npx oes 05-tampered-envelope/envelope.oes.json \
  --content 05-tampered-envelope/evidence.txt \
  --keys issuer-discovery.json --offline      # exit 1
```

### Drive them from your own verifier

Each case's `expected.json` records the artifact type, inputs, and expected
verdict — load it, run your verifier, and assert. That's exactly what this
package's `vectors.test.ts` does.

## Cross-implementation parity

These vectors are **generated from, and proven byte-equivalent to, the reference
signer**: signatures are deterministic (RSA PKCS#1 v1.5), and a CI test in the
reference implementation re-signs the same subjects with the production signer
and asserts the bytes match — in both directions (the reference verifier accepts
the vectors; the reference signer reproduces them). A passing run against these
vectors therefore means you can verify real, production-issued evidence.

The bundled `python/oes_verify.py` is a second, independent implementation that
verifies the same vectors — a useful cross-check that your canonicalization is
byte-correct across languages.

## Regenerating the vectors

```bash
bun run scripts/gen-vectors.ts
```

Output is deterministic — a clean `git diff` means nothing drifted. If you
change the signing scheme, the reference-implementation parity test will fail
until the vectors and the spec are updated together.
