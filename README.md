# oes — Open Evidence Signing

**Sign and verify compliance evidence that anyone can check — without trusting,
or even contacting, whoever produced it.**

`oes` is the zero-dependency reference implementation of the
[Open Evidence Signing (OES) v1.0](./SPEC.md) format. It does two things:

- **Verify** — confirm evidence wasn't altered, was signed by a known key, and
  (optionally) was timestamped by an independent RFC 3161 authority. Runs fully
  offline after a one-time key fetch.
- **Sign** — mint OES envelopes for your own evidence with your own key,
  including keys that live in a KMS/HSM and never touch this library (BYOK).

Together that makes OES a vendor-neutral standard: any issuer can produce
evidence, and any auditor can verify it independently.

> Apache-2.0. No runtime dependencies — Node.js built-ins (`crypto`, `zlib`)
> only. Node 18+ / Bun.

## Install

```bash
npm install open-evidence-signing          # library
npx oes --help           # CLI, no install needed
```

## Verify

```ts
import { verifyEnvelope, resolverFromDiscovery } from 'open-evidence-signing';
import { readFileSync } from 'node:fs';

const result = await verifyEnvelope(
  readFileSync('evidence.oes.json', 'utf-8'),
  readFileSync('evidence.zip'),
  resolverFromDiscovery(JSON.parse(readFileSync('issuer-discovery.json', 'utf-8'))),
);
if (!result.valid) throw new Error(result.errors.join('; '));
console.log('signed by', result.details.issuer, 'at', result.details.timestampedAt);
```

…or from the command line, with CI-friendly exit codes (`0` valid · `1` failed ·
`2` usage):

```bash
npx oes evidence.oes.json --content evidence.zip \
  --keys issuer-discovery.json --offline
```

## Sign

```ts
import { signEnvelope, localSigner } from 'open-evidence-signing';
import { readFileSync, writeFileSync } from 'node:fs';

const signer = localSigner(readFileSync('signing-key.private.pem', 'utf-8'));
const envelope = await signEnvelope(signer, {
  content: readFileSync('evidence.zip'),
  type: 'compliance-evidence:bundle',
  metadata: { title: 'Q1 Access Review', framework: 'SOC 2', controlRef: 'CC6.1' },
  issuer: { id: 'https://compliance.acme.example', name: 'Acme Corp' },
  tsa: { urls: ['http://timestamp.digicert.com'] },   // optional RFC 3161 timestamp
});
writeFileSync('evidence.oes.json', JSON.stringify(envelope, null, 2));
```

The private key can live in a KMS/HSM — implement the tiny `Signer` interface
and the key never enters this library. See [BYOK & key discovery](./docs/byok.md).

## Documentation

| Guide | What it covers |
|---|---|
| [Getting started](./docs/getting-started.md) | Install + a 60-second tour of sign and verify. |
| [Verifying](./docs/verifying.md) | Envelopes, manifests, ZIP packs; key resolution; results; offline. |
| [Signing](./docs/signing.md) | `signEnvelope`/`signManifest`, bundles, RFC 3161 timestamps, algorithms. |
| [BYOK & key discovery](./docs/byok.md) | Sign with a KMS/HSM key; publish, rotate, and revoke keys. |
| [CLI reference](./docs/cli.md) | All flags, exit codes, examples. |
| [API reference](./docs/api.md) | Every export and its signature. |
| [Conformance & test vectors](./docs/conformance.md) | Prove an implementation is correct. |
| [SPEC.md](./SPEC.md) | The OES v1.0 protocol. |

## What it deliberately does *not* do

- **It doesn't validate the TSA certificate chain.** A timestamp still proves
  the imprint was certified at `genTime`; trusting the TSA itself is your policy
  (spec §6.3 step 7).
- **It doesn't decide which issuers you trust.** It proves *who* signed (via key
  discovery); trust anchoring is your policy.

## Provenance

Maintained by [Screenata](https://screenata.com) and released as a vendor-neutral
open standard. The bundled `python/oes_verify.py` is a second, independent
verifier; `test-vectors/` are proven byte-equivalent to the reference signer.
