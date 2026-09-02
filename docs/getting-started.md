# Getting started

`oes` implements the [Open Evidence Signing (OES) v1.0](../SPEC.md) format:
a vendor-neutral way to **sign** compliance evidence and **verify** it later
without trusting — or contacting — whoever produced it.

- **Verify**: confirm evidence wasn't altered, was signed by a known key, and
  (optionally) was timestamped by an independent RFC 3161 authority.
- **Sign**: mint OES envelopes for your own evidence with your own key — including
  keys that live in a KMS/HSM and never touch this library (BYOK).

Zero runtime dependencies. Node.js 18+ or Bun. Apache-2.0.

## Install

```bash
npm install open-evidence-signing      # or: pnpm add open-evidence-signing / bun add open-evidence-signing
```

For the CLI only, no install is needed:

```bash
npx oes evidence.oes.json --content evidence.zip
```

## 60-second tour

### Verify an envelope

```ts
import { verifyEnvelope, resolverFromDiscovery } from 'open-evidence-signing';
import { readFileSync } from 'node:fs';

const envelope = readFileSync('evidence.oes.json', 'utf-8');
const evidence = readFileSync('evidence.zip');
const discovery = JSON.parse(readFileSync('issuer-discovery.json', 'utf-8'));

const result = await verifyEnvelope(envelope, evidence, resolverFromDiscovery(discovery));
if (!result.valid) throw new Error(result.errors.join('; '));

console.log('signed by', result.details.issuer, 'at', result.details.timestampedAt);
```

### Sign an envelope

```ts
import { signEnvelope, localSigner } from 'open-evidence-signing';
import { readFileSync, writeFileSync } from 'node:fs';

const signer = localSigner(readFileSync('signing-key.private.pem', 'utf-8'));
const evidence = readFileSync('evidence.zip');

const envelope = await signEnvelope(signer, {
  content: evidence,
  type: 'compliance-evidence:bundle',
  metadata: { title: 'Q1 Access Review', framework: 'SOC 2', controlRef: 'CC6.1' },
  issuer: { id: 'https://compliance.acme.example', name: 'Acme Corp' },
  tsa: { urls: ['http://timestamp.digicert.com'] }, // optional RFC 3161 timestamp
});

writeFileSync('evidence.oes.json', JSON.stringify(envelope, null, 2));
```

That envelope is now verifiable by anyone running `oes` (or any
spec-conformant verifier) against your published key — no account with you
required.

## Where to next

| You want to… | Read |
|---|---|
| Verify envelopes, manifests, or ZIP packs | [Verifying](./verifying.md) |
| Produce signed evidence | [Signing](./signing.md) |
| Sign with a KMS/HSM key (BYOK) and publish keys | [BYOK & key discovery](./byok.md) |
| Use the CLI in CI | [CLI reference](./cli.md) |
| Look up an export's signature | [API reference](./api.md) |
| Prove your implementation is conformant | [Conformance & test vectors](./conformance.md) |
| Read the protocol | [SPEC.md](../SPEC.md) |
