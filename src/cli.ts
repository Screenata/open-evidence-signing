/**
 * oes-verify CLI.
 *
 *   oes-verify <envelope.oes.json | manifest.json | pack.zip> [options]
 *
 *   --content <file>   raw evidence bytes (envelope content-hash check, spec §7.2)
 *   --keys <file>      cached discovery document JSON, or a PEM file (offline keys)
 *   --offline          never touch the network; requires --keys
 *   --allow-http       permit non-HTTPS discovery (local dev only)
 *   --json             machine-readable output
 *   -h, --help         show this help
 *
 * Exit codes:  0 = valid · 1 = verification failed · 2 = usage / I/O error
 */
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { verifyEnvelope } from './envelope';
import { verifyManifest, type ManifestKeyResolver } from './manifest';
import { verifyZipPack } from './bundle';
import { resolverFromDiscovery, resolverFromPems } from './discovery';
import { resolverFromNetwork } from './discovery';
import type {
  DiscoveryDocument,
  KeyResolver,
  ResolvedKey,
  VerificationResult,
} from './types';

const HELP = `oes-verify — verify Open Evidence Signing (OES) v1.0 artifacts

Usage:
  oes-verify <envelope.oes.json | manifest.json | pack.zip> [options]

Options:
  --content <file>   raw evidence bytes for the content-hash check (spec §7.2)
  --keys <file>      cached discovery document (JSON) or a PEM file for offline keys
  --offline          never touch the network; requires --keys
  --allow-http       permit non-HTTPS discovery URLs (local dev only)
  --json             emit a machine-readable JSON result
  -h, --help         show this help

Exit codes: 0 valid · 1 verification failed · 2 usage/I-O error`;

interface Args {
  target?: string;
  content?: string;
  keys?: string;
  offline: boolean;
  allowHttp: boolean;
  json: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { offline: false, allowHttp: false, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '-h':
      case '--help': a.help = true; break;
      case '--offline': a.offline = true; break;
      case '--allow-http': a.allowHttp = true; break;
      case '--json': a.json = true; break;
      case '--content': a.content = argv[++i]; break;
      case '--keys': a.keys = argv[++i]; break;
      default:
        if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
        if (a.target) throw new Error(`Unexpected extra argument: ${arg}`);
        a.target = arg;
    }
  }
  return a;
}

/** Build an envelope key resolver from --keys / network per the flags. */
function buildEnvelopeResolver(args: Args): KeyResolver {
  if (args.keys) return resolverFromFile(args.keys);
  if (args.offline) throw new Error('--offline requires --keys to supply a discovery document or PEM');
  return resolverFromNetwork({ allowHttp: args.allowHttp });
}

function resolverFromFile(path: string): KeyResolver {
  const raw = fs.readFileSync(path, 'utf-8');
  // A PEM file starts with the armor header; a discovery JSON starts with '{'
  // (and merely *contains* a PEM inside publicKeyPem).
  if (raw.trimStart().startsWith('-----BEGIN')) {
    const pems = raw.split(/(?=-----BEGIN)/).filter((p) => p.includes('-----BEGIN'));
    return resolverFromPems(pems);
  }
  const doc = JSON.parse(raw) as DiscoveryDocument;
  return resolverFromDiscovery(doc);
}

/** A manifest resolver that can also fetch `publicKeyUrl` when online. */
function buildManifestResolver(args: Args): ManifestKeyResolver {
  if (args.keys) {
    const base = resolverFromFile(args.keys);
    return (fp) => base(fp);
  }
  if (args.offline) throw new Error('--offline requires --keys');
  return async (fingerprint, publicKeyUrl): Promise<ResolvedKey | null> => {
    if (!publicKeyUrl) return null;
    if (!args.allowHttp && !publicKeyUrl.startsWith('https://')) {
      throw new Error(`Refusing non-HTTPS publicKeyUrl: ${publicKeyUrl}`);
    }
    const res = await fetch(publicKeyUrl);
    if (!res.ok) throw new Error(`publicKeyUrl fetch failed: ${res.status}`);
    const text = await res.text();
    const pem = text.includes('-----BEGIN') ? text : (JSON.parse(text).publicKeyPem as string);
    return { pem, fingerprint };
  };
}

function report(result: VerificationResult, args: Args): void {
  if (args.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }
  const mark = (ok: boolean) => (ok ? '✓' : '✗');
  process.stdout.write(`\n${result.valid ? '✓ VALID' : '✗ INVALID'}\n\n`);
  for (const c of result.checks) {
    process.stdout.write(`  ${mark(c.passed)} ${c.name}${c.details ? ` — ${c.details}` : ''}\n`);
  }
  if (result.details.issuer) process.stdout.write(`\n  issuer:      ${result.details.issuer}\n`);
  if (result.details.signedAt) process.stdout.write(`  signed at:   ${result.details.signedAt}\n`);
  if (result.details.timestampedAt) process.stdout.write(`  timestamped: ${result.details.timestampedAt}\n`);
  if (result.details.keyFingerprint) process.stdout.write(`  key:         ${result.details.keyFingerprint}\n`);
  process.stdout.write(`  content hash verified: ${result.contentHashVerified}\n`);
  for (const w of result.warnings) process.stdout.write(`  ! ${w}\n`);
  for (const e of result.errors) process.stderr.write(`  error: ${e}\n`);
  process.stdout.write('\n');
}

export async function run(argv: string[]): Promise<number> {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n\n${HELP}\n`);
    return 2;
  }
  if (args.help || !args.target) {
    process.stdout.write(`${HELP}\n`);
    return args.help ? 0 : 2;
  }

  let result: VerificationResult;
  try {
    const targetBytes = fs.readFileSync(args.target);
    const contentBytes = args.content ? fs.readFileSync(args.content) : undefined;

    if (args.target.toLowerCase().endsWith('.zip')) {
      result = await verifyZipPack(targetBytes, buildManifestResolver(args));
    } else {
      const parsed = JSON.parse(targetBytes.toString('utf-8'));
      if (parsed['@context']) {
        // verifyEnvelope re-narrows internally and now performs the per-file
        // (subject.files[]) checks itself — no CLI-side bundle handling needed.
        result = await verifyEnvelope(parsed, contentBytes, buildEnvelopeResolver(args));
      } else if (parsed.cryptographic_signature || parsed.version) {
        result = await verifyManifest(parsed, buildManifestResolver(args));
      } else {
        process.stderr.write('Unrecognized artifact: not an OES envelope, manifest, or ZIP pack\n');
        return 2;
      }
    }
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return 2;
  }

  report(result, args);
  return result.valid ? 0 : 1;
}

// Auto-run only when this file is the direct entry point (e.g. `bun src/cli.ts`).
// The published `bin/oes-verify.js` wrapper imports and calls `run()` itself.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`fatal: ${e?.message ?? e}\n`);
      process.exit(2);
    }
  );
}
