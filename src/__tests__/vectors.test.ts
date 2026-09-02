/**
 * Drives every committed test vector through the public verifier API and
 * asserts the recorded `expected.json`. This is the cross-implementation
 * conformance gate: the vectors are signed by the (production-equivalent) test
 * key, and a passing run proves this verifier validates them.
 */
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  verifyEnvelope,
  verifyManifest,
  verifyZipPack,
  verifyEnvelopeBundleFiles,
  resolverFromDiscovery,
} from '../index';
import type { DiscoveryDocument, EvidenceSigningEnvelope } from '../types';

const VEC = path.join(import.meta.dirname, '..', '..', 'test-vectors');
const discovery = JSON.parse(fs.readFileSync(path.join(VEC, 'issuer-discovery.json'), 'utf-8')) as DiscoveryDocument;
const resolver = resolverFromDiscovery(discovery);

interface Expected {
  description: string;
  artifact: 'envelope' | 'manifest' | 'zip';
  target: string;
  content?: string;
  expect: { valid: boolean; contentHashVerified?: boolean; timestamped?: boolean; bundleFiles?: boolean; errorsMatch?: string };
}

const caseDirs = fs
  .readdirSync(VEC, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

describe('committed test vectors', () => {
  it('has the expected set of vectors', () => {
    expect(caseDirs.length).toBeGreaterThanOrEqual(7);
  });

  for (const name of caseDirs) {
    const dir = path.join(VEC, name);
    const exp = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf-8')) as Expected;

    it(`${name} — ${exp.description}`, async () => {
      const contentBytes = exp.content ? fs.readFileSync(path.join(dir, exp.content)) : undefined;
      let result;

      if (exp.artifact === 'envelope') {
        const env = JSON.parse(fs.readFileSync(path.join(dir, exp.target), 'utf-8')) as EvidenceSigningEnvelope;
        result = await verifyEnvelope(env, contentBytes, resolver);
        if (exp.expect.valid && exp.expect.bundleFiles && contentBytes) {
          const fileChecks = verifyEnvelopeBundleFiles(env, contentBytes);
          expect(fileChecks.length).toBeGreaterThan(0);
          expect(fileChecks.every((c) => c.passed)).toBe(true);
        }
        if (exp.expect.timestamped) expect(result.details.timestampedAt).toBeTruthy();
      } else if (exp.artifact === 'zip') {
        result = await verifyZipPack(fs.readFileSync(path.join(dir, exp.target)), resolver);
      } else {
        result = await verifyManifest(fs.readFileSync(path.join(dir, exp.target), 'utf-8'), resolver);
      }

      expect(result.valid).toBe(exp.expect.valid);
      if (exp.expect.contentHashVerified !== undefined) {
        expect(result.contentHashVerified).toBe(exp.expect.contentHashVerified);
      }
      if (exp.expect.errorsMatch) {
        expect(result.errors.join(' ')).toMatch(new RegExp(exp.expect.errorsMatch, 'i'));
      }
    });
  }
});
