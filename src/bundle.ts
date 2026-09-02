/**
 * Evidence bundle (ZIP) verification.
 *
 *  - {@link verifyEnvelopeBundleFiles}: given an envelope with `subject.files[]`
 *    and the bundle ZIP bytes, check each file's individual hash (spec §8.2).
 *  - {@link verifyZipPack}: standalone v4.0 manifest pack — find `manifest.json`
 *    inside the ZIP, verify its signature, then verify every file's hash and
 *    per-file signature. Mirrors the reference `verifyZipPackage`.
 */
import crypto from 'node:crypto';
import { readZip } from './zip';
import { verifyManifest, type ManifestKeyResolver } from './manifest';
import type { EvidenceSigningEnvelope, VerificationCheck, VerificationResult } from './types';

function sha256Hex(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/** Per-file hash checks for an envelope's `subject.files[]` against bundle bytes. */
export function verifyEnvelopeBundleFiles(
  envelope: EvidenceSigningEnvelope,
  zipBytes: Buffer
): VerificationCheck[] {
  const files = envelope.subject.files ?? [];
  if (files.length === 0) return [];

  let entries: Map<string, Buffer>;
  try {
    entries = readZip(zipBytes);
  } catch (e) {
    return [{ name: 'Bundle files', passed: false, details: `Could not read ZIP: ${(e as Error).message}` }];
  }

  return files.map((f) => {
    const bytes = entries.get(f.filename);
    if (!bytes) return { name: f.filename, passed: false, details: 'File not present in bundle' };
    const actual = sha256Hex(bytes);
    const match = actual === f.contentHash.value;
    return {
      name: f.filename,
      passed: match,
      details: match ? 'File hash matches' : 'File hash mismatch',
    };
  });
}

interface FileEntry {
  filename: string;
  sha256: string;
  signature?: string;
}

function collectManifestFiles(manifest: Record<string, unknown>): FileEntry[] {
  const files = (manifest.files ?? {}) as Record<string, unknown>;
  const out: FileEntry[] = [];
  for (const key of ['screenshots', 'attachments', 'artifacts']) {
    const arr = files[key];
    if (Array.isArray(arr)) out.push(...(arr as FileEntry[]));
  }
  if (files.comments_txt && typeof files.comments_txt === 'object') {
    out.push(files.comments_txt as FileEntry);
  }
  return out.filter((f) => f && f.filename);
}

/**
 * Verify a standalone v4.0 evidence pack ZIP: manifest signature + every file's
 * hash and (when present) per-file signature.
 */
export async function verifyZipPack(
  zipBytes: Buffer,
  resolveKey: ManifestKeyResolver,
  now: number = Date.now()
): Promise<VerificationResult> {
  let entries: Map<string, Buffer>;
  try {
    entries = readZip(zipBytes);
  } catch (e) {
    return { valid: false, contentHashVerified: false, checks: [], errors: [`Could not read ZIP: ${(e as Error).message}`], warnings: [], details: {} };
  }

  const manifestName = [...entries.keys()].find(
    (p) => p === 'manifest.json' || p.endsWith('/manifest.json')
  );
  if (!manifestName) {
    return { valid: false, contentHashVerified: false, checks: [], errors: ['No manifest.json found in ZIP archive'], warnings: [], details: {} };
  }

  const manifestJson = entries.get(manifestName)!.toString('utf-8');
  const manifestResult = await verifyManifest(manifestJson, resolveKey, now);
  if (!manifestResult.valid || !manifestResult.manifest) {
    return manifestResult;
  }

  const sig = manifestResult.manifest.cryptographic_signature as { publicKeyFingerprint: string; algorithm: string; publicKeyUrl?: string };
  const key = await resolveKey(sig.publicKeyFingerprint, sig.publicKeyUrl);
  const nodeAlg = sig.algorithm === 'ECDSA-SHA256' ? 'SHA256' : 'RSA-SHA256';

  const checks = [...manifestResult.checks];
  const errors = [...manifestResult.errors];
  const warnings = [...manifestResult.warnings];

  const fileEntries = collectManifestFiles(manifestResult.manifest);
  // The manifest path inside a top-level folder shifts file paths too.
  const prefix = manifestName.includes('/') ? manifestName.slice(0, manifestName.lastIndexOf('/') + 1) : '';
  let filesVerified = 0;

  for (const entry of fileEntries) {
    const bytes = entries.get(entry.filename) ?? entries.get(prefix + entry.filename);
    if (!bytes) {
      checks.push({ name: entry.filename, passed: false, details: 'File not found in ZIP archive' });
      errors.push(`File missing: ${entry.filename}`);
      continue;
    }
    if (sha256Hex(bytes) !== entry.sha256) {
      checks.push({ name: entry.filename, passed: false, details: 'Hash mismatch' });
      errors.push(`File hash mismatch: ${entry.filename}`);
      continue;
    }
    if (entry.signature && key) {
      let ok: boolean;
      try {
        const v = crypto.createVerify(nodeAlg);
        v.update(bytes);
        ok = v.verify(key.pem, entry.signature, 'base64');
      } catch {
        ok = false;
      }
      if (!ok) {
        checks.push({ name: entry.filename, passed: false, details: 'File signature verification failed' });
        errors.push(`File signature failed: ${entry.filename}`);
        continue;
      }
    }
    checks.push({
      name: entry.filename,
      passed: true,
      details: entry.signature ? 'Hash and signature verified' : 'Hash verified (no per-file signature present)',
    });
    filesVerified++;
  }

  const valid = errors.length === 0;
  return {
    valid,
    contentHashVerified: false,
    checks,
    errors,
    warnings,
    details: {
      ...manifestResult.details,
      filesVerified,
      filesTotal: fileEntries.length,
    },
  };
}
