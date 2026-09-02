/**
 * Minimal read-only ZIP reader. Parses the central directory and inflates
 * entries with Node's built-in `zlib` (DEFLATE) — no external dependency.
 *
 * Scope: STORE (0) and DEFLATE (8) only; ZIP64 and encryption are rejected
 * with a clear error. Sufficient for OES evidence bundles, which are plain
 * ZIPs of evidence files plus a manifest.
 *
 * Hardened against hostile archives: every decompressed entry is capped
 * (`MAX_ENTRY_BYTES`) and the whole archive has a cumulative output budget
 * (`MAX_TOTAL_BYTES`) so a zip bomb fails with a clean error instead of an
 * OOM. All header offsets are bounds-checked, so a truncated or crafted
 * central directory throws a "Corrupt"/"ZIP" error rather than a raw
 * RangeError.
 */
import zlib from 'node:zlib';

const EOCD_SIG = 0x06054b50;
const CDH_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;

/** Per-entry decompressed-size cap. Sized well above any real evidence file. */
const MAX_ENTRY_BYTES = 200 * 1024 * 1024;
/** Cumulative decompressed-size budget across all entries in one archive. */
const MAX_TOTAL_BYTES = 500 * 1024 * 1024;

export interface ZipEntry {
  filename: string;
  /** Decompressed file bytes. */
  bytes: Buffer;
}

function findEocd(buf: Buffer): number {
  if (buf.length < 22) throw new Error('Not a ZIP archive (too small)');
  // EOCD is at the tail; comment can push it back up to 65535 bytes.
  const minOffset = Math.max(0, buf.length - (0xffff + 22));
  for (let i = buf.length - 22; i >= minOffset; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  throw new Error('Not a ZIP archive (no end-of-central-directory record)');
}

/** Read every file entry from a ZIP buffer into a name → bytes map. */
export function readZip(buf: Buffer): Map<string, Buffer> {
  const eocd = findEocd(buf);
  const totalEntries = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);

  if (cdOffset === 0xffffffff || cdSize === 0xffffffff || totalEntries === 0xffff) {
    throw new Error('ZIP64 archives are not supported by this verifier');
  }
  if (cdOffset + cdSize > eocd) {
    throw new Error('Corrupt central directory (out of bounds)');
  }

  const entries = new Map<string, Buffer>();
  let pos = cdOffset;
  let totalInflated = 0;
  for (let i = 0; i < totalEntries; i++) {
    if (pos + 46 > buf.length || buf.readUInt32LE(pos) !== CDH_SIG) {
      throw new Error(`Corrupt central directory at entry ${i}`);
    }
    const flags = buf.readUInt16LE(pos + 8);
    const method = buf.readUInt16LE(pos + 10);
    const compSize = buf.readUInt32LE(pos + 20);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const localOffset = buf.readUInt32LE(pos + 42);
    if (pos + 46 + nameLen > buf.length) {
      throw new Error(`Corrupt central directory entry name at ${i}`);
    }
    const filename = buf.subarray(pos + 46, pos + 46 + nameLen).toString('utf-8');

    if (flags & 0x0001) throw new Error(`Encrypted ZIP entry not supported: ${filename}`);

    if (!filename.endsWith('/')) {
      const bytes = inflateEntry(buf, localOffset, method, compSize, filename);
      totalInflated += bytes.length;
      if (totalInflated > MAX_TOTAL_BYTES) {
        throw new Error('ZIP exceeds the cumulative decompression budget');
      }
      entries.set(filename, bytes);
    }
    pos += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function inflateEntry(
  buf: Buffer,
  localOffset: number,
  method: number,
  compSize: number,
  filename: string
): Buffer {
  if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== LFH_SIG) {
    throw new Error(`Corrupt local header for ${filename}`);
  }
  // Local header name/extra lengths can differ from the central directory's.
  const nameLen = buf.readUInt16LE(localOffset + 26);
  const extraLen = buf.readUInt16LE(localOffset + 28);
  const dataStart = localOffset + 30 + nameLen + extraLen;
  if (dataStart + compSize > buf.length) {
    throw new Error(`Corrupt entry data range for ${filename}`);
  }
  const compressed = buf.subarray(dataStart, dataStart + compSize);

  if (method === 0) {
    if (compressed.length > MAX_ENTRY_BYTES) throw new Error(`ZIP entry too large: ${filename}`);
    return Buffer.from(compressed);
  }
  if (method === 8) return zlib.inflateRawSync(compressed, { maxOutputLength: MAX_ENTRY_BYTES });
  throw new Error(`Unsupported ZIP compression method ${method} for ${filename}`);
}
