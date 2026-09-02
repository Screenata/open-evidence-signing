/**
 * Minimal ASN.1 DER reader — just enough to walk an RFC 3161 TimeStampToken
 * and pull out `TSTInfo.messageImprint.hashedMessage`, `genTime`, and
 * `serialNumber`. Read-only; no encoding, no schema validation.
 *
 * Keeping this hand-rolled (instead of pulling in pkijs/asn1js) is what lets
 * the verifier stay zero-dependency while still doing a real RFC 3161 check.
 */

export interface DerNode {
  tag: number;
  /** Class+constructed bit stripped tag number (e.g. 0x10 for SEQUENCE). */
  tagNumber: number;
  constructed: boolean;
  /** Raw content bytes (excludes tag + length header). */
  content: Buffer;
  /** Decoded children, present when `constructed`. */
  children: DerNode[];
}

// Universal tag numbers we care about.
export const TAG = {
  INTEGER: 0x02,
  OCTET_STRING: 0x04,
  OID: 0x06,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x10,
  SET: 0x11,
} as const;

/** Max constructed nesting depth — a real TimeStampToken nests ~6 levels. */
const MAX_DEPTH = 64;

/** Parse one TLV at `offset`. Returns the node and the offset just past it. */
function parseNode(buf: Buffer, offset: number, depth = 0): { node: DerNode; end: number } {
  if (depth > MAX_DEPTH) throw new Error('DER: nesting too deep');
  if (offset >= buf.length) throw new Error('DER: unexpected end of input');
  const tag = buf[offset];
  const constructed = (tag & 0x20) !== 0;
  const tagNumber = tag & 0x1f;

  let pos = offset + 1;
  if (pos >= buf.length) throw new Error('DER: truncated length');
  let length: number;
  const first = buf[pos++];
  if (first < 0x80) {
    length = first;
  } else {
    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 4) throw new Error('DER: unsupported length encoding');
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      if (pos >= buf.length) throw new Error('DER: truncated long length');
      length = length * 256 + buf[pos++];
    }
  }

  const contentStart = pos;
  const contentEnd = contentStart + length;
  if (contentEnd > buf.length) throw new Error('DER: content overruns buffer');
  const content = buf.subarray(contentStart, contentEnd);

  const node: DerNode = { tag, tagNumber, constructed, content, children: [] };
  if (constructed) {
    let inner = 0;
    while (inner < content.length) {
      const { node: child, end } = parseNode(content, inner, depth + 1);
      node.children.push(child);
      inner = end;
    }
  }
  return { node, end: contentEnd };
}

/** Parse a complete DER document (single top-level TLV). */
export function parseDer(buf: Buffer): DerNode {
  return parseNode(buf, 0).node;
}

/** Depth-first iterator over a node and all its descendants. */
export function* walk(node: DerNode): Generator<DerNode> {
  yield node;
  for (const child of node.children) yield* walk(child);
}

/** Decode a GeneralizedTime / UTCTime content buffer to an ISO 8601 string. */
export function decodeAsn1Time(node: DerNode): string | null {
  const raw = node.content.toString('ascii');
  // GeneralizedTime: YYYYMMDDHHMMSS[.fff]Z   UTCTime: YYMMDDHHMMSSZ
  let m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z?$/.exec(raw);
  if (m) {
    const [, y, mo, d, h, mi, s, frac] = m;
    const fracPart = frac ? `.${frac}` : '';
    return `${y}-${mo}-${d}T${h}:${mi}:${s}${fracPart}Z`;
  }
  m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/.exec(raw);
  if (m) {
    const [, yy, mo, d, h, mi, s] = m;
    const year = Number(yy) >= 50 ? `19${yy}` : `20${yy}`;
    return `${year}-${mo}-${d}T${h}:${mi}:${s}Z`;
  }
  return null;
}
