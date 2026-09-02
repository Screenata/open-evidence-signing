import { describe, it, expect } from 'vitest';
import { canonicalize, sortKeys } from '../canonical';

describe('canonicalize (sorted-keys-2space, spec §4.2)', () => {
  it('sorts keys recursively and indents with 2 spaces', () => {
    const out = canonicalize({ b: 1, a: { d: 2, c: 3 } }).toString('utf-8');
    expect(out).toBe('{\n  "a": {\n    "c": 3,\n    "d": 2\n  },\n  "b": 1\n}');
  });

  it('produces identical bytes regardless of key insertion order', () => {
    const a = canonicalize({ a: { c: 3, d: 2 }, b: 1 });
    const b = canonicalize({ b: 1, a: { d: 2, c: 3 } });
    expect(a.equals(b)).toBe(true);
  });

  it('preserves array order', () => {
    expect(sortKeys([3, 1, 2])).toEqual([3, 1, 2]);
  });

  it('is UTF-8 encoded', () => {
    const out = canonicalize({ title: 'café — résumé' });
    expect(out).toBeInstanceOf(Buffer);
    expect(out.toString('utf-8')).toContain('café — résumé');
  });
});
