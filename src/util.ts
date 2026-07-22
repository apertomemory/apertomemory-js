export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function concat(...arrs: Uint8Array[]): Uint8Array {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/**
 * Read a key from a CBOR-decoded map WITHOUT assuming its runtime shape.
 * cbor2 decodes integer/byte-keyed maps as Map, text-keyed maps as plain
 * objects, and — critically — an EMPTY map as a plain object too. Assuming
 * `Map` and calling `.get` on such an object throws; that mistake caused two
 * separate DoS bugs (known_keys and empty custody). Route every access to
 * decoded data through here so the assumption cannot recur.
 */
export function mapGet(v: unknown, key: number | string): unknown {
  if (v instanceof Map) return v.get(key);
  if (v && typeof v === "object") return (v as Record<string, unknown>)[String(key)];
  return undefined;
}

/** Iterate a CBOR-decoded map as [key, value] pairs, Map or object alike. */
export function mapEntries(v: unknown): [unknown, unknown][] {
  if (v instanceof Map) return [...v.entries()];
  if (v && typeof v === "object") return Object.entries(v as Record<string, unknown>);
  return [];
}

/** Is this a CBOR map at all (Map or plain object), i.e. not a scalar/bytes? */
export function isCborMap(v: unknown): boolean {
  return v instanceof Map || (!!v && typeof v === "object" && !(v instanceof Uint8Array) && !Array.isArray(v));
}
