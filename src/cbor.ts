import { encode, decode, Tag } from "cbor2";
import { sortCoreDeterministic } from "cbor2/sorts";

/** Canonical CBOR per RFC 8949 §4.2 (core deterministic encoding). */
export function encodeCanonical(value: unknown): Uint8Array {
  return encode(value, { sortKeys: sortCoreDeterministic });
}

/** Decode CBOR. Integer/byte-keyed maps decode as Map; text-keyed as objects. */
export function decodeCbor(bytes: Uint8Array): unknown {
  return decode(bytes);
}

export { Tag };
