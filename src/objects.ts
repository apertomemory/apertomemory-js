/**
 * Memory Object seal/open (draft-ferro-apertomemory, Sections 3-4).
 *
 * sealed-object: {1: id, 2: scope_id, 3: version, 4: COSE_Encrypt0(COSE_Sign1(payload))}
 * Sign-then-encrypt: authorship lives inside the ciphertext.
 */
import { encodeCanonical, decodeCbor } from "./cbor.js";
import { encodeSign1, decodeSign1, verifySign1, encodeEnc0, decodeEnc0 } from "./cose.js";
import type { Identity } from "./keys.js";
import { bytesToHex } from "./util.js";

export const FORMAT_VERSION = 1;

export const TYPE: Record<string, number> = { episodic: 1, semantic: 2, procedural: 3 };
export const TRUST: Record<string, number> = { self: 1, trusted: 2, "third-party": 3, unverified: 4 };
const inv = (m: Record<string, number>) =>
  Object.fromEntries(Object.entries(m).map(([k, v]) => [v, k])) as Record<number, string>;
const TYPE_INV = inv(TYPE), TRUST_INV = inv(TRUST);

export interface MemoryObjectInput {
  content: string;
  memType?: "episodic" | "semantic" | "procedural";
  confidence?: number;
  trust?: "self" | "trusted" | "third-party" | "unverified";
  tags?: string[];
  tool?: string;
  created?: number;      // epoch seconds; 0/undefined = now
  objectId?: Uint8Array; // 16B; undefined = random
}

export interface OpenedObject {
  id: string;
  scopeId: string;
  type: string;
  content: string;
  confidence: number;
  provenance: { tool: string; authorKeyId: string };
  trust: string;
  tags: string[];
  created: number;
  signatureVerified: boolean;
}

export function payloadMap(obj: MemoryObjectInput, authorKeyId: Uint8Array): Map<number, unknown> {
  const m = new Map<number, unknown>([
    [1, TYPE[obj.memType ?? "semantic"]],
    [2, obj.content],
    [3, obj.confidence ?? 0.8],
    [4, new Map<number, unknown>([[1, obj.tool ?? "amem-ts/0.1"], [2, authorKeyId]])],
    [5, TRUST[obj.trust ?? "self"]],
    [7, new Map<number, unknown>([[1, obj.created || Math.floor(Date.now() / 1000)]])],
  ]);
  if (obj.tags?.length) m.set(6, obj.tags);
  return m;
}

export interface SealOptions {
  nonce?: Uint8Array; // 12B; test vectors only
  kid?: Uint8Array;   // overrides identity.authorKeyId in the COSE header
}

export function seal(
  obj: MemoryObjectInput, identity: Identity, scopeId: Uint8Array, dek: Uint8Array,
  opts: SealOptions = {},
): { sealed: Uint8Array; objectId: Uint8Array } {
  const objectId = obj.objectId ?? crypto.getRandomValues(new Uint8Array(16));
  const payload = encodeCanonical(payloadMap(obj, identity.authorKeyId));
  const signed = encodeSign1(payload, identity.signSeed, opts.kid ?? identity.authorKeyId);
  const nonce = opts.nonce ?? crypto.getRandomValues(new Uint8Array(12));
  const envelope = encodeEnc0(signed, dek, nonce);
  const sealed = encodeCanonical(new Map<number, unknown>([
    [1, objectId], [2, scopeId], [3, FORMAT_VERSION], [4, envelope],
  ]));
  return { sealed, objectId };
}

export function openSealed(
  sealedCbor: Uint8Array, dek: Uint8Array, expectedSignPub?: Uint8Array,
): OpenedObject {
  const sealed = decodeCbor(sealedCbor) as Map<number, unknown>;
  const version = sealed.get(3) as number;
  if (version !== FORMAT_VERSION) throw new Error(`unsupported format_version ${version}`);
  const signedBytes = decodeEnc0(sealed.get(4) as Uint8Array, dek);
  const inner = decodeSign1(signedBytes);

  let signatureVerified = false;
  if (expectedSignPub) {
    if (!verifySign1(inner, expectedSignPub)) {
      throw new Error("invalid signature: possible tampering");
    }
    signatureVerified = true;
  }

  const p = decodeCbor(inner.payload) as Map<number, unknown>;
  const prov = p.get(4) as Map<number, unknown>;
  const ts = p.get(7) as Map<number, unknown>;
  return {
    id: bytesToHex(sealed.get(1) as Uint8Array),
    scopeId: bytesToHex(sealed.get(2) as Uint8Array),
    type: TYPE_INV[p.get(1) as number] ?? String(p.get(1)),
    content: p.get(2) as string,
    confidence: p.get(3) as number,
    provenance: { tool: prov.get(1) as string, authorKeyId: bytesToHex(prov.get(2) as Uint8Array) },
    trust: TRUST_INV[p.get(5) as number] ?? String(p.get(5)),
    tags: (p.get(6) as string[] | undefined) ?? [],
    created: ts.get(1) as number,
    signatureVerified,
  };
}
