/**
 * Memory Object seal/open — format_version 2 (draft-ferro-apertomemory).
 *
 * sealed-object: {1: id, 2: scope_id, 3: format_version, 4: COSE_Encrypt0(COSE_Sign1(payload))}
 *
 * Two bindings that v1 lacked (both derived from the test vectors, not ported):
 *
 *   Envelope binding — external_aad = canonical CBOR [format_version, id, scope_id]
 *     is fed to BOTH the COSE_Sign1 and the COSE_Encrypt0. Rewriting the cleartext
 *     envelope (id/scope_id) or forcing a version downgrade invalidates the AEAD.
 *
 *   Author binding — the payload's author_key_id MUST equal sha256(verifying key)[:8].
 *     A signer cannot claim an identity it cannot prove. Trust is DERIVED from which
 *     key verified — never read from the payload.
 *
 * Custody (payload key 20): re-sealing changes the signer, so a migrated object's
 * signature proves custody, not authorship. An object with a custody record MUST NOT
 * open as trust="self".
 */
import { encodeCanonical, decodeCbor } from "./cbor.js";
import { encodeSign1, decodeSign1, verifySign1, encodeEnc0, decodeEnc0 } from "./cose.js";
import { keyId, type Identity } from "./keys.js";
import { bytesToHex, hexToBytes, bytesEqual, mapGet, mapEntries, isCborMap } from "./util.js";

export const FORMAT_VERSION = 2;
export const SUPPORTED_VERSIONS = [1, 2];

export const TYPE: Record<string, number> = { episodic: 1, semantic: 2, procedural: 3 };
const inv = (m: Record<string, number>) =>
  Object.fromEntries(Object.entries(m).map(([k, v]) => [v, k])) as Record<number, string>;
const TYPE_INV = inv(TYPE);

// payload key for the (informational) self-declared trust field; trust is derived,
// so this is written for wire-compatibility but never read as authoritative.
const TRUST_SELF = 1;
const CUSTODY = 20;
const KNOWN_PAYLOAD_KEYS = new Set([1, 2, 3, 4, 5, 6, 7, CUSTODY]);

export class SignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignatureError";
  }
}

/** Canonical binding of the cleartext envelope, fed to sign and AEAD. */
export function envelopeAad(version: number, id: Uint8Array, scopeId: Uint8Array): Uint8Array {
  return encodeCanonical([version, id, scopeId]);
}

export interface MemoryObjectInput {
  content: string;
  memType?: "episodic" | "semantic" | "procedural";
  confidence?: number;
  tags?: string[];
  tool?: string;
  created?: number;         // epoch seconds; 0/undefined = now
  objectId?: Uint8Array;    // 16B; undefined = random
  extensions?: Map<number, unknown>; // preserved verbatim (unknown payload keys)
}

export type Authorship = "signed" | "attested" | "unknown";

export interface Provenance {
  tool: string;
  signerKeyId: string | null;      // who signed the object as it stands
  authorKeyId: string | null;      // who wrote it (null when unproven)
  authorship: Authorship;
  claimedAuthorKeyId?: string | null; // present only when authorship = "unknown"
}

export interface OpenedObject {
  id: string;
  scopeId: string;
  formatVersion: number;
  type: string;
  content: string;
  confidence: number | null;   // null when the producer wrote an out-of-range value
  provenance: Provenance;
  trust: "self" | "trusted" | "unverified";
  tags: string[];
  created: number;
  signatureVerified: boolean;
  extensions: Map<number, unknown>;
  schemaViolation?: string;   // set when an authentic object breaks the schema (e.g. confidence)
}

export function payloadMap(obj: MemoryObjectInput, authorKeyId: Uint8Array): Map<number, unknown> {
  if (TYPE[obj.memType ?? "semantic"] === undefined) {
    throw new Error(`unknown memType ${obj.memType}`);
  }
  if (typeof obj.content !== "string" || obj.content.length === 0) {
    throw new Error("content must be a non-empty string");
  }
  const c = obj.confidence ?? 0.8;
  if (!Number.isFinite(c) || c < 0 || c > 1) {
    throw new Error(`confidence out of range [0,1]: ${c}`);
  }
  const m = new Map<number, unknown>([
    [1, TYPE[obj.memType ?? "semantic"]],
    [2, obj.content],
    [3, c],
    [4, new Map<number, unknown>([[1, obj.tool ?? "amem-ts/0.2"], [2, authorKeyId]])],
    [5, TRUST_SELF],                        // informational; trust is derived on read
    [7, new Map<number, unknown>([[1, obj.created || Math.floor(Date.now() / 1000)]])],
  ]);
  if (obj.tags?.length) m.set(6, obj.tags);
  if (obj.extensions) {
    for (const [k, v] of obj.extensions) if (!KNOWN_PAYLOAD_KEYS.has(k)) m.set(k, v);
  }
  return m;
}

export interface SealOptions {
  nonce?: Uint8Array;      // 12B; test vectors only
  custody?: Map<number, unknown>; // set only by migration/quarantine
}

/**
 * Seal an object as format_version 2. The author is always the signing identity:
 * there is no way to declare an author_key_id different from the signer (that was
 * a forgery API in v1 and has been removed).
 */
export function seal(
  obj: MemoryObjectInput, identity: Identity, scopeId: Uint8Array, dek: Uint8Array,
  opts: SealOptions = {},
): { sealed: Uint8Array; objectId: Uint8Array } {
  const objectId = obj.objectId ?? crypto.getRandomValues(new Uint8Array(16));
  const author = keyId(identity.signPub);
  const aad = envelopeAad(FORMAT_VERSION, objectId, scopeId);

  const pm = payloadMap(obj, author);
  if (opts.custody) pm.set(CUSTODY, opts.custody);
  const payload = encodeCanonical(pm);

  const signed = encodeSign1(payload, identity.signSeed, author, aad);
  const nonce = opts.nonce ?? crypto.getRandomValues(new Uint8Array(12));
  const envelope = encodeEnc0(signed, dek, nonce, aad);
  const sealed = encodeCanonical(new Map<number, unknown>([
    [1, objectId], [2, scopeId], [3, FORMAT_VERSION], [4, envelope],
  ]));
  return { sealed, objectId };
}

export interface OpenOptions {
  ownerSignPub?: Uint8Array;             // owner's Ed25519 public key -> trust "self"
  knownKeys?: Record<string, string>;    // { key_id_hex: sign_pub_hex } -> trust "trusted"
  allowUnverified?: boolean;             // opt-in to read what we cannot authenticate
}

/**
 * Decrypt, authenticate, and decode a sealed object. Fail-closed: on any
 * authenticity failure it throws SignatureError and returns no content.
 */
export function openSealed(
  sealedCbor: Uint8Array, dek: Uint8Array, opts: OpenOptions = {},
): OpenedObject {
  const sealed = decodeCbor(sealedCbor);
  if (!isCborMap(sealed) || ![1, 2, 3, 4].every((k) => mapGet(sealed, k) !== undefined)) {
    throw new Error("malformed sealed-object");
  }
  const id = mapGet(sealed, 1) as Uint8Array;
  const scopeId = mapGet(sealed, 2) as Uint8Array;
  const version = mapGet(sealed, 3) as number;
  if (!SUPPORTED_VERSIONS.includes(version)) {
    throw new Error(`unsupported format_version ${version}`);
  }

  // Envelope binding: v2 feeds [version, id, scope_id] as external_aad to the AEAD
  // (and the signature). A rewritten envelope or a forced downgrade fails the tag.
  const aad = version >= 2 ? envelopeAad(version, id, scopeId) : new Uint8Array(0);

  const signedBytes = decodeEnc0(mapGet(sealed, 4) as Uint8Array, dek, aad);
  const inner = decodeSign1(signedBytes);

  const p = decodeCbor(inner.payload);
  if (!isCborMap(p)) throw new Error("malformed payload");
  const prov = mapGet(p, 4);
  const claimedKid = mapGet(prov, 2) as Uint8Array | undefined;
  const custody = mapGet(p, CUSTODY);
  const hasCustody = custody !== undefined;

  // Vector 010: the COSE protected-header kid and the payload author_key_id are
  // BOTH signed. If they disagree the object is self-inconsistent — two consumers
  // reading different fields would attribute it differently — so refuse it.
  if (version >= 2 && inner.kid && claimedKid && !bytesEqual(inner.kid, claimedKid)) {
    throw new SignatureError("header kid does not match payload author_key_id");
  }

  // Candidate keys: owner -> "self", each known key -> "trusted".
  const candidates: Array<{ pub: Uint8Array; level: "self" | "trusted" }> = [];
  if (opts.ownerSignPub) candidates.push({ pub: opts.ownerSignPub, level: "self" });
  for (const pubHex of Object.values(opts.knownKeys ?? {})) {
    candidates.push({ pub: hexToBytes(pubHex), level: "trusted" });
  }

  let verifiedPub: Uint8Array | null = null;
  let signerLevel: "self" | "trusted" | null = null;

  if (version >= 2) {
    for (const { pub, level } of candidates) {
      // Author binding: the payload's author_key_id MUST equal sha256(verifying key)[:8].
      if (!bytesEqual(keyId(pub), claimedKid ?? new Uint8Array(0))) continue;
      if (verifySign1(inner, pub, aad)) { verifiedPub = pub; signerLevel = level; break; }
    }
    if (!verifiedPub && !opts.allowUnverified) {
      throw new SignatureError(
        "object not authenticated: no known key matches its author_key_id, or the signature is invalid",
      );
    }
  } else if (!opts.allowUnverified) {
    // format_version 1 carries no binding and cannot be authenticated.
    throw new SignatureError(
      "format_version 1 carries no envelope/author binding; pass allowUnverified to read it as untrusted",
    );
  }

  const signerKid = verifiedPub ? bytesToHex(keyId(verifiedPub)) : null;
  const tool = mapGet(prov, 1) as string;

  // ---- derive trust + provenance ----------------------------------------
  let trust: "self" | "trusted" | "unverified";
  let provenance: Provenance;

  if (hasCustody) {
    // A custody record is an attestation BY THE CUSTODIAN, and only the vault
    // owner may make one (vector 011): a third party in the keyring must not be
    // able to put words in the owner's mouth. So an attestation counts only when
    // the verified signer is the owner. The signature proves custody, never
    // authorship, so trust is never "self".
    const signerIsOwner = signerLevel === "self";
    const proven = mapGet(custody, 4) as Uint8Array | undefined;   // safe on empty custody (014)
    const provenHex = proven ? bytesToHex(proven) : null;
    const accepted = new Set<string>();
    if (opts.ownerSignPub) accepted.add(bytesToHex(keyId(opts.ownerSignPub)));
    for (const k of Object.keys(opts.knownKeys ?? {})) accepted.add(k);

    if (signerIsOwner && provenHex && accepted.has(provenHex)) {
      trust = "trusted";
      provenance = { tool, signerKeyId: signerKid, authorKeyId: provenHex, authorship: "attested" };
    } else {
      // custody not honoured: non-owner signer (011), unaccepted key (012),
      // or empty/absent field 4 (014). No author may be reported.
      trust = "unverified";
      const claimed = mapGet(custody, 2) as Uint8Array | undefined;
      provenance = {
        tool, signerKeyId: signerKid, authorKeyId: null, authorship: "unknown",
        claimedAuthorKeyId: claimed ? bytesToHex(claimed) : null,
      };
    }
  } else if (verifiedPub) {
    trust = signerLevel === "self" ? "self" : "trusted";
    provenance = { tool, signerKeyId: signerKid, authorKeyId: signerKid, authorship: "signed" };
  } else {
    // unverified (allowUnverified on an object with no custody / v1)
    trust = "unverified";
    provenance = {
      tool, signerKeyId: null, authorKeyId: null, authorship: "unknown",
      claimedAuthorKeyId: claimedKid ? bytesToHex(claimedKid) : null,
    };
  }

  const ts = mapGet(p, 7);
  const extensions = new Map<number, unknown>();
  for (const [k, v] of mapEntries(p)) {
    const kn = typeof k === "number" ? k : Number(k);
    if (!KNOWN_PAYLOAD_KEYS.has(kn)) extensions.set(kn, v);
  }

  // Vector 013: an authentic object may still carry a confidence outside
  // [0,1]. It must not be refused, but the value must not propagate (consumers
  // rank by confidence); report null and flag the schema violation.
  const rawConf = mapGet(p, 3) as number;
  let confidence: number | null = rawConf;
  let schemaViolation: string | undefined;
  if (typeof rawConf !== "number" || !Number.isFinite(rawConf) || rawConf < 0 || rawConf > 1) {
    confidence = null;
    schemaViolation = "confidence out of range";
  }

  return {
    id: bytesToHex(id),
    scopeId: bytesToHex(scopeId),
    formatVersion: version,
    type: TYPE_INV[mapGet(p, 1) as number] ?? String(mapGet(p, 1)),
    content: mapGet(p, 2) as string,
    confidence,
    provenance,
    trust,
    tags: (mapGet(p, 6) as string[] | undefined) ?? [],
    created: mapGet(ts, 1) as number,
    signatureVerified: verifiedPub !== null,
    extensions,
    ...(schemaViolation ? { schemaViolation } : {}),
  };
}
