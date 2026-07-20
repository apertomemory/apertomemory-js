/**
 * .amem export container (draft-ferro-apertomemory, Section 7):
 *   {1: export_version, 2: vault-meta, 3: [sealed objects], 4: {object_id: dek_wrapped}}
 * Everything inside is already signed and encrypted; the container adds no cleartext.
 */
import { decodeCbor, encodeCanonical } from "./cbor.js";
import * as K from "./keys.js";
import { openSealed, type OpenedObject } from "./objects.js";
import { bytesToHex, bytesEqual } from "./util.js";

export const EXPORT_VERSION = 1;

interface ScopeEntry { scopeId: Uint8Array; kekWrapped: Uint8Array; ephPub: Uint8Array }

function entries(v: unknown): [unknown, unknown][] {
  if (v instanceof Map) return [...v.entries()];
  if (v && typeof v === "object") return Object.entries(v);
  throw new Error("malformed container: expected map");
}

function get(v: unknown, key: string | number): unknown {
  if (v instanceof Map) return v.get(key);
  if (v && typeof v === "object") return (v as Record<string, unknown>)[String(key)];
  throw new Error("malformed container: expected map");
}

/**
 * Open a .amem export with the user's passphrase.
 * Verifies the passphrase against the stored public key, unwraps each
 * scope KEK and each object DEK, decrypts every object, and verifies
 * every signature against the vault's signing key.
 */
export function readAmem(bytes: Uint8Array, passphrase: string): {
  identity: { signPub: string; kaPub: string; authorKeyId: string };
  scopes: string[];
  objects: (OpenedObject & { scope: string })[];
} {
  const root = decodeCbor(bytes);
  if (get(root, 1) !== EXPORT_VERSION) throw new Error("unsupported export version");

  const meta = get(root, 2);
  const salt = get(meta, "salt") as Uint8Array;
  const signPub = get(meta, "sign_pub") as Uint8Array;
  const identity = K.identityFromMaster(K.masterFromPassphrase(passphrase, salt));
  if (!bytesEqual(identity.signPub, signPub)) throw new Error("wrong passphrase");

  const scopes = new Map<string, ScopeEntry>();
  for (const [name, s] of entries(get(meta, "scopes"))) {
    scopes.set(String(name), {
      scopeId: get(s, "scope_id") as Uint8Array,
      kekWrapped: get(s, "kek_wrapped") as Uint8Array,
      ephPub: get(s, "eph_pub") as Uint8Array,
    });
  }
  const keks = new Map<string, { name: string; kek: Uint8Array }>();
  for (const [name, s] of scopes) {
    const kek = K.unwrapKek(s.kekWrapped, s.ephPub, s.scopeId, identity.kaSeed);
    keks.set(bytesToHex(s.scopeId), { name, kek });
  }

  const deks = new Map<string, Uint8Array>();
  for (const [oid, dw] of entries(get(root, 4))) {
    deks.set(bytesToHex(oid as Uint8Array), dw as Uint8Array);
  }

  const objects: (OpenedObject & { scope: string })[] = [];
  for (const sealed of get(root, 3) as Uint8Array[]) {
    const s = decodeCbor(sealed) as Map<number, unknown>;
    const oidHex = bytesToHex(s.get(1) as Uint8Array);
    const scope = keks.get(bytesToHex(s.get(2) as Uint8Array));
    if (!scope) throw new Error(`no KEK for scope of object ${oidHex}`);
    const dekWrapped = deks.get(oidHex);
    if (!dekWrapped) throw new Error(`no DEK for object ${oidHex}`);
    const dek = K.unwrapDek(dekWrapped, scope.kek);
    objects.push({ ...openSealed(sealed, dek, identity.signPub), scope: scope.name });
  }

  return {
    identity: {
      signPub: bytesToHex(identity.signPub),
      kaPub: bytesToHex(identity.kaPub),
      authorKeyId: bytesToHex(identity.authorKeyId),
    },
    scopes: [...scopes.keys()],
    objects,
  };
}

export { encodeCanonical };
