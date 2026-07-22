/**
 * Minimal COSE_Sign1 / COSE_Encrypt0 (RFC 9052/9053), exactly as used by
 * the ApertoMemory format: EdDSA (alg -8) signatures, A256GCM (alg 3)
 * encryption, canonical CBOR throughout.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { gcm } from "@noble/ciphers/aes.js";
import { encodeCanonical, decodeCbor, Tag } from "./cbor.js";

const ALG = 1, KID = 4, IV = 5;
const EDDSA = -8, A256GCM = 3;
const TAG_SIGN1 = 18, TAG_ENC0 = 16;
const EMPTY = new Uint8Array(0);

// ---------- COSE_Sign1 ----------

export function encodeSign1(
  payload: Uint8Array, signSeed: Uint8Array, kid: Uint8Array, externalAad: Uint8Array = EMPTY,
): Uint8Array {
  const phdr = encodeCanonical(new Map<number, unknown>([[ALG, EDDSA], [KID, kid]]));
  const sigStructure = encodeCanonical(["Signature1", phdr, externalAad, payload]);
  const signature = ed25519.sign(sigStructure, signSeed);
  return encodeCanonical(new Tag(TAG_SIGN1, [phdr, new Map(), payload, signature]));
}

export interface Sign1 {
  protectedBytes: Uint8Array;
  kid: Uint8Array | undefined;
  payload: Uint8Array;
  signature: Uint8Array;
}

export function decodeSign1(bytes: Uint8Array): Sign1 {
  const t = decodeCbor(bytes);
  if (!(t instanceof Tag) || t.tag !== TAG_SIGN1) throw new Error("not a COSE_Sign1");
  const [phdr, , payload, signature] = t.contents as [Uint8Array, Map<number, unknown>, Uint8Array, Uint8Array];
  const ph = decodeCbor(phdr) as Map<number, unknown>;
  if (ph.get(ALG) !== EDDSA) throw new Error("unexpected signature algorithm");
  return { protectedBytes: phdr, kid: ph.get(KID) as Uint8Array | undefined, payload, signature };
}

export function verifySign1(msg: Sign1, signPub: Uint8Array, externalAad: Uint8Array = EMPTY): boolean {
  const sigStructure = encodeCanonical(["Signature1", msg.protectedBytes, externalAad, msg.payload]);
  return ed25519.verify(msg.signature, sigStructure, signPub);
}

// ---------- COSE_Encrypt0 ----------

export function encodeEnc0(
  plaintext: Uint8Array, dek: Uint8Array, nonce: Uint8Array, externalAad: Uint8Array = EMPTY,
): Uint8Array {
  if (nonce.length !== 12) throw new Error("nonce must be 96 bits");
  const phdr = encodeCanonical(new Map<number, unknown>([[ALG, A256GCM]]));
  const aad = encodeCanonical(["Encrypt0", phdr, externalAad]);
  const ciphertext = gcm(dek, nonce, aad).encrypt(plaintext);
  return encodeCanonical(new Tag(TAG_ENC0, [phdr, new Map([[IV, nonce]]), ciphertext]));
}

export function decodeEnc0(bytes: Uint8Array, dek: Uint8Array, externalAad: Uint8Array = EMPTY): Uint8Array {
  const t = decodeCbor(bytes);
  if (!(t instanceof Tag) || t.tag !== TAG_ENC0) throw new Error("not a COSE_Encrypt0");
  const [phdr, uhdr, ciphertext] = t.contents as [Uint8Array, Map<number, unknown>, Uint8Array];
  const ph = decodeCbor(phdr) as Map<number, unknown>;
  if (ph.get(ALG) !== A256GCM) throw new Error("unexpected AEAD algorithm");
  const nonce = uhdr.get(IV) as Uint8Array;
  if (!nonce || nonce.length !== 12) throw new Error("missing or invalid IV");
  const aad = encodeCanonical(["Encrypt0", phdr, externalAad]);
  return gcm(dek, nonce, aad).decrypt(ciphertext);
}
