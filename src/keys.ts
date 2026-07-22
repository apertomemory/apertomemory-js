/**
 * ApertoMemory v1 key hierarchy (draft-ferro-apertomemory, Section 6).
 *
 *   passphrase --Argon2id(m=64MiB,t=3,p=4)--> master secret (32B)
 *   master --HKDF-SHA256--> Ed25519 seed (signing) + X25519 seed (key agreement)
 *   scope KEK (32B random) <-- ECDH-ES(X25519) + HKDF-SHA256 + AES-256-KW -- master
 *   object DEK (32B random, single object) <-- AES-256-KW -- scope KEK
 */
import { argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { aeskw } from "@noble/ciphers/aes.js";
import { utf8, concat } from "./util.js";

export const ARGON2_PARAMS = { t: 3, m: 64 * 1024, p: 4, dkLen: 32 } as const;
export const INFO_SIGN = utf8("apertomemory/v1/sign");
export const INFO_KA = utf8("apertomemory/v1/ka");
export const INFO_KEK_WRAP = utf8("apertomemory/v1/kek-wrap");

export interface Identity {
  signSeed: Uint8Array;   // Ed25519 private seed (32B)
  signPub: Uint8Array;    // Ed25519 public key (32B)
  kaSeed: Uint8Array;     // X25519 private seed (32B)
  kaPub: Uint8Array;      // X25519 public key (32B)
  authorKeyId: Uint8Array; // first 8 bytes of SHA-256(signPub)
}

const hkdf32 = (ikm: Uint8Array, info: Uint8Array): Uint8Array =>
  hkdf(sha256, ikm, undefined, info, 32);

/** author_key_id = first 8 bytes of SHA-256 of the Ed25519 public key. */
export const keyId = (signPub: Uint8Array): Uint8Array => sha256(signPub).slice(0, 8);

export function masterFromPassphrase(passphrase: string, salt: Uint8Array): Uint8Array {
  return argon2id(utf8(passphrase), salt, ARGON2_PARAMS);
}

export function identityFromMaster(master: Uint8Array): Identity {
  const signSeed = hkdf32(master, INFO_SIGN);
  const kaSeed = hkdf32(master, INFO_KA);
  const signPub = ed25519.getPublicKey(signSeed);
  const kaPub = x25519.getPublicKey(kaSeed);
  const authorKeyId = keyId(signPub);
  return { signSeed, signPub, kaSeed, kaPub, authorKeyId };
}

export function newScopeKek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export function newDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/** Wrap a scope KEK towards the user's X25519 key (ECDH-ES + HKDF + AES-KW). */
export function wrapKek(
  kek: Uint8Array, userKaPub: Uint8Array, scopeId: Uint8Array,
  ephemeralSeed?: Uint8Array,
): { kekWrapped: Uint8Array; ephPub: Uint8Array } {
  const eph = ephemeralSeed ?? crypto.getRandomValues(new Uint8Array(32));
  const shared = x25519.getSharedSecret(eph, userKaPub);
  const wk = hkdf32(shared, concat(INFO_KEK_WRAP, scopeId));
  return { kekWrapped: aeskw(wk).encrypt(kek), ephPub: x25519.getPublicKey(eph) };
}

export function unwrapKek(
  kekWrapped: Uint8Array, ephPub: Uint8Array, scopeId: Uint8Array, kaSeed: Uint8Array,
): Uint8Array {
  const shared = x25519.getSharedSecret(kaSeed, ephPub);
  const wk = hkdf32(shared, concat(INFO_KEK_WRAP, scopeId));
  return aeskw(wk).decrypt(kekWrapped);
}

export const wrapDek = (dek: Uint8Array, kek: Uint8Array): Uint8Array =>
  aeskw(kek).encrypt(dek);

export const unwrapDek = (dekWrapped: Uint8Array, kek: Uint8Array): Uint8Array =>
  aeskw(kek).decrypt(dekWrapped);
