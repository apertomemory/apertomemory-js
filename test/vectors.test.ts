/** Conformance against the official test vectors — byte-exact where the spec is deterministic. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  masterFromPassphrase, identityFromMaster, wrapKek, unwrapKek, wrapDek, unwrapDek,
  seal, openSealed, decodeSign1, verifySign1, decodeEnc0,
  hexToBytes as h, bytesToHex,
} from "../src/index.js";
import { decodeCbor, encodeCanonical } from "../src/cbor.js";

const tv1 = JSON.parse(readFileSync(new URL("../../test-vectors/amem-testvector-001.json", import.meta.url), "utf8"));
const tv2 = JSON.parse(readFileSync(new URL("../../test-vectors/amem-testvector-002.json", import.meta.url), "utf8"));

test("TV001: key derivation chain from passphrase", () => {
  const master = masterFromPassphrase(tv1.kdf.passphrase, h(tv1.kdf.salt_hex));
  assert.equal(bytesToHex(master), tv1.kdf.master_secret_hex);
  const id = identityFromMaster(master);
  assert.equal(bytesToHex(id.signSeed), tv1.ed25519.seed_hex);
  assert.equal(bytesToHex(id.signPub), tv1.ed25519.public_hex);
  assert.equal(bytesToHex(id.authorKeyId), tv1.ed25519.author_key_id_hex);
});

test("TV001: decrypt, verify and decode the sealed object", () => {
  const sealed = h(tv1.sealed_object_cbor_hex);
  const out = openSealed(sealed, h(tv1.dek_hex), h(tv1.ed25519.public_hex));
  assert.equal(out.signatureVerified, true);
  assert.equal(out.type, "semantic");
  assert.equal(out.trust, "self");
  assert.match(out.content, /email B2B formali/);
  // the decrypted COSE_Sign1 must be byte-identical to the vector
  const s = decodeCbor(sealed) as Map<number, unknown>;
  const signed = decodeEnc0(s.get(4) as Uint8Array, h(tv1.dek_hex));
  assert.equal(bytesToHex(signed), tv1.cose_sign1_hex);
  const inner = decodeSign1(signed);
  assert.equal(bytesToHex(inner.payload), tv1.payload_cbor_hex);
  assert.equal(verifySign1(inner, h(tv1.ed25519.public_hex)), true);
});

test("TV001: re-seal reproduces the vector byte-for-byte", () => {
  const payload = decodeCbor(h(tv1.payload_cbor_hex)) as Map<number, unknown>;
  const prov = payload.get(4) as Map<number, unknown>;
  const created = (payload.get(7) as Map<number, unknown>).get(1) as number;
  const inner = decodeSign1(h(tv1.cose_sign1_hex));
  const sealedRef = decodeCbor(h(tv1.sealed_object_cbor_hex)) as Map<number, unknown>;
  const id = identityFromMaster(masterFromPassphrase(tv1.kdf.passphrase, h(tv1.kdf.salt_hex)));

  const { sealed } = seal(
    {
      content: payload.get(2) as string,
      memType: "semantic",
      confidence: payload.get(3) as number,
      trust: "self",
      tags: payload.get(6) as string[],
      tool: prov.get(1) as string,
      created,
      objectId: sealedRef.get(1) as Uint8Array,
    },
    id,
    sealedRef.get(2) as Uint8Array,
    h(tv1.dek_hex),
    { nonce: h(tv1.nonce_hex), kid: inner.kid },
  );
  assert.equal(bytesToHex(sealed), tv1.sealed_object_cbor_hex);
});

test("TV002: KEK/DEK wrap chain matches", () => {
  const scopeId = h(tv2.scope_id_hex);
  const { kekWrapped, ephPub } = wrapKek(
    h(tv2.kek_hex), h(tv2.x25519.user_pub_hex), scopeId, h(tv2.x25519.ephemeral_seed_hex));
  assert.equal(bytesToHex(kekWrapped), tv2.kek_wrapped_hex);
  assert.equal(bytesToHex(ephPub), tv2.x25519.ephemeral_pub_hex);
  const kek = unwrapKek(h(tv2.kek_wrapped_hex), h(tv2.x25519.ephemeral_pub_hex), scopeId, h(tv2.x25519.user_seed_hex));
  assert.equal(bytesToHex(kek), tv2.kek_hex);
  assert.equal(bytesToHex(wrapDek(h(tv2.dek_hex), kek)), tv2.dek_wrapped_hex);
  assert.equal(bytesToHex(unwrapDek(h(tv2.dek_wrapped_hex), kek)), tv2.dek_hex);
});

test("TV001 payload: canonical re-encode is byte-identical", () => {
  const p = decodeCbor(h(tv1.payload_cbor_hex));
  assert.equal(bytesToHex(encodeCanonical(p)), tv1.payload_cbor_hex);
});
