/**
 * Key-primitive conformance and the legacy-v1 guard, against the v2 vectors.
 *
 * The full sealed-object conformance (byte-exact seal, the three MUST-REJECT
 * cases, custody) lives in v2-vectors.test.ts. This file keeps the deterministic
 * key-hierarchy / KEK-wrap checks and the one legacy case (009): reproducing the
 * v1 test vectors byte-for-byte is no longer meaningful, because seal() now emits
 * format_version 2, so those references have been removed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  masterFromPassphrase, identityFromMaster, wrapKek, openSealed,
  hexToBytes as h, bytesToHex,
} from "../src/index.js";

const VEC = JSON.parse(
  readFileSync(new URL("../../test-vectors/v2/apertomemory-v2-test-vectors.json", import.meta.url), "utf8"),
).vectors;

test("001: passphrase -> master -> Ed25519 + X25519 + author_key_id", () => {
  const v = VEC["001-key-hierarchy"];
  const master = masterFromPassphrase(v.input.passphrase, h(v.input.salt));
  assert.equal(bytesToHex(master), v.expect.master);
  const id = identityFromMaster(master);
  assert.equal(bytesToHex(id.signPub), v.expect.sign_pub);
  assert.equal(bytesToHex(id.kaPub), v.expect.ka_pub);
  assert.equal(bytesToHex(id.authorKeyId), v.expect.author_key_id);
});

test("002: ECDH-ES + HKDF + AES-KW reproduces the wrapped KEK", () => {
  const v = VEC["002-kek-wrap"];
  const { kekWrapped, ephPub } = wrapKek(
    h(v.input.kek), h(v.input.ka_pub), h(v.input.scope_id), h(v.input.ephemeral_seed));
  assert.equal(bytesToHex(kekWrapped), v.expect.kek_wrapped);
  assert.equal(bytesToHex(ephPub), v.expect.ephemeral_pub);
});

test("009: a format_version 1 object MUST NOT verify, and opts in as unverified", () => {
  const v = VEC["009-legacy-v1-MUST-NOT-VERIFY"];
  assert.throws(() => openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  }), /.*/);
  const out = openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
    allowUnverified: true,
  });
  assert.equal(out.signatureVerified, false);
  assert.equal(out.trust, v.expect.trust_when_allowed);
});
