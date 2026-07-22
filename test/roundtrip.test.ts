/** Full round-trip with fresh random keys, plus tamper detection. (v2 API) */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  masterFromPassphrase, identityFromMaster, newScopeKek, newDek,
  wrapKek, unwrapKek, wrapDek, unwrapDek, seal, openSealed, SignatureError,
} from "../src/index.js";

test("seal -> open round-trip: self / signed / verified", () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const id = identityFromMaster(masterFromPassphrase("test passphrase", salt));
  const scopeId = crypto.getRandomValues(new Uint8Array(16));
  const kek = newScopeKek();
  const { kekWrapped, ephPub } = wrapKek(kek, id.kaPub, scopeId);
  const kek2 = unwrapKek(kekWrapped, ephPub, scopeId, id.kaSeed);
  const dek = newDek();
  const dekWrapped = wrapDek(dek, kek2);

  const { sealed } = seal(
    { content: "prefers concise answers", memType: "semantic", tags: ["style"] },
    id, scopeId, dek);
  const out = openSealed(sealed, unwrapDek(dekWrapped, kek2), { ownerSignPub: id.signPub });
  assert.equal(out.content, "prefers concise answers");
  assert.equal(out.signatureVerified, true);
  assert.equal(out.trust, "self");
  assert.equal(out.provenance.authorship, "signed");
  assert.equal(out.provenance.authorKeyId, out.provenance.signerKeyId);
  assert.deepEqual(out.tags, ["style"]);
});

test("tampered ciphertext fails to open", () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const id = identityFromMaster(masterFromPassphrase("x", salt));
  const scopeId = crypto.getRandomValues(new Uint8Array(16));
  const dek = newDek();
  const { sealed } = seal({ content: "hello" }, id, scopeId, dek);
  const bad = new Uint8Array(sealed);
  bad[bad.length - 1] ^= 0xff;
  assert.throws(() => openSealed(bad, dek, { ownerSignPub: id.signPub }));
});

test("wrong signing key is rejected", () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const id = identityFromMaster(masterFromPassphrase("x", salt));
  const other = identityFromMaster(masterFromPassphrase("y", salt));
  const scopeId = crypto.getRandomValues(new Uint8Array(16));
  const dek = newDek();
  const { sealed } = seal({ content: "hello" }, id, scopeId, dek);
  // wrong key: author_key_id will not match sha256(other.signPub)[:8] -> rejected
  assert.throws(() => openSealed(sealed, dek, { ownerSignPub: other.signPub }), SignatureError);
});

test("opening without any key is fail-closed", () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const id = identityFromMaster(masterFromPassphrase("x", salt));
  const scopeId = crypto.getRandomValues(new Uint8Array(16));
  const dek = newDek();
  const { sealed } = seal({ content: "hello" }, id, scopeId, dek);
  assert.throws(() => openSealed(sealed, dek), SignatureError);
  // explicit opt-in yields unverified, never self
  const out = openSealed(sealed, dek, { allowUnverified: true });
  assert.equal(out.signatureVerified, false);
  assert.equal(out.trust, "unverified");
});

test("envelope binding: rewriting the outer id/scope invalidates the object", () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const id = identityFromMaster(masterFromPassphrase("x", salt));
  const scopeId = crypto.getRandomValues(new Uint8Array(16));
  const dek = newDek();
  const { sealed } = seal({ content: "secret" }, id, scopeId, dek);
  // flip a byte in the outer object id region (offsets 3..18 hold the 16B id)
  const bad = new Uint8Array(sealed);
  bad[4] ^= 0xff;
  assert.throws(() => openSealed(bad, dek, { ownerSignPub: id.signPub }));
});
