/** Full round-trip with fresh random keys, plus tamper detection. */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  masterFromPassphrase, identityFromMaster, newScopeKek, newDek,
  wrapKek, unwrapKek, wrapDek, unwrapDek, seal, openSealed,
} from "../src/index.js";

test("seal -> open round-trip with signature verification", () => {
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
  const out = openSealed(sealed, unwrapDek(dekWrapped, kek2), id.signPub);
  assert.equal(out.content, "prefers concise answers");
  assert.equal(out.signatureVerified, true);
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
  assert.throws(() => openSealed(bad, dek, id.signPub));
});

test("wrong signing key is rejected", () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const id = identityFromMaster(masterFromPassphrase("x", salt));
  const other = identityFromMaster(masterFromPassphrase("y", salt));
  const scopeId = crypto.getRandomValues(new Uint8Array(16));
  const dek = newDek();
  const { sealed } = seal({ content: "hello" }, id, scopeId, dek);
  assert.throws(() => openSealed(sealed, dek, other.signPub), /invalid signature/);
});
