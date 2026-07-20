/**
 * Cross-implementation interoperability: a .amem vault exported by the
 * Python reference implementation (apertomemory on PyPI) is opened by
 * this TypeScript implementation, with every signature verified.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readAmem } from "../src/index.js";

test("opens a vault exported by the Python reference implementation", () => {
  const bytes = new Uint8Array(
    readFileSync(new URL("../../test-vectors/interop-python-export.amem", import.meta.url)));
  const vault = readAmem(bytes, "interop test passphrase");

  assert.equal(vault.objects.length, 3);
  assert.deepEqual(vault.scopes.sort(), ["default", "work"]);
  for (const o of vault.objects) {
    assert.equal(o.signatureVerified, true);
    assert.equal(o.provenance.authorKeyId, vault.identity.authorKeyId);
  }
  const contents = vault.objects.map(o => o.content).sort();
  assert.match(contents.join("|"), /formal B2B emails/);
  assert.match(contents.join("|"), /Fridays/);
  const work = vault.objects.filter(o => o.scope === "work");
  assert.equal(work.length, 2);
});

test("wrong passphrase is rejected", () => {
  const bytes = new Uint8Array(
    readFileSync(new URL("../../test-vectors/interop-python-export.amem", import.meta.url)));
  assert.throws(() => readAmem(bytes, "not the passphrase"), /wrong passphrase/);
});
