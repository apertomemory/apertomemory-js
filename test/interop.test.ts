/**
 * Cross-implementation interoperability.
 *
 * Two fixtures, two roles:
 *
 *  - interop-python-export.amem is a format_version 1 vault exported by the
 *    old Python 0.1.x. Under format_version 2 rules it MUST NOT open as
 *    verified: a v1 object carries no binding. This test used to assert the
 *    opposite; inverting it turns the old interop fixture into a permanent
 *    regression against the very defect v2 closes.
 *
 *  - interop-python-v2-export.amem (NOT YET PRESENT) must be produced by the
 *    Python 0.2.0 reference implementation and dropped into test-vectors/.
 *    The v2 interop test is written below but skipped until that file exists.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { readAmem } from "../src/index.js";
import { decodeCbor, encodeCanonical } from "../src/cbor.js";

const V1_FIXTURE = new URL("../../test-vectors/interop-python-export.amem", import.meta.url);
const V2_FIXTURE = new URL("../../test-vectors/interop-python-v2-export.amem", import.meta.url);

// Rewrite the container with known_keys removed from its metadata. Operates on
// the raw CBOR only; the library code is untouched.
function stripKnownKeys(bytes: Uint8Array): Uint8Array {
  const root = decodeCbor(bytes) as Map<number, unknown>;
  const meta = root.get(2);
  if (meta instanceof Map) meta.delete("known_keys");
  else if (meta && typeof meta === "object") delete (meta as Record<string, unknown>).known_keys;
  return encodeCanonical(root);
}

// Flip a byte inside the first object's sealed bytes so its AEAD tag fails.
function corruptFirstObject(bytes: Uint8Array): Uint8Array {
  const root = decodeCbor(bytes) as Map<number, unknown>;
  const objs = root.get(3) as Uint8Array[];
  const first = new Uint8Array(objs[0]!);
  first[first.length - 1] ^= 0xff;
  objs[0] = first;
  return encodeCanonical(root);
}

// ---------------------------------------------------------------------------
// v1 fixture: now a regression guard. A v1 export MUST NOT verify.
// ---------------------------------------------------------------------------
test("v1 interop export MUST NOT open as verified (format_version 1 has no binding)", () => {
  const bytes = new Uint8Array(readFileSync(V1_FIXTURE));
  // per-object isolation (container rule 2): no container-wide throw, but every
  // v1 object is excluded (goes to `failed`), never returned as verified.
  const vault = readAmem(bytes, "interop test passphrase");
  assert.equal(vault.objects.length, 0, "no v1 object may be returned as verified");
  assert.equal(vault.failed.length, 3);
});

test("v1 interop export under allow_unverified opens as trust=unverified", () => {
  const bytes = new Uint8Array(readFileSync(V1_FIXTURE));
  const vault = readAmem(bytes, "interop test passphrase", { allowUnverified: true });
  assert.equal(vault.objects.length, 3);
  assert.equal(vault.failed.length, 0);
  for (const o of vault.objects) {
    assert.equal(o.signatureVerified, false);
    assert.equal(o.trust, "unverified");
  }
});

test("v1 interop export: wrong passphrase is still rejected first", () => {
  const bytes = new Uint8Array(readFileSync(V1_FIXTURE));
  assert.throws(() => readAmem(bytes, "not the passphrase", { allowUnverified: true }),
    /wrong passphrase/);
});

// ---------------------------------------------------------------------------
// v2 fixture: real cross-impl interop, asserted case-by-case against the
// expected decode in interop-v2-expected.json (three distinct trust outcomes).
// ---------------------------------------------------------------------------
const EXPECTED = new URL("../../test-vectors/interop-v2-expected.json", import.meta.url);
const haveV2 = existsSync(fileURLToPath(V2_FIXTURE)) && existsSync(fileURLToPath(EXPECTED));
const skipV2 = haveV2 ? false
  : "missing fixture: place the Python 0.2.0 export at "
    + "test-vectors/interop-python-v2-export.amem and its expected decode at "
    + "test-vectors/interop-v2-expected.json";

test("v2 interop: every object decodes exactly as interop-v2-expected.json says",
  { skip: skipV2 }, () => {
    const exp = JSON.parse(readFileSync(EXPECTED, "utf8"));
    const bytes = new Uint8Array(readFileSync(V2_FIXTURE));
    const vault = readAmem(bytes, exp.passphrase);

    assert.equal(vault.failed.length, 0, "no object should fail with the full keyring");
    assert.equal(vault.objects.length, Object.keys(exp.objects).length);

    for (const o of vault.objects) {
      const e = exp.objects[o.id];
      assert.ok(e, `unexpected object id ${o.id}`);
      assert.equal(o.content, e.content, `content ${o.id}`);
      assert.equal(o.trust, e.trust, `trust ${o.id}`);
      assert.equal(o.signatureVerified, e.signature_verified, `verified ${o.id}`);
      assert.equal(o.provenance.authorship, e.authorship, `authorship ${o.id}`);
      assert.equal(o.provenance.authorKeyId, e.author_key_id, `author_key_id ${o.id}`);
      assert.equal(o.provenance.signerKeyId, e.signer_key_id, `signer_key_id ${o.id}`);
    }
  });

test("v2 interop: the quarantined hostile object is never self, never owner-authored",
  { skip: skipV2 }, () => {
    const exp = JSON.parse(readFileSync(EXPECTED, "utf8"));
    const bytes = new Uint8Array(readFileSync(V2_FIXTURE));
    const vault = readAmem(bytes, exp.passphrase);

    // locate the object whose expected trust is "unverified" (the hostile one)
    const [hostileId] = Object.entries(exp.objects).find(([, e]) => (e as any).trust === "unverified")!;
    const o = vault.objects.find((x) => x.id === hostileId)!;
    assert.ok(o, "hostile object must still be readable (isolated, not thrown)");

    // the object's signature is genuinely the owner's, but authorship was never proven
    assert.notEqual(o.trust, "self", "provenance-laundering: hostile object reported as self");
    assert.equal(o.trust, "unverified");
    assert.equal(o.provenance.authorship, "unknown");
    assert.equal(o.provenance.authorKeyId, null, "hostile content must not be attributed to anyone");
    assert.notEqual(o.provenance.authorKeyId, vault.identity.authorKeyId,
      "provenance-laundering: hostile content attributed to the owner");
  });

// --- container semantics (README rules 1-3) --------------------------------

test("v2 interop rule 3: with an EMPTY keyring, the attested object degrades to unverified",
  { skip: skipV2 }, () => {
    const exp = JSON.parse(readFileSync(EXPECTED, "utf8"));
    const bytes = new Uint8Array(readFileSync(V2_FIXTURE));

    // strip known_keys from the container metadata before reading
    const stripped = stripKnownKeys(bytes);
    // the attested object can no longer resolve to trusted -> it needs opt-in
    const vault = readAmem(stripped, exp.passphrase, { allowUnverified: true });

    const attestedId = Object.entries(exp.objects).find(([, e]) => (e as any).trust === "trusted")![0];
    const o = vault.objects.find((x) => x.id === attestedId)!;
    assert.ok(o);
    assert.equal(o.trust, "unverified",
      "trust must be evaluated at read time: no keyring => attested degrades to unverified");
    assert.notEqual(o.trust, "trusted");
  });

test("v2 interop rule 2: a corrupt object does not prevent reading the others",
  { skip: skipV2 }, () => {
    const exp = JSON.parse(readFileSync(EXPECTED, "utf8"));
    const bytes = new Uint8Array(readFileSync(V2_FIXTURE));

    const corrupted = corruptFirstObject(bytes);
    const vault = readAmem(corrupted, exp.passphrase);

    assert.equal(vault.failed.length, 1, "the corrupted object must be isolated in `failed`");
    assert.equal(vault.objects.length, Object.keys(exp.objects).length - 1,
      "the remaining objects must still be readable");
  });
