/**
 * Conformance suite for format_version 2, driven entirely by the normative
 * vectors in test-vectors/v2/. This file is written against the *vectors*, not
 * against any reference implementation: an implementation is conformant iff it
 * reproduces the deterministic byte strings AND refuses every MUST-REJECT case.
 *
 * Written before the source changes: it is expected to fail across the board
 * until objects.ts/cose.ts implement the two bindings and custody handling.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  masterFromPassphrase, identityFromMaster, wrapKek,
  seal, openSealed, envelopeAad,
  hexToBytes as h, bytesToHex,
} from "../src/index.js";

const VEC = JSON.parse(
  readFileSync(new URL("../../test-vectors/v2/apertomemory-v2-test-vectors.json", import.meta.url), "utf8"),
).vectors;

// ---------------------------------------------------------------------------
// 001 — key hierarchy
// ---------------------------------------------------------------------------
test("001 key-hierarchy: passphrase -> master -> Ed25519/X25519 -> author_key_id", () => {
  const v = VEC["001-key-hierarchy"];
  const master = masterFromPassphrase(v.input.passphrase, h(v.input.salt));
  assert.equal(bytesToHex(master), v.expect.master);
  const id = identityFromMaster(master);
  assert.equal(bytesToHex(id.signPub), v.expect.sign_pub);
  assert.equal(bytesToHex(id.kaPub), v.expect.ka_pub);
  assert.equal(bytesToHex(id.authorKeyId), v.expect.author_key_id);
});

// ---------------------------------------------------------------------------
// 002 — KEK wrap
// ---------------------------------------------------------------------------
test("002 kek-wrap: ECDH-ES + HKDF + AES-KW reproduces the wrapped KEK", () => {
  const v = VEC["002-kek-wrap"];
  const { kekWrapped, ephPub } = wrapKek(
    h(v.input.kek), h(v.input.ka_pub), h(v.input.scope_id), h(v.input.ephemeral_seed),
  );
  assert.equal(bytesToHex(kekWrapped), v.expect.kek_wrapped);
  assert.equal(bytesToHex(ephPub), v.expect.ephemeral_pub);
});

// ---------------------------------------------------------------------------
// 003 — sealed object v2: byte-exact reproduction + correct open
// ---------------------------------------------------------------------------
test("003 sealed-object-v2: external_aad bytes match [version, id, scope_id]", () => {
  const v = VEC["003-sealed-object-v2"];
  const aad = envelopeAad(2, h(v.input.object_id), h(v.input.scope_id));
  assert.equal(bytesToHex(aad), v.expect.external_aad);
});

test("003 sealed-object-v2: seal reproduces the vector byte-for-byte", () => {
  const v = VEC["003-sealed-object-v2"];
  const id = identityFromMaster(masterFromPassphrase(v.input.passphrase, h(v.input.identity_salt)));
  const { sealed } = seal(
    {
      content: v.input.content,
      memType: "semantic",
      confidence: v.input.confidence,
      tags: v.input.tags,
      tool: "amem-cli/0.2",
      created: v.input.created,
      objectId: h(v.input.object_id),
    },
    id,
    h(v.input.scope_id),
    h(v.input.dek),
    { nonce: h(v.input.nonce) },
  );
  assert.equal(bytesToHex(sealed), v.expect.sealed_object);
});

test("003 sealed-object-v2: open yields self / signed / verified", () => {
  const v = VEC["003-sealed-object-v2"];
  const id = identityFromMaster(masterFromPassphrase(v.input.passphrase, h(v.input.identity_salt)));
  const out = openSealed(h(v.expect.sealed_object), h(v.input.dek), { ownerSignPub: id.signPub });
  assert.equal(out.trust, v.expect.trust);
  assert.equal(out.provenance.authorship, v.expect.authorship);
  assert.equal(out.provenance.authorKeyId, v.expect.author_key_id);
  assert.equal(out.signatureVerified, v.expect.signature_verified);
});

// ---------------------------------------------------------------------------
// 004, 005, 006 — MUST-REJECT
// ---------------------------------------------------------------------------
test("004 forged-authorship: MUST reject under every key", () => {
  const v = VEC["004-forged-authorship-MUST-REJECT"];
  // under the owner key
  assert.throws(() => openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  }), /.*/);
  // even under the actual signer key: the payload claims a different author_key_id
  assert.throws(() => openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.signer_sign_pub),
  }), /.*/);
});

test("005 rewritten-envelope: MUST reject (AEAD covers id/scope via external_aad)", () => {
  const v = VEC["005-rewritten-envelope-MUST-REJECT"];
  assert.throws(() => openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  }), /.*/);
});

test("006 version-downgrade: MUST reject (version is inside external_aad)", () => {
  const v = VEC["006-version-downgrade-MUST-REJECT"];
  assert.throws(() => openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  }), /.*/);
});

// ---------------------------------------------------------------------------
// 007, 008 — custody records
// ---------------------------------------------------------------------------
test("007 custody-attested: trusted, attested to the proven author, signed by custodian", () => {
  const v = VEC["007-custody-attested"];
  const out = openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
    knownKeys: v.input.known_keys,
  });
  assert.equal(out.trust, v.expect.trust);                       // trusted
  assert.equal(out.provenance.authorship, v.expect.authorship);  // attested
  assert.equal(out.provenance.authorKeyId, v.expect.author_key_id); // proven author, not signer
  assert.equal(out.provenance.signerKeyId, v.expect.signer_key_id); // the custodian
  assert.notEqual(out.trust, "self");
});

test("008 custody-unproven: unverified, unknown authorship, author_key_id null", () => {
  const v = VEC["008-custody-unproven"];
  const out = openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  });
  assert.equal(out.trust, v.expect.trust);                          // unverified
  assert.equal(out.provenance.authorship, v.expect.authorship);     // unknown
  assert.equal(out.provenance.authorKeyId, v.expect.author_key_id); // null
  assert.equal(out.provenance.claimedAuthorKeyId, v.expect.claimed_author_key_id);
  assert.notEqual(out.trust, "self");
});

// ---------------------------------------------------------------------------
// 009 — legacy v1
// ---------------------------------------------------------------------------
test("009 legacy-v1: MUST NOT verify; readable only under explicit opt-in", () => {
  const v = VEC["009-legacy-v1-MUST-NOT-VERIFY"];
  // without opt-in: rejected
  assert.throws(() => openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  }), /.*/);
  // with opt-in: readable but unverified
  const out = openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
    allowUnverified: true,
  });
  assert.equal(out.trust, v.expect.trust_when_allowed); // unverified
  assert.equal(out.signatureVerified, false);
});

// ---------------------------------------------------------------------------
// 010 — inconsistent kid: header kid contradicts payload author_key_id
// ---------------------------------------------------------------------------
test("010 inconsistent-kid: MUST reject (header kid != payload author_key_id)", () => {
  const v = VEC["010-inconsistent-kid-MUST-REJECT"];
  assert.throws(() => openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  }), /.*/);
});

// ---------------------------------------------------------------------------
// 011 — custody from a non-owner signer MUST NOT be honoured
// ---------------------------------------------------------------------------
test("011 custody-from-non-owner: not honoured -> unverified, no author", () => {
  const v = VEC["011-custody-from-non-owner-MUST-NOT-BE-HONOURED"];
  const out = openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
    knownKeys: v.input.known_keys,
  });
  assert.equal(out.trust, v.expect.trust);                       // unverified
  assert.equal(out.provenance.authorship, v.expect.authorship);  // unknown
  assert.equal(out.provenance.authorKeyId, v.expect.author_key_id); // null
  assert.notEqual(out.trust, "self");
});

// ---------------------------------------------------------------------------
// 012 — custody names a key that is not accepted
// ---------------------------------------------------------------------------
test("012 custody-unaccepted-key: no author reported, not the unaccepted key", () => {
  const v = VEC["012-custody-naming-an-unaccepted-key"];
  const out = openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  });
  assert.equal(out.trust, v.expect.trust);                          // unverified
  assert.equal(out.provenance.authorship, v.expect.authorship);     // unknown
  assert.equal(out.provenance.authorKeyId, v.expect.author_key_id); // null
});

// ---------------------------------------------------------------------------
// 013 — out-of-range confidence: authentic, but the value must not propagate
// ---------------------------------------------------------------------------
test("013 out-of-range-confidence: opens as self, confidence null + flagged", () => {
  const v = VEC["013-out-of-range-confidence"];
  const out = openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  });
  assert.equal(out.trust, v.expect.trust);          // self
  assert.equal(out.confidence, v.expect.confidence); // null
  assert.equal((out as unknown as { schemaViolation?: string }).schemaViolation, v.expect.schema_violation);
});

// ---------------------------------------------------------------------------
// 014 — empty custody map: proves nothing, must not crash
// ---------------------------------------------------------------------------
test("014 empty-custody-map: degrades to unverified, never throws", () => {
  const v = VEC["014-empty-custody-map"];
  const out = openSealed(h(v.input.sealed_object), h(v.input.dek), {
    ownerSignPub: h(v.input.owner_sign_pub),
  });
  assert.equal(out.trust, v.expect.trust);                          // unverified
  assert.equal(out.provenance.authorship, v.expect.authorship);     // unknown
  assert.equal(out.provenance.authorKeyId, v.expect.author_key_id); // null
});
