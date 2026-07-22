# apertomemory (TypeScript)

[![CI](https://github.com/apertomemory/apertomemory-js/actions/workflows/ci.yml/badge.svg)](https://github.com/apertomemory/apertomemory-js/actions/workflows/ci.yml)
[![IETF I-D](https://img.shields.io/badge/IETF-draft--ferro--apertomemory-blue)](https://datatracker.ietf.org/doc/draft-ferro-apertomemory/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

TypeScript implementation of the **ApertoMemory** format: portable,
client-side-encrypted, user-owned AI memory, as specified in the IETF
Internet-Draft
[draft-ferro-apertomemory](https://datatracker.ietf.org/doc/draft-ferro-apertomemory/).

This is the **second implementation** of the format - in a different
language and on an independent cryptographic stack - alongside the
[Python reference implementation](https://github.com/apertomemory/apertomemory).
It implements **format_version 2** and its test suite proves
interoperability in both directions:

- a `format_version` 2 `.amem` vault exported by the Python
  implementation opens here, with each object resolving to the same
  trust level (`self` / `trusted` / `unverified`) the reference reports;
- an object sealed here opens and verifies in the Python implementation;
- re-sealing the official v2 vector reproduces it **byte for byte**, and
  every `MUST-REJECT` vector is refused.

Built on the audited, dependency-light [noble](https://paulmillr.com/noble/)
cryptography stack (pure TypeScript, no native modules) plus
[cbor2](https://github.com/hildjj/cbor2) for RFC 8949 canonical CBOR -
it runs in Node 20+ and in the browser.

## Install

```bash
npm install apertomemory
```

## Usage

Reading a vault (exported with `amem export` from the
[Python CLI](https://github.com/apertomemory/apertomemory), or by any
conforming implementation):

```ts
import { readAmem } from "apertomemory";
import { readFileSync } from "node:fs";

const bytes = new Uint8Array(readFileSync("my-memory.amem"));
const vault = readAmem(bytes, "your passphrase");

for (const o of vault.objects) {
  // trust is DERIVED from which key verified the signature, never declared:
  //   "self"       - authored by you
  //   "trusted"    - authored by a third party in the vault's known_keys
  //   "unverified" - could not be authenticated (only via allowUnverified)
  console.log(o.scope, o.content, o.trust, o.provenance.authorship);
}

// Objects that cannot be authenticated are excluded and listed separately -
// one hostile object never takes down the whole read.
for (const f of vault.failed) console.warn("excluded", f.id, f.error);
```

Sealing and opening single objects with the low-level API:

```ts
import {
  masterFromPassphrase, identityFromMaster,
  newDek, seal, openSealed,
} from "apertomemory";

const salt = crypto.getRandomValues(new Uint8Array(16));
const identity = identityFromMaster(masterFromPassphrase("your passphrase", salt));
const scopeId = crypto.getRandomValues(new Uint8Array(16));
const dek = newDek();

// The author is always the signing identity: there is no way to declare an
// author different from the signer, and no way to declare your own trust.
const { sealed } = seal(
  { content: "prefers concise answers", memType: "semantic", tags: ["style"] },
  identity, scopeId, dek,
);

// Fail-closed: openSealed throws unless the signature verifies under a key you
// supply, and the payload's author_key_id matches that key.
const obj = openSealed(sealed, dek, { ownerSignPub: identity.signPub });
console.log(obj.trust, obj.provenance.authorship); // "self" "signed"
```

New to ApertoMemory? Start from the
[5-minute getting started guide](https://github.com/apertomemory/apertomemory/blob/main/GETTING-STARTED.md) -
vault, CLI, and connecting your AI assistant via MCP.

## format_version 2

Version 2 adds the two bindings version 1 lacked. They are what make the
trust model above trustworthy rather than advisory:

- **Envelope binding.** `external_aad = canonical CBOR [format_version, id,
  scope_id]` is fed to both the COSE_Sign1 and the COSE_Encrypt0. A storage
  server that rewrites the cleartext envelope invalidates the AEAD tag, and a
  version downgrade (2 → 1, to strip the bindings) is detected the same way.
- **Author binding.** The payload's `author_key_id` MUST equal
  `sha256(verifying key)[:8]`. A signer cannot claim an identity it cannot
  prove, so trust can be *derived* from which key verified rather than read
  from the payload.

Migrated third-party memories carry a **custody record**: re-sealing changes
the signer, so the signature proves custody, not authorship. Such objects open
as `trusted` (attested to the proven author) or `unverified` (authorship never
proven) - **never** `self`. `provenance` reports `signerKeyId`, `authorKeyId`
and an `authorship` of `signed` / `attested` / `unknown`.

`format_version` 1 objects carry neither binding; they are readable only under
an explicit `allowUnverified` opt-in and always report `trust = "unverified"`.

## Conformance

The test suite runs against the official test vectors of the
specification (`test-vectors/v2/`):

```bash
npm test
```

Covered: the Argon2id → HKDF-SHA256 → Ed25519/X25519 derivation chain and
`author_key_id` (vector 001), the ECDH-ES + AES-KW key-wrap hierarchy
(vector 002), byte-exact re-sealing of the v2 sealed object (003), the three
`MUST-REJECT` attacks - forged authorship, rewritten envelope, version
downgrade (004-006) - custody-attested and custody-unproven decoding
(007-008), the legacy-v1 non-verification rule (009), and cross-implementation
import of a Python-exported v2 vault across all three trust levels.

## Security

Same status as the reference implementation: standard, well-reviewed
primitives, **no independent audit yet**. Report vulnerabilities
privately - see
[SECURITY.md](https://github.com/apertomemory/apertomemory/blob/main/SECURITY.md)
in the main repository.

## License

MIT - see [LICENSE](LICENSE).
