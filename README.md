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
Its test suite proves interoperability in both directions:

- a `.amem` vault exported by the Python implementation opens here,
  with every Ed25519 signature verified;
- an object sealed here opens and verifies in the Python implementation;
- re-sealing the official test vector reproduces it **byte for byte**.

Built on the audited, dependency-light [noble](https://paulmillr.com/noble/)
cryptography stack (pure TypeScript, no native modules) plus
[cbor2](https://github.com/hildjj/cbor2) for RFC 8949 canonical CBOR -
it runs in Node 20+ and in the browser.

## Install

```bash
npm install apertomemory
```

## Usage

```ts
import {
  masterFromPassphrase, identityFromMaster,
  newScopeKek, newDek, wrapKek, wrapDek,
  seal, openSealed, readAmem,
} from "apertomemory";

// derive identity from a passphrase
const salt = crypto.getRandomValues(new Uint8Array(16));
const identity = identityFromMaster(masterFromPassphrase("my passphrase", salt));

// seal a memory (sign-then-encrypt: Ed25519 inside AES-256-GCM)
const scopeId = crypto.getRandomValues(new Uint8Array(16));
const dek = newDek();
const { sealed } = seal(
  { content: "prefers concise answers", memType: "semantic", tags: ["style"] },
  identity, scopeId, dek,
);

// open and verify
const obj = openSealed(sealed, dek, identity.signPub);
// obj.signatureVerified === true

// open a full .amem export (from any conforming implementation)
const vault = readAmem(amemFileBytes, "my passphrase");
// vault.objects[i].content, .scope, .signatureVerified ...
```

## Conformance

The test suite runs against the official test vectors of the
specification (`test-vectors/`):

```bash
npm test
```

Covered: the Argon2id -> HKDF-SHA256 -> Ed25519/X25519 derivation chain
(vector 001), the ECDH-ES + AES-KW key-wrap hierarchy (vector 002),
byte-exact canonical CBOR re-encoding, byte-exact re-sealing of vector
001, tamper detection, and cross-implementation import of a
Python-exported vault.

## Security

Same status as the reference implementation: standard, well-reviewed
primitives, **no independent audit yet**. Report vulnerabilities
privately - see
[SECURITY.md](https://github.com/apertomemory/apertomemory/blob/main/SECURITY.md)
in the main repository.

## License

MIT - see [LICENSE](LICENSE).
