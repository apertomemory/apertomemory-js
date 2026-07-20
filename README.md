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

Reading a vault (exported with `amem export` from the
[Python CLI](https://github.com/apertomemory/apertomemory), or by any
conforming implementation):

```ts
import { readAmem } from "apertomemory";
import { readFileSync } from "node:fs";

const bytes = new Uint8Array(readFileSync("my-memory.amem"));
const vault = readAmem(bytes, "your passphrase");

for (const o of vault.objects) {
  console.log(o.scope, o.content, o.signatureVerified); // true - always checked
}
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

const { sealed } = seal(
  { content: "prefers concise answers", memType: "semantic", tags: ["style"] },
  identity, scopeId, dek,
);

const obj = openSealed(sealed, dek, identity.signPub); // throws on tampering or wrong key
```

New to ApertoMemory? Start from the
[5-minute getting started guide](https://github.com/apertomemory/apertomemory/blob/main/GETTING-STARTED.md) -
vault, CLI, and connecting your AI assistant via MCP.

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
