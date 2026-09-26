# identity-control-plane — portable workload credentials and tamper-evident logs

> **Status:** Active — maintained. See [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

[![CI](https://github.com/nurazhardotcom/identity-control-plane/actions/workflows/ci.yml/badge.svg)](https://github.com/nurazhardotcom/identity-control-plane/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

A small Clojure/ Babashka control plane with two explicitly separated
surfaces:

- a **portable v1** core for a custom HMAC-SHA-256 bearer credential and a
  restricted canonical JSON v1 daglog; and
- a **native JVM v0 compatibility surface** retained for existing callers.

The v1 token is not an OIDC token and the envelope is not a JWT. It has a
strict half-open lifetime of **300 seconds**: valid at `iat <= now < exp`,
expired at `now == exp`. A successful validation is reusable; there is no
consume operation, nonce ledger, or replay prevention. Possession of a valid
bearer token is therefore replayable until expiry.

## v1 contracts

`control-plane.contract-v1` defines exact, string-keyed records:

- sidecar claims: `v`, issuer, subject, audience, millisecond issue/expiry,
  and `jti`;
- daglog entries: `v`, sequence, millisecond timestamp, actor, action,
  restricted details, previous hash, body hash, and HMAC; and
- trusted anchors: log id, entry count, head/tip hashes, the SHA-256 of the
  exact JSONL UTF-8 bytes, and an anchored timestamp.

The JSON v1 value grammar is deliberately restricted to `null`, booleans,
Unicode-scalar strings, safe integers, vectors, and string-keyed maps. Object
names are ordered by Unicode scalar value. Serialization has fixed escaping,
rejects floats/keywords/unpaired surrogates, and hashes the resulting UTF-8
bytes. The same pure code runs on the JVM and in ClojureScript.

## Architecture and honest boundaries

- `src/control_plane/json_v1.cljc`, `encoding_v1.cljc`, and
  `contract_v1.cljc` contain portable value, UTF-8, base64url, and contract
  logic.
- `src/control_plane/sidecar_core.cljc` and `daglog_core.cljc` are pure
  claim/chain logic. `daglog_core/verify-entry-step-v1` is a pure per-record
  step verifier; adapters supply the digest and HMAC effect results.
- `src/control_plane/effect.cljc` declares clock, crypto, local-store,
  trusted-anchor, and future archive ports. The archive ports are contracts
  only; this repository has no Worker, R2, Cloudflare resource, credential,
  or upload implementation. No namespace in the portable core requires
  `effect.cljc` or a crypto adapter, and a test asserts that.
- Both adapters resolve a malformed token or a broken record to a
  `{:valid false :reason ...}` result and **reject** the returned Promise for
  configuration errors such as a missing `:expected-aud`, a missing
  `:now-ms`, or an HMAC key under 16 bytes. A rejection always means a
  caller mistake, never a verification verdict.
- `src/control_plane/sidecar_jvm.clj`, `crypto_jvm.clj`, and
  `daglog_jvm.clj` are synchronous JVM adapters. The JVM v1 file adapter
  serializes writers with a native JVM file lock.
- `src/control_plane/webcrypto.cljs` is an asynchronous Web Crypto adapter.
  Its headless tests use no DOM, Reagent, network, filesystem, or random
  source. It uses caller-supplied fixed ids and timestamps.

### Integrity claims

- A chain verifies **semantic record integrity**: sequence, previous link,
  canonical body digest, and HMAC for every supplied record.
- A valid prefix is still a valid chain. **Truncation is detected only when
  the result is checked against an independently trusted anchor.** The anchor
  also binds the exact JSONL export bytes, so a whitespace-only change can
  preserve semantic verification but fail byte-integrity verification.
- The v1 readers are fail-closed. A JSONL export that is unparseable, is
  missing its final LF, contains a blank record, violates the entry contract,
  or breaks the sequence/prev-hash chain is rejected rather than returned as
  a log. Both adapters translate that rejection into a precise `:reason`.
- HMAC keys of at least 16 bytes are required. Keys are caller-owned; JVM
  memory, garbage-collected copies, strings, and crypto-provider internals
  cannot be reliably wiped. Any legacy purge is best effort only.
- File locking is a JVM/native effect, not a browser or ClojureScript
  guarantee.

## JSONL and anchor exports

`daglog-core/log->jsonl-v1` produces one canonical JSON object per line with a
final LF. JVM and Web Crypto adapters can also create an anchor and a local
bundle containing:

- the full log JSONL;
- canonical anchor JSON;
- SHA-256 digests and filenames/media types; and
- an `export-descriptor-v1` suitable for a later private docs endpoint.

These are local export contracts only. Nothing is uploaded here. A future
private Worker may use the descriptor to place the full log and anchor in
immutable storage, but credentials and bucket policy must remain outside this
repository.

## Native v0 compatibility

The existing `control-plane.sidecar` and `control-plane.daglog` JVM public
namespaces and APIs remain source-compatible. Their v0 format is deep-sorted
`pr-str` plus EDN-lines and is a **native/JVM compatibility mode only**. It
is not a portable v1 writer and new browser/shared integrations must not use
it. The old append/file APIs are retained solely for migration compatibility;
new records should use the v1 adapters and canonical JSONL export.

The old sidecar store is not a replay-prevention mechanism. The old file
recorder's lock is native-only. The old verification result detects edits,
reordering, and broken links, but a chain alone does not prove that a log has
not been truncated.

## Verification commands

```bash
# Native Babashka compatibility suite (existing v0 tests)
bb test
bb demo

# JVM portable v1 suite
clojure -M:test

# Headless ClojureScript + Web Crypto suite (Node Web Crypto)
clojure -M:cljs-test

# Static analysis
clj-kondo --lint src test --fail-level warning
```

The fixed test key `0123456789abcdef0123456789abcdef` and timestamps in the
portable tests are public known-answer vectors, not secrets. No test uses
`Math.random`, wall-clock time in a verified path, or an external service.
The same vectors are asserted on both the JVM and Web Crypto adapters, so the
two must produce byte-identical tokens, digests, and export descriptors.

Both portable suites also assert that every `(deftest` in their source
actually registered as a test. Clojure's reader absorbs an unbalanced closing
paren into the following form, which nests a `deftest` inside another
`deftest` body: the var is created without `:test` metadata and silently
never runs, producing a green suite with fewer tests than it appears to
have. `clj-kondo --fail-level warning` is the syntax gate, and the runners
fail independently on a declared-versus-registered count mismatch.

## License

MIT ©2026 Nur Azhar — see [LICENSE](LICENSE). Built with AI assistance under
human direction; see [AI_DISCLOSURE.md](AI_DISCLOSURE.md).
