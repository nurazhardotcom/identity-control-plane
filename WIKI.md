# WIKI — identity-control-plane

This repository deliberately has a portable v1 core and a native v0
compatibility surface. The v1 token is a custom HMAC bearer credential, not
OIDC and not a JWT. It is valid for the half-open interval
`[iat_ms, exp_ms)` with an exact 300,000 ms lifetime. Validation is stateless:
a valid token can be replayed until expiry, and no consume/replay-prevention
ledger exists.

## Portable v1 files

- `control-plane.json-v1` — restricted JSON grammar, fixed canonical escaping,
  strict UTF-8 encode/decode, duplicate-name rejection, and safe integers.
- `control-plane.encoding-v1` — strict unpadded base64url over unsigned bytes.
- `control-plane.contract-v1` — versioned token, entry, and trusted-anchor
  shapes plus export media types.
- `control-plane.sidecar-core` — pure claim creation, token parsing, and TTL
  semantics.
- `control-plane.daglog-core` — pure body preparation, canonical JSONL export,
  structure checks, and `verify-entry-step-v1`.
- `control-plane.effect` — clock, crypto, local-store, trusted-anchor, and
  future archive ports. Archive ports have no implementation in this repo.

## Adapters

- `control-plane.sidecar-jvm` / `control-plane.daglog-jvm` use JCA and provide
  synchronous v1 append, verify, anchor, export, and native JSONL file APIs.
- `control-plane.webcrypto` uses asynchronous Web Crypto only. It is usable
  from a browser or headless Node without DOM or Reagent. It returns Promises
  and requires caller-supplied fixed `jti` and timestamps.
- The JVM v1 file writer uses a JVM file lock. That is a native effect and is
  not a browser guarantee.

## v1 wire examples

Token claims are signed inside the custom envelope:

```clojure
{"v" 1 "iss" "identity-control-plane" "sub" "payments-api"
 "aud" "vault:transit" "iat_ms" 1767225600000
 "exp_ms" 1767225900000 "jti" "fixed-jti-v1"}
```

A canonical v1 entry is represented with string names and restricted values:

```clojure
{"action" "vault.read"
 "actor" "payments-api"
 "details" {"path" "transit/sign"}
 "prev_hash" "GENESIS"
 "seq" 1
 "ts_ms" 1767225600000
 "v" 1
 "hash" "22d0146f…"
 "hmac" "d4f8db43…"}
```

The body hash is SHA-256 over the canonical JSON body's UTF-8 bytes. The HMAC
is over `identity-control-plane/daglog/v1\n<hash>`. JSONL export is canonical
UTF-8 text with one record per LF-terminated line. The anchor is separate and
contains the full entry count, head/tip hashes, and SHA-256 of the exact JSONL
bytes.

## What verification proves

1. Token signature, required audience, not-before time, and strict expiry are
   checked. A successful token is not consumed.
2. A daglog step checks exact record shape, sequence, previous link, body
   digest, and HMAC.
3. A chain over a supplied prefix can be valid. **Only an independently trusted
   anchor can establish completeness and detect truncation.**
4. Semantic chain integrity and byte integrity are different: an equivalent
   non-canonical JSONL representation can pass semantic verification but fail
   the anchor's exact-byte digest.
5. Short HMAC keys fail closed. Memory purge is best effort; no reliable JVM or
   browser memory-wipe claim is made.

## Native v0 compatibility

`control-plane.sidecar` and `control-plane.daglog` retain the original JVM
public APIs and v0 behavior for existing callers. v0 uses deep-sorted `pr-str`
and EDN-lines and is supported only in the native/JVM compatibility mode. It
is not used by the portable core and must not be selected for new shared or
browser records. Existing v0 file append/verify behavior is migration-only;
file locking is native-only.

## Export boundary

The v1 APIs can produce a local full-log JSONL bundle, canonical anchor JSON,
and an export descriptor. They do not upload. An external immutable R2 design
may later use a private docs Worker, but this repository intentionally has no
Worker, R2 resource, bucket policy, or credential.

## Gates

```bash
bb test
bb demo
clojure -M:test
clojure -M:cljs-test
clj-kondo --lint src test --fail-level warning
```

The portable suites use fixed public known-answer keys and timestamps. They do
not use secrets, `Math.random`, or wall-clock time in verified paths. The JVM
and Web Crypto suites assert the same vectors, so the adapters must agree
byte for byte.

`clj-kondo --fail-level warning` is the syntax gate for every file. Because a
`deftest` swallowed by an unbalanced delimiter is valid Clojure to the reader
but never runs, each portable runner additionally fails when the number of
`(deftest` forms in its source differs from the number of registered tests.

## Adapter failure contract

Both v1 adapters follow the same rule, and the tests assert it:

- a malformed token, a failed signature, a broken chain, or a rejected export
  **resolves** to `{:valid false :reason ...}`; and
- a caller mistake — missing `:expected-aud`, missing `:now-ms`, or an HMAC
  key under 16 bytes — **rejects** the Promise (JVM: throws).

A rejection never carries a verification verdict, so a caller cannot mistake a
configuration bug for a clean check.
