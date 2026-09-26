# PROJECT — identity-control-plane

## Status

Active. Public remote: `github.com/nurazhardotcom/identity-control-plane`.
This tree is an uncommitted implementation pass; no commit, push, deploy, or
remote-system change is part of the work.

## Layout

```text
identity-control-plane/
├── deps.edn                              # Clojure JVM + cljs.main test deps
├── bb.edn                                # native v0 tasks
├── src/control_plane/
│   ├── json_v1.cljc                     # restricted canonical JSON + UTF-8
│   ├── encoding_v1.cljc                  # strict base64url
│   ├── contract_v1.cljc                  # versioned wire contracts
│   ├── effect.cljc                       # effect ports; no archive impl
│   ├── sidecar_core.cljc                 # pure bearer-token semantics
│   ├── daglog_core.cljc                  # pure v1 core + step verifier
│   ├── sidecar.clj / daglog.clj          # retained native v0 JVM APIs
│   ├── crypto_jvm.clj                    # JCA effect adapter
│   ├── sidecar_jvm.clj                   # synchronous v1 sidecar adapter
│   ├── daglog_jvm.clj                    # synchronous v1 daglog adapter
│   └── webcrypto.cljs                    # async Web Crypto adapter
├── test/control_plane/
│   ├── sidecar_test.clj / daglog_test.clj # preserved native v0 suites
│   ├── v1_test.clj                       # portable JVM known-answer suite
│   ├── webcrypto_test.cljs               # headless Web Crypto suite
│   └── test_runner.clj                   # JVM entry point + shape guard
├── README.md / WIKI.md / SECURITY.md
└── .github/workflows/ci.yml
```

## Verification commands

```bash
bb test
bb demo
clojure -M:test
clojure -M:cljs-test
clj-kondo --lint src test --fail-level warning
```

The exact test counts are reported by the commands rather than hard-coded in
this document.

`clojure -M:test` also fails when a `(deftest` appears in a test source but
does not register as a real test. Clojure's reader absorbs an unbalanced
closing paren into the following form, so a `deftest` nested inside another
`deftest` body is created as an unbound Var with no `:test` metadata and
silently never runs — a green suite with fewer tests than it appears to have.
The declared-versus-registered count check turns that into a hard failure.

## Design contract

- v1 token lifetime is exactly 300 seconds, with valid bearer replay allowed
  before expiry and no consume/replay prevention.
- New portable records use restricted canonical JSON v1 and UTF-8 bytes.
- Legacy `pr-str`/EDN v0 remains only in native/JVM compatibility behavior;
  existing public v0 APIs are retained.
- Chain verification is semantic. Truncation requires an independently
  trusted anchor; anchors also bind exact JSONL bytes.
- No OIDC/JWT claim, reliable memory-wipe claim, R2/Cloudflare resource,
  credential, or upload is included.
- File locking and purge are native/best-effort effects, not portable browser
  guarantees.

## CI

CI runs the preserved native suite, portable JVM tests, headless CLJS/Web
Crypto tests, clj-kondo, and the existing secret scan. The username coherence
check is performed before build/test jobs.
