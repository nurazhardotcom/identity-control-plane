# PROJECT — identity-control-plane

## Status

Active. Local only — NO remote repo exists yet
(`nurazhardotcom/identity-control-plane` does not resolve; verified 2026-09-22).
Test harness: PASSING — `bb test` exits 0 (8 tests, 46 assertions,
0 failures, 0 errors; verified 2026-09-22).

## Layout

```text
identity-control-plane/
├── bb.edn                              # test / demo / daglog tasks
├── README.md                           # problem statement + CLI usage
├── WIKI.md                             # architecture, schemas, fail-closed gates
├── PROJECT.md                          # this file
├── src/control_plane/sidecar.clj       # ephemeral credential sidecar
├── src/control_plane/daglog.clj        # hash-chained HMAC-signed log
└── test/control_plane/sidecar_test.clj # TTL + HMAC verification suite
```

## Verification commands

```bash
bb test                                                     # suite, exit 0
bb demo                                                     # deterministic transcript
export CONTROL_PLANE_HMAC_KEY='a-secret-of-16-bytes-minimum'
bb daglog append ./daglog.edn payments-api vault.read '{:path "transit/sign"}'
bb daglog verify ./daglog.edn                               # exit 0 valid, 1 tampered
```

## Test-harness contract

`bb.edn` `test` task explicitly `(require 'control-plane.sidecar-test)`
before `clojure.test/run-tests` and exits non-zero when failures + errors > 0.
Time-sensitive tests must inject fixed `:now` — never wall clock.

## Next steps

- Create + push public remote `nurazhardotcom/identity-control-plane`
  (excluded from the archive script).
- Add daglog `verify-chain` negative tests (reorder/truncate fixtures) if the
  recorder gains new entry fields.
