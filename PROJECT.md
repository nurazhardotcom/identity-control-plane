# PROJECT — identity-control-plane

## Status

Active. Public remote: github.com/nurazhardotcom/identity-control-plane
(origin/main; verified 2026-09-22).
Test harness: PASSING — `bb test` exits 0 (16 tests, 75 assertions,
0 failures, 0 errors; verified 2026-09-23).

## Layout

```text
identity-control-plane/
├── bb.edn                              # test / demo / daglog tasks
├── README.md                           # problem statement + CLI usage
├── WIKI.md                             # architecture, schemas, fail-closed gates
├── PROJECT.md                          # this file
├── src/control_plane/sidecar.clj       # ephemeral credential sidecar
├── src/control_plane/daglog.clj        # hash-chained HMAC-signed log
├── test/control_plane/sidecar_test.clj # TTL + HMAC verification suite
└── test/control_plane/daglog_test.clj  # chain + file verify suite
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

`bb.edn` `test` task explicitly `(require 'control-plane.sidecar-test
'control-plane.daglog-test)` before `clojure.test/run-tests` and exits
non-zero when failures + errors > 0.
Time-sensitive tests must inject fixed `:now` — never wall clock.

## Next steps

- None pending for Phase 1 — remote live, `verify-chain` negative tests
  (reorder/truncate fixtures) and CI green.
