# WIKI — identity-control-plane (Non-Human Identity & Machine Control Planes)

Zero-npm Babashka + Clojure control plane for machine identities: an ephemeral
credential sidecar (OIDC-style token exchange, strict 300s TTL, memory purge on
expiry) plus a hash-chained, HMAC-signed transaction log (daglog).

## Architecture

- `src/control_plane/sidecar.clj` — ephemeral credential generator.
  - `issue-token` mints `base64url(payload).base64url(HMAC-SHA256)` claims
    `{:iss :sub :aud :iat :exp :jti}` with `:exp = :iat + 300`; token material
    stored as `char[]` keyed by `:jti` (never interned Strings).
  - `validate-token`: structure → constant-time signature compare →
    strict TTL (`[iat, exp)`: at `now == exp` already expired) →
    mandatory audience (`:expected-aud` required, omission throws);
    token failures return `{:valid false :reason ...}`, never throw.
  - `purge!` / `purge-expired!` / `reset-store!` zero (`\u0000` fill) and drop
    materials; validating an expired token purges immediately. Only the
    store-held copy is wipeable — caller-held token `String`s are immutable.
  - Keys < 16 bytes refused at issue and verify time.
- `src/control_plane/daglog.clj` — tamper-evident recorder.
  - Each entry seals `{:seq :ts :actor :action :details :prev-hash}` with
    `:hash = SHA-256(canonical-body)` and `:hmac = HMAC-SHA-256(hash)`;
    genesis links to `"GENESIS"`; canonical form is `pr-str` of deep-sorted map.
  - `verify-chain` recomputes sequence, link, hash, HMAC per entry, reporting
    `{:valid false :reason :at}` at the first break.
  - File mode appends EDN lines under an exclusive file lock and
    verifies in a streaming pass (`verify-log-file`); recording keys come
    from `$CONTROL_PLANE_HMAC_KEY` — the recorder refuses to run without it.
- `bb.edn` — `test` (TTL + HMAC suite), `demo` (deterministic transcript),
  `daglog` (append/verify CLI). Demos/tests inject fixed keys and timestamps;
  no wall clock in any verified path.

## EDN log schemas

Sidecar claims (inside the signed payload):

```clojure
{:iss "identity-control-plane" :sub "payments-api" :aud "vault:transit"
 :iat 1767225600 :exp 1767225900 :jti "demo-jti-0001"}
```

Daglog entry (one EDN line per entry in file mode):

```clojure
{:seq 3 :ts "2026-09-22T00:00:03Z" :actor "payments-api"
 :action "vault.read" :details {:path "transit/sign"}
 :prev-hash "9f2c…" :hash "a41d…" :hmac "77be…"}
```

## Fail-closed security gates

1. Expired, tampered, malformed, not-yet-valid, or audience-mismatched tokens
   never validate; expired material is zeroed on the spot.
2. Short HMAC keys (< 16 bytes) throw at both issue and verify time.
3. Daglog verification recomputes every link/hash/HMAC; any forgery, reorder,
   or truncation fails at the exact sequence number.
4. Recorder refuses to run without `$CONTROL_PLANE_HMAC_KEY` — no default key,
   no unsigned log.
5. `validate-token` requires `:expected-aud` — the audience is always
   checked, never silently skipped.

## 1-line verification

```bash
bb test
```

Expected: 16 tests, 75 assertions, 0 failures, 0 errors, exit 0.

## Cloud IAM & Security Automation linkage

- Sidecar models the workload-identity exchange remote Cloud IAM automation
  performs (short-lived OIDC-style tokens instead of static secrets); the
  300s TTL + memory purge is the executable policy for non-human credential
  lifetime.
- Daglog is the tamper-evident machine-action trail: every automated IAM
  mutation can be appended (`bb daglog append …`) and later verified
  (`bb daglog verify …`, exit 0/1) by auditors or a remote gate.
- `bb demo` gives a deterministic transcript for runbooks; `entry->json`
  renders entries for SIEM/evidence ingestion.
