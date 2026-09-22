# identity-control-plane — Non-Human Identity & Machine Control Planes

> **Status:** Active — maintained. See [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

[![CI](https://github.com/nurazhardotcom/identity-control-plane/actions/workflows/ci.yml/badge.svg)](https://github.com/nurazhardotcom/identity-control-plane/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

Zero-npm, Babashka (`bb`) + Clojure control plane for machine
identities: an ephemeral credential sidecar (OIDC-style token exchange
with a strict 300-second TTL and memory purge on expiry) plus a
hash-chained, HMAC-signed transaction log (daglog) that makes every
machine action tamper-evident.

## Problem Statement

Workloads authenticate with static secrets that leak, linger, and
cannot be revoked granularly — while the audit trail of what those
workloads *did* is a mutable log file. This toolkit replaces both: short-
lived HMAC-signed workload tokens that die after 300 seconds with
their memory zeroed, and an append-only daglog where each entry's hash
chains to its predecessor and carries an HMAC signature, so forgery,
reordering, or truncation is detected at the exact sequence number.

## Architecture Design

- `src/control_plane/sidecar.clj` — ephemeral credential generator:
  - `issue-token` mints `base64url(payload).base64url(HMAC-SHA256)` for
    `{:workload :aud}`, `:exp = :iat + 300`, storing the token material
    as a `char[]` keyed by `:jti` (never interned `String`s, which the
    JVM cannot wipe).
  - `validate-token` checks structure → signature (constant-time
    compare) → strict TTL (`[iat, exp)`: at `now == exp` the token is
    already expired) → audience; any failure returns
    `{:valid false :reason ...}`, never throws.
  - Immediate purge: validating an expired token zeroes and drops its
    material; `purge-expired!` sweeps the store; keys shorter than 16
    bytes are refused at both issue and verify time.
- `src/control_plane/daglog.clj` — tamper-evident recorder:
  - Each entry seals `{:seq :ts :actor :action :details :prev-hash}`
    with `:hash = SHA-256(canonical-body)` and
    `:hmac = HMAC-SHA-256(hash)`; genesis links to `"GENESIS"`.
  - `verify-chain` recomputes sequence, link, hash, and HMAC per entry
    and reports `{:valid false :reason :at}` at the first break.
  - File mode appends EDN lines (`load-log`/`append-to-file!`);
    `entry->json` renders entries as JSON. Recording keys come from
    `$CONTROL_PLANE_HMAC_KEY` — the recorder refuses to run without it.
- Determinism: demos and tests inject fixed keys/timestamps; no wall
  clock in any verified path.

## 1-Line Verification Command

```bash
bb test
```

## Usage

```bash
bb test                                                     # run the TTL + HMAC test suite
bb demo                                                     # deterministic sidecar + daglog transcript
export CONTROL_PLANE_HMAC_KEY='a-secret-of-16-bytes-minimum'
bb daglog append ./daglog.edn payments-api vault.read '{:path "transit/sign"}'
bb daglog verify ./daglog.edn                               # exit 0 valid, 1 tampered
```

## License

MIT ©2026 Nur Azhar — see [LICENSE](LICENSE). Built with AI assistance under human direction — see [AI_DISCLOSURE.md](AI_DISCLOSURE.md).
