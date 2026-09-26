# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| latest `main` | yes |
| older tags | no — upgrade and re-test |

## Reporting a vulnerability

Open a private security advisory through the repository's **Security** tab.
Do not file a public issue for a suspected vulnerability. Include the affected
file/commit, reproduction steps, and impact assessment. Expect an initial
response within 7 days.

## Security model and limits

- The v1 sidecar token is a custom HMAC-SHA-256 bearer credential. It is not
  OIDC and is not a JWT. Its exact lifetime is 300 seconds, but successful
  validation does not consume it. Anyone who obtains a valid token may replay
  it until `exp_ms`; this repository intentionally has no replay-prevention
  or single-use ledger.
- A daglog chain proves the integrity of the records supplied to it. A valid
  prefix can pass chain verification. Completeness and truncation detection
  require comparison with an independently trusted anchor containing the full
  count, head/tip hashes, and exact JSONL byte digest.
- Canonical JSON v1 is restricted to safe integers, strings, vectors, and
  string-keyed maps. UTF-8 bytes are authenticated. Semantic equivalence and
  byte identity are intentionally distinguished; the anchor protects the
  export bytes. The safe-integer range is checked against the decimal text
  before conversion, so a host that cannot represent an integer exactly — a
  JavaScript double above 2^53 — rejects it instead of rounding it.
- Verification is fail-closed. An export that is unparseable, missing its
  final LF, blank, contract-invalid, or chain-inconsistent is rejected, and a
  short HMAC key or a malformed hex signature is refused rather than coerced.
- HMAC keys must be at least 16 bytes. Callers own key lifecycle and
  distribution. The JVM adapters do not claim reliable erasure of strings,
  GC copies, byte-array copies, or JCA internals. Legacy purge is best effort
  only. Browser storage and JavaScript memory are not wipeable guarantees.
- File locking is implemented only by the native JVM file adapter. It is not
  available or implied by the shared core or Web Crypto adapter.
- The repository contains no R2 bucket, Cloudflare Worker, cloud credential,
  or upload client. Export descriptors and JSONL/anchor bytes are local
  contracts for a possible future private endpoint; this code does not upload
  them.
- HMAC authenticates writers who possess the key. It does not provide
  non-repudiation, confidentiality, authorization policy, or protection from
  an attacker who can rewrite both a log and its trusted anchor.

Never commit real HMAC keys, exported production logs, or anchor material.
The fixed strings in tests are public known-answer vectors only.
