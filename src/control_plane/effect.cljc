(ns control-plane.effect
  "Small effect ports used by the portable cores.

  Cores never import a filesystem, cloud client, clock, or random source.
  Adapters may return a host Promise for asynchronous ports. The archive
  ports below are contracts only: this repository contains no R2, Cloudflare,
  Worker, credential, or upload implementation.")

(defprotocol CryptoPort
  (sha256-hex [this input-bytes]
    "Return lowercase SHA-256 hex for an unsigned-byte sequence.")
  (hmac-sha256-hex [this key-bytes input-bytes]
    "Return lowercase HMAC-SHA-256 hex for an unsigned-byte sequence."))

(defprotocol ClockPort
  (now-ms [this]
    "Return current epoch milliseconds; callers/tests may inject fixed values."))

(defprotocol JsonlStorePort
  (read-jsonl-bytes [this]
    "Read a complete JSONL export as unsigned bytes.")
  (append-jsonl-bytes! [this bytes]
    "Append bytes under the adapter's native consistency mechanism."))

(defprotocol TrustedAnchorPort
  (read-trusted-anchor [this log-id]
    "Read an independently trusted anchor; return nil when absent."))

(defprotocol ImmutableArchivePort
  (put-jsonl! [this export-descriptor bytes]
    "Future private endpoint port for a full JSONL export. No implementation here.")
  (put-anchor! [this export-descriptor bytes]
    "Future private endpoint port for an anchor export. No implementation here."))
