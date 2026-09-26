(ns control-plane.webcrypto
  "Async Web Crypto effect adapter for the portable v1 cores.

  This namespace uses only Web Crypto, typed arrays, Promises, and pure data;
  it has no DOM, Reagent, filesystem, network, R2, or Worker code. Node's
  Web Crypto implementation is used by the headless test runner. A valid
  bearer token is reusable until its strict 300000 ms expiry: there is no
  consume operation and no replay-prevention ledger.

  Failure semantics deliberately match `control-plane.sidecar-jvm` and
  `control-plane.daglog-jvm`:

  - configuration errors (missing `:now-ms`, missing/blank `:expected-aud`,
    a missing or too-short HMAC key) REJECT the returned Promise; and
  - a malformed token, a failed signature check, or a broken chain RESOLVES
    to a `{:valid false :reason ...}` result.

  Nothing here uploads anything. Export bundles and export descriptors are
  local contracts for a possible future private endpoint."
  (:require [clojure.string :as str]
            [control-plane.contract-v1 :as contract]
            [control-plane.daglog-core :as daglog]
            [control-plane.json-v1 :as json]
            [control-plane.sidecar-core :as sidecar]))

(def min-key-bytes 16)

(defn- fail!
  [message]
  (throw (js/Error. message)))

(defn- crypto-object
  "Return the ambient Web Crypto object or fail. There is no polyfill: an
  absent SubtleCrypto is a configuration error, never a silent downgrade."
  []
  (let [c (.-crypto (.-globalThis js/globalThis))]
    (when-not (and c (some? (.-subtle c)))
      (fail! "Web Crypto SubtleCrypto is unavailable"))
    c))

(defn- uint8-bytes
  "Portable unsigned-byte vector to a Uint8Array.

   Idempotent on a Uint8Array: `hex->uint8-bytes` already returns one, and
   re-wrapping it with `count`/`nth` fails because a typed array implements
   neither protocol."
  [xs]
  (if (instance? js/Uint8Array xs)
    xs
    (let [arr (js/Uint8Array. (count xs))]
      (dotimes [i (count xs)]
        (aset arr i (bit-and (long (nth xs i)) 0xFF)))
      arr)))

(defn- key->bytes
  "Accept a Uint8Array, a portable unsigned-byte sequence, or UTF-8 text.
  Keys shorter than 16 bytes fail closed; this is a configuration error."
  [key]
  (let [b (cond
            (instance? js/Uint8Array key) key
            (string? key) (uint8-bytes (json/utf8-code-units-v1 key))
            (sequential? key) (uint8-bytes key)
            :else (fail! "HMAC key must be UTF-8 text or unsigned bytes"))]
    (when (< (.-length b) min-key-bytes)
      (fail! (str "HMAC key must be >= " min-key-bytes " bytes")))
    b))

(defn- array-buffer->vector
  [buffer]
  (vec (array-seq (js/Uint8Array. buffer))))

(def ^:private hex-nibbles
  (into {} (map-indexed (fn [i c] [c i]) "0123456789abcdef")))

(def ^:private hex-digits "0123456789abcdef")

(defn- bytes->hex
  "Lowercase hexadecimal for an ArrayBuffer, computed without a host
  formatter so the output cannot depend on locale or platform."
  ^string [buffer]
  (let [arr (js/Uint8Array. buffer)]
    (str/join
     (map (fn [i]
            (let [b (bit-and (long (aget arr i)) 0xFF)
                  hi (bit-shift-right b 4)
                  lo (bit-and b 0x0F)]
              (str (subs hex-digits hi (inc hi))
                   (subs hex-digits lo (inc lo)))))
          (range (.-length arr))))))

(defn- hex->uint8-bytes
  "Strict lowercase hexadecimal to a Uint8Array. Uppercase digits, an odd
  length, an empty string, and unknown characters are rejected."
  [s]
  (when-not (and (string? s) (pos? (count s)) (even? (count s)))
    (fail! "Invalid hexadecimal HMAC"))
  (let [out (js/Uint8Array. (/ (count s) 2))]
    (dotimes [i (/ (count s) 2)]
      ;; Byte i is the pair (2i, 2i+1). The high nibble is
      ;; (subs s 2i (inc 2i)) and the low nibble is (subs s (inc 2i) (+ 2i 2)).
      ;; Reading the low nibble as (subs s (inc 2i) (inc 2i)) yields an empty
      ;; string, so the digit lookup always returned nil and every signature
      ;; failed closed with "Invalid hexadecimal HMAC".
      (let [hi (get hex-nibbles (subs s (* 2 i) (inc (* 2 i))))
            lo (get hex-nibbles (subs s (inc (* 2 i)) (+ (* 2 i) 2)))]
        (when (or (nil? hi) (nil? lo))
          (fail! "Invalid hexadecimal HMAC"))
        (aset out i (bit-or (bit-shift-left hi 4) lo))))
    out))

(defn- import-hmac
  [key]
  (let [subtle (.-subtle (crypto-object))]
    (.importKey subtle "raw" (key->bytes key)
                #js {"name" "HMAC" "hash" "SHA-256"}
                false #js ["sign" "verify"])))

(defn- digest-hex
  "Promise for lowercase SHA-256 hex over a portable unsigned-byte vector."
  [input]
  (.then (.digest (.-subtle (crypto-object)) "SHA-256" (uint8-bytes input))
        bytes->hex))

(defn- hmac-sign
  "Promise for the raw HMAC-SHA-256 bytes over a portable byte vector."
  [key input]
  (-> (import-hmac key)
      (.then (fn [crypto-key]
               (.sign (.-subtle (crypto-object)) "HMAC" crypto-key
                      (uint8-bytes input))))
      (.then array-buffer->vector)))

(defn- hmac-verify?
  "Promise for a boolean. Web Crypto verification is over the raw signature
  bytes, so no hex-string comparison happens in this adapter."
  [key input signature]
  (-> (import-hmac key)
      (.then (fn [crypto-key]
               (.verify (.-subtle (crypto-object)) "HMAC" crypto-key
                        (uint8-bytes signature) (uint8-bytes input))))))

(defn- now-required
  "Fixed caller-supplied time. This adapter never reads a wall clock, so
  verification paths stay deterministic in tests and reviews."
  [options]
  (let [now (get options :now-ms)]
    (when-not (contract/valid-ms? now)
      (fail! "Web Crypto validation requires a fixed :now-ms"))
    now))

(defn issue-token-v1
  "Return a Promise for a custom HMAC bearer token. No random source is used;
  callers supply `:jti` and `:issued-at-ms`. Configuration errors reject."
  [{:keys [workload audience issued-at-ms jti key]}]
  (try
    (let [claims (sidecar/make-claims-v1 {:workload workload
                                          :audience audience
                                          :issued-at-ms issued-at-ms
                                          :jti jti})]
      (when-not claims
        (fail! "Invalid v1 token claims: workload, audience, issued-at-ms, and jti are required"))
      (let [prepared (sidecar/token-payload-v1 claims)]
        (-> (hmac-sign key (:signing-bytes prepared))
            (.then (fn [signature]
                     {:token (sidecar/finish-token-v1 prepared signature)
                      :jti jti
                      :expires-at-ms (get claims "exp_ms")
                      :claims claims})))))
    (catch :default e (js/Promise.reject e))))

(defn- parse-token-safely
  "Shape-check a token without letting a parse failure escape. Returns nil
  for every malformed token, matching the synchronous JVM adapter."
  [token]
  (try
    (sidecar/parse-token-v1 token)
    (catch :default _ nil)))

(defn validate-token-v1
  "Return a Promise for signature plus semantic validation.

  This never consumes a token: repeated valid calls before `exp_ms` are
  expected and are asserted by the test suite. Configuration errors reject;
  a malformed token resolves to `:malformed` and a bad signature to
  `:bad-signature`."
  [token key {:keys [expected-aud] :as options}]
  (try
    (let [now-ms (now-required options)
          _ (when-not (contract/valid-text? expected-aud)
              (fail! "validate-token-v1 requires a non-blank :expected-aud"))
          _ (key->bytes key)
          parsed (parse-token-safely token)]
      (if-not parsed
        (js/Promise.resolve {:valid false :reason :malformed :claims nil})
        (-> (hmac-verify? key (:signing-bytes parsed) (:signature-bytes parsed))
            (.then (fn [signature-valid?]
                     (if (true? signature-valid?)
                       (sidecar/validate-claims-v1 (:claims parsed) now-ms expected-aud)
                       {:valid false :reason :bad-signature :claims nil}))))))
    (catch :default e (js/Promise.reject e))))

(defn- signing-bytes-for
  "Portable signing input for a daglog entry hash."
  [entry-hash]
  (json/utf8-code-units-v1 (contract/daglog-signing-input-v1 entry-hash)))

(defn- verify-entry-after-hash
  "Second half of one step: HMAC over the computed digest, then the pure
  per-record step verifier."
  [entry state key computed-hash]
  (let [signature-hex (get entry "hmac")]
    (if-not (contract/valid-hash? signature-hex)
      (js/Promise.resolve
       (daglog/verify-entry-step-v1
        entry (assoc state :computed-hash computed-hash :hmac-valid? false)))
      (-> (hmac-verify? key (signing-bytes-for computed-hash)
                        (hex->uint8-bytes signature-hex))
          (.then (fn [hmac-valid?]
                   (daglog/verify-entry-step-v1
                    entry {:expected-seq (:expected-seq state)
                           :expected-prev-hash (:expected-prev-hash state)
                           :computed-hash computed-hash
                           :hmac-valid? hmac-valid?})))))))

(defn- verify-entry
  "First half of one step: body digest, then the HMAC step."
  [entry state key]
  (if-not (contract/valid-entry? entry)
    (js/Promise.resolve
     (daglog/verify-entry-step-v1
      entry {:expected-seq (:expected-seq state)
             :expected-prev-hash (:expected-prev-hash state)
             :computed-hash nil
             :hmac-valid? false}))
    (let [body (daglog/body-of-entry-v1 entry)]
      (-> (digest-hex (json/utf8-code-units-v1 (json/canonical-json-v1 body)))
          (.then (fn [computed-hash]
                   (verify-entry-after-hash entry state key computed-hash)))))))

(defn- finish-append
  [log prepared entry-hash key]
  (-> (hmac-sign key (signing-bytes-for entry-hash))
      (.then (fn [signature]
               (conj (vec log)
                     (daglog/finish-append-v1
                      prepared entry-hash (bytes->hex (uint8-bytes signature))))))))

(defn append-entry-v1
  "Return a Promise for a new log vector after appending one v1 record.
  The log must be a vector of valid v1 entries; `input` is a pure request
  map with :ts-ms, :actor, :action, and optional :details."
  [log key input]
  (try
    (let [prepared (daglog/entry-body-v1 log input)]
      (-> (digest-hex (:body-bytes prepared))
          (.then (fn [entry-hash]
                   (finish-append log prepared entry-hash key)))))
    (catch :default e (js/Promise.reject e))))

;; The loop state and the per-step map share one key name. The previous code
;; called it :expected-prev in the loop but built :expected-prev-hash for the
;; step, so the step verifier always received a nil previous hash and reported
;; :broken-link for a perfectly valid chain.
(def genesis-state
  {:expected-seq 1
   :expected-prev-hash contract/genesis-prev
   :index 0
   :valid true})

(defn- advance
  [state entry result]
  (if (:valid result)
    {:expected-seq (inc (:expected-seq state))
     :expected-prev-hash (get entry "hash")
     :index (inc (:index state))
     :valid true}
    result))

(defn- verify-entry-at
  "Sequential step. The loop is written as recursion over one live promise
  at a time instead of a pre-built chain, so a large log does not allocate
  one pending promise per entry."
  [log key state]
  (if (or (not (:valid state))
          (>= (:index state) (count log)))
    (js/Promise.resolve state)
    (let [entry (nth log (:index state))
          step {:expected-seq (:expected-seq state)
                :expected-prev-hash (:expected-prev-hash state)}]
      (-> (verify-entry entry step key)
          (.then (fn [result]
                   (verify-entry-at log key (advance state entry result))))))))

(defn- log-summary
  "Structure summary shared by anchor creation and anchor comparison."
  [log]
  (let [structure (daglog/verify-structure-v1 log)]
    (when-not (:valid structure)
      (fail! "Invalid daglog structure"))
    {:entries (count log)
     :head-hash (:head-hash structure)
     :tip-hash (:tip-hash structure)}))

(defn verify-log-v1
  "Return a Promise for a complete per-entry verification of sequence,
  previous link, canonical body digest, and HMAC. A valid prefix can still
  pass; only a trusted anchor establishes completeness."
  [log key]
  (try
    (-> (verify-entry-at log key genesis-state)
        (.then (fn [state]
                 (if (:valid state)
                   {:valid true
                    :entries (:index state)
                    :head-hash (if (zero? (:index state))
                                 contract/genesis-prev
                                 (get (first log) "hash"))
                    :tip-hash (if (zero? (:index state))
                                contract/genesis-prev
                                (get (peek log) "hash"))}
                   state))))
    (catch :default e (js/Promise.reject e))))

(defn create-anchor-v1
  "Return a Promise for an anchor candidate over the exact canonical JSONL
  bytes of a fully verified log. Storing or trusting that anchor is an
  owner/system responsibility; this performs no upload."
  [log key {:keys [log-id anchored-at-ms]}]
  (-> (verify-log-v1 log key)
      (.then (fn [verification]
               (when-not (:valid verification)
                 (fail! "Cannot anchor an invalid log"))
               (let [jsonl (daglog/log->jsonl-v1 log)]
                 (-> (digest-hex (json/utf8-code-units-v1 jsonl))
                     (.then (fn [log-sha256]
                              (daglog/make-anchor-v1
                               log {:log-id log-id
                                    :anchored-at-ms anchored-at-ms
                                    :log-sha256 log-sha256})))))))))

(defn- compare-anchor
  [anchor log jsonl]
  (-> (digest-hex (json/utf8-code-units-v1 jsonl))
      (.then (fn [log-sha256]
               (daglog/verify-anchor-completeness-v1
                anchor (merge (log-summary log) {:log-sha256 log-sha256}))))))

(defn- export-failure
  "Uniform failure result for a JSONL export that cannot be verified.

  A structural break inside an otherwise parseable export is reported with
  its own precise reason and sequence number. Anything else is reported as
  `:malformed-export` with a `:detail` map, which the JVM adapter reproduces
  exactly."
  [e]
  (let [data (ex-data e)]
    (if (and (= :daglog-v1 (:type data)) (false? (:valid data)))
      (select-keys data [:valid :reason :at])
      {:valid false
       :reason :malformed-export
       :detail (merge {:message (.-message e)} data)})))

(defn verify-anchor-v1
  "Return a Promise comparing a candidate JSONL export with an independently
  trusted anchor. An unverifiable export resolves to the same
  `{:valid false :reason ...}` shapes the JVM adapter returns; configuration
  errors reject."
  [anchor key jsonl]
  (try
    (let [log (daglog/jsonl->log-v1 jsonl)]
      (-> (verify-log-v1 log key)
          (.then (fn [verification]
                   (if-not (:valid verification)
                     verification
                     (compare-anchor anchor log jsonl))))))
    (catch :default e
      (js/Promise.resolve (export-failure e)))))

(defn export-bundle-v1
  "Return a Promise for local JSONL text, canonical anchor JSON, and an
  `export-descriptor-v1`. This is a local contract only; nothing is
  uploaded and no cloud credential exists in this repository."
  [log anchor]
  (let [log-jsonl (daglog/log->jsonl-v1 log)
        anchor-json (daglog/anchor-export-v1 anchor)]
    (-> (digest-hex (json/utf8-code-units-v1 log-jsonl))
        (.then (fn [log-sha]
                 (-> (digest-hex (json/utf8-code-units-v1 anchor-json))
                     (.then (fn [anchor-sha]
                              {:log-jsonl log-jsonl
                               :anchor-json anchor-json
                               :descriptor (daglog/export-descriptor-v1
                                            log anchor log-sha anchor-sha)}))))))))
