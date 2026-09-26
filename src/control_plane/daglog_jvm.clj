(ns control-plane.daglog-jvm
  "Synchronous JVM effect adapter for portable daglog v1. JSONL and anchors
  are local exports only; no R2/Cloudflare client or credential is present."
  (:require [control-plane.contract-v1 :as contract]
            [control-plane.crypto-jvm :as crypto]
            [control-plane.daglog-core :as core]
            [control-plane.json-v1 :as json-v1])
  (:import (java.io File RandomAccessFile)
           (java.nio.file Files)))

(defn- summary [log]
  (let [structure (core/verify-structure-v1 log)]
    (when-not (:valid structure)
      (throw (IllegalArgumentException. (str "Invalid daglog structure: " structure))))
    {:entries (count log)
     :head-hash (:head-hash structure)
     :tip-hash (:tip-hash structure)}))

(defn append-entry-v1
  "Append one canonical v1 entry to a vector. `input` is a pure request map
  with :ts-ms, :actor, :action, and optional :details."
  [log key input]
  (let [kb (crypto/key->bytes key)
        prepared (core/entry-body-v1 log input)
        entry-hash (crypto/sha256-hex (:body-bytes prepared))
        entry-hmac (crypto/hmac-sha256-hex
                    kb
                    (json-v1/utf8-code-units-v1
                     (contract/daglog-signing-input-v1 entry-hash)))]
    (conj (vec log)
          (core/finish-append-v1 prepared entry-hash entry-hmac))))

(defn verify-log-v1
  "Verify every v1 sequence, link, canonical-body SHA-256, and HMAC step."
  [log key]
  (crypto/key->bytes key)
  (loop [i 0 previous contract/genesis-prev]
    (if (>= i (count log))
      {:valid true
       :entries i
       :head-hash (if (zero? i) contract/genesis-prev
                      (get (first log) "hash"))
       :tip-hash (if (zero? i) contract/genesis-prev
                      (get (peek log) "hash"))}
      (let [entry (nth log i)
            body (core/body-of-entry-v1 entry)]
        (if-not body
          {:valid false :reason :malformed-entry :at nil}
          (let [body-json (json-v1/canonical-json-v1 body)
                computed-hash (crypto/sha256-hex
                               (json-v1/utf8-code-units-v1 body-json))
                hmac-valid? (crypto/verify-hmac?
                             key
                             (json-v1/utf8-code-units-v1
                              (contract/daglog-signing-input-v1 computed-hash))
                             (get entry "hmac"))
                result (core/verify-entry-step-v1
                        entry {:expected-seq (inc i)
                               :expected-prev-hash previous
                               :computed-hash computed-hash
                               :hmac-valid? hmac-valid?})]
            (if (:valid result)
              (recur (inc i) (get entry "hash"))
              result)))))))

(defn create-anchor-v1
  "Verify a log and create an anchor candidate over the exact canonical JSONL
  bytes. Storing/retrieving that anchor independently is an owner/system
  responsibility; this function does not upload it."
  [log key {:keys [log-id anchored-at-ms]}]
  (let [verification (verify-log-v1 log key)]
    (when-not (:valid verification)
      (throw (IllegalArgumentException. (str "Cannot anchor invalid log: " verification))))
    (let [jsonl (core/log->jsonl-v1 log)
          digest (crypto/sha256-hex (json-v1/utf8-code-units-v1 jsonl))]
      (core/make-anchor-v1 log {:log-id log-id
                                :anchored-at-ms anchored-at-ms
                                :log-sha256 digest}))))

(defn- export-failure
  "Uniform failure result for a JSONL export that cannot be verified.

  A structural break inside an otherwise parseable export is reported with
  its own precise reason and sequence number, matching the v0 recorder's
  `:bad-seq`/`:broken-link` contract. Anything else is reported as
  `:malformed-export` with a `:detail` map, which the Web Crypto adapter
  reproduces exactly."
  [e]
  (let [data (ex-data e)]
    (if (and (= :daglog-v1 (:type data)) (false? (:valid data)))
      (select-keys data [:valid :reason :at])
      {:valid false
       :reason :malformed-export
       :detail (merge {:message (str (.getMessage e))} data)})))

(defn verify-anchor-v1
  "Verify a candidate JSONL export and compare it with a trusted anchor. A
  valid prefix without the independent anchor is not considered complete."
  [anchor key jsonl]
  (try
    (let [log (core/jsonl->log-v1 jsonl)
          verification (verify-log-v1 log key)]
      (if-not (:valid verification)
        verification
        (let [structure (core/verify-structure-v1 log)
              digest (crypto/sha256-hex (json-v1/utf8-code-units-v1 jsonl))]
          (core/verify-anchor-completeness-v1
           anchor (merge (summary log)
                         {:log-sha256 digest
                          :head-hash (:head-hash structure)
                          :tip-hash (:tip-hash structure)})))))
    (catch Exception e (export-failure e))))

(defn export-anchor-v1 [anchor]
  (core/anchor-export-v1 anchor))

(defn export-bundle-v1
  "Return local JSONL, canonical anchor JSON, digests, and a descriptor. The
  descriptor is suitable for a later private endpoint but performs no I/O."
  [log anchor]
  (let [log-jsonl (core/log->jsonl-v1 log)
        anchor-json (core/anchor-export-v1 anchor)
        log-sha (crypto/sha256-hex (json-v1/utf8-code-units-v1 log-jsonl))
        anchor-sha (crypto/sha256-hex
                    (json-v1/utf8-code-units-v1 anchor-json))
        descriptor (core/export-descriptor-v1 log anchor log-sha anchor-sha)]
    {:log-jsonl log-jsonl
     :anchor-json anchor-json
     :descriptor descriptor}))

(defn- read-file-text [file]
  (String. (Files/readAllBytes (.toPath file)) "UTF-8"))

(defn append-jsonl-file-v1!
  "Native JVM file adapter. It serializes writers with a JVM file lock and
  accepts only canonical v1 JSONL; legacy EDN is intentionally not mixed in."
  [path key input]
  (let [kb (crypto/key->bytes key)
        file (File. (str path))]
    (.createNewFile file)
    (with-open [raf (RandomAccessFile. file "rw")
                channel (.getChannel raf)
                _lock (.lock channel)]
      (let [length (.length raf)
            existing-bytes (byte-array length)]
        (.readFully raf existing-bytes)
        (let [existing (if (zero? length)
                         ""
                         (String. existing-bytes "UTF-8"))
              log (if (empty? existing) [] (core/jsonl->canonical-log-v1 existing))
              entry (peek (append-entry-v1 log kb input))]
          (.seek raf (.length raf))
          (.write raf (.getBytes ^String (str (json-v1/canonical-json-v1 entry)
                                               "\n")
                                 "UTF-8"))
          entry)))))

(defn verify-jsonl-file-v1! [path key]
  (let [file (File. (str path))]
    (when-not (.isFile file)
      (throw (IllegalArgumentException. (str "No such v1 JSONL file: " path))))
    (let [jsonl (read-file-text file)
          log (core/jsonl->canonical-log-v1 jsonl)]
      (verify-log-v1 log key))))
