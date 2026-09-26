(ns control-plane.contract-v1
  "Versioned wire contracts for the portable control-plane v1 surface.

  Wire objects use string names and restricted JSON v1 values. These
  predicates are shared by the pure cores and both effect adapters; they do
  not mint, persist, or verify anything."
  (:require [clojure.string :as str]
            [control-plane.json-v1 :as json-v1]))

(def protocol-version 1)
(def token-issuer "identity-control-plane")
(def token-kind "identity-control-plane/sidecar-token/v1")
(def anchor-kind "identity-control-plane/daglog-anchor/v1")
(def genesis-prev "GENESIS")
(def token-ttl-ms 300000)
(def log-media-type "application/x-ndjson; charset=utf-8")
(def anchor-media-type "application/json; charset=utf-8")

(def token-claim-keys
  #{"v" "iss" "sub" "aud" "iat_ms" "exp_ms" "jti"})
(def token-body-keys
  #{"v" "seq" "ts_ms" "actor" "action" "details" "prev_hash"})
(def entry-keys
  #{"v" "seq" "ts_ms" "actor" "action" "details" "prev_hash" "hash" "hmac"})
(def anchor-keys
  #{"v" "kind" "log_id" "entries" "head_hash" "tip_hash" "log_sha256"
    "anchored_at_ms"})

(defn exact-keys? [m expected]
  (and (map? m) (= (set (keys m)) expected)))

(defn valid-text? [x]
  (boolean (and (string? x)
                (json-v1/valid-string? x)
                (not (str/blank? x))
                (not (re-find #"[\u0000-\u001f\u007f]" x)))))

(defn valid-id? [x]
  (boolean (and (string? x) (re-matches #"[A-Za-z0-9][A-Za-z0-9._-]{0,127}" x))))

(defn valid-hash? [x]
  (boolean (and (string? x) (re-matches #"[0-9a-f]{64}" x))))

(defn valid-link? [x]
  (or (= genesis-prev x) (valid-hash? x)))

(defn valid-ms? [x]
  (and (json-v1/safe-integer? x) (>= (long x) 0)))

(defn valid-seq? [x]
  (and (json-v1/safe-integer? x) (pos? (long x))))

(defn valid-token-claims? [claims]
  (boolean
   (and (exact-keys? claims token-claim-keys)
        (= protocol-version (get claims "v"))
        (= token-issuer (get claims "iss"))
        (valid-text? (get claims "sub"))
        (valid-text? (get claims "aud"))
        (valid-id? (get claims "jti"))
        (valid-ms? (get claims "iat_ms"))
        (valid-ms? (get claims "exp_ms")))))

(defn valid-entry-body? [body]
  (boolean
   (and (exact-keys? body token-body-keys)
        (= protocol-version (get body "v"))
        (valid-seq? (get body "seq"))
        (valid-ms? (get body "ts_ms"))
        (valid-text? (get body "actor"))
        (valid-text? (get body "action"))
        (json-v1/valid-value? (get body "details"))
        (valid-link? (get body "prev_hash")))))

(defn valid-entry? [entry]
  (boolean
   (and (exact-keys? entry entry-keys)
        (valid-entry-body? (select-keys entry token-body-keys))
        (valid-hash? (get entry "hash"))
        (valid-hash? (get entry "hmac")))))

(defn valid-anchor? [anchor]
  (boolean
   (and (exact-keys? anchor anchor-keys)
        (= protocol-version (get anchor "v"))
        (= anchor-kind (get anchor "kind"))
        (valid-id? (get anchor "log_id"))
        (valid-seq? (get anchor "entries"))
        (valid-hash? (get anchor "head_hash"))
        (valid-hash? (get anchor "tip_hash"))
        (valid-hash? (get anchor "log_sha256"))
        (valid-ms? (get anchor "anchored_at_ms")))))

(defn token-signing-input-v1 [payload]
  (str "identity-control-plane/sidecar/v1\n" payload))

(defn daglog-signing-input-v1 [entry-hash]
  (str "identity-control-plane/daglog/v1\n" entry-hash))

(defn log-filename-v1 [log-id]
  (when (valid-id? log-id) (str log-id ".jsonl")))

(defn anchor-filename-v1 [log-id]
  (when (valid-id? log-id) (str log-id ".anchor-v1.json")))

(defn valid-export-descriptor? [descriptor]
  (boolean
   (and (exact-keys? descriptor #{"v" "log" "anchor"})
        (= protocol-version (get descriptor "v"))
        (map? (get descriptor "log"))
        (map? (get descriptor "anchor"))
        (= #{"filename" "media_type" "entries" "sha256"}
           (set (keys (get descriptor "log"))))
        (= #{"filename" "media_type" "sha256"}
           (set (keys (get descriptor "anchor"))))
        (= log-media-type (get-in descriptor ["log" "media_type"]))
        (= anchor-media-type (get-in descriptor ["anchor" "media_type"]))
        (valid-text? (get-in descriptor ["log" "filename"]))
        (valid-text? (get-in descriptor ["anchor" "filename"]))
        (valid-seq? (get-in descriptor ["log" "entries"]))
        (valid-hash? (get-in descriptor ["log" "sha256"]))
        (valid-hash? (get-in descriptor ["anchor" "sha256"])))))
