(ns control-plane.sidecar-core
  "Pure v1 sidecar semantics: canonical claims, strict bearer-token parsing,
  and the half-open 300-second lifetime check. Cryptography and wall-clock
  access are injected by adapters; this namespace has no mutable token store."
  (:require [clojure.string :as str]
            [control-plane.contract-v1 :as contract]
            [control-plane.encoding-v1 :as encoding]
            [control-plane.json-v1 :as json-v1]))

(defn make-claims-v1
  "Build the exact portable v1 claim object. `issued-at-ms` and `jti` are
  required so deterministic callers and effect adapters remain explicit."
  [{:keys [workload audience issued-at-ms jti]}]
  (let [claims {"v" contract/protocol-version
                "iss" contract/token-issuer
                "sub" workload
                "aud" audience
                "iat_ms" issued-at-ms
                "exp_ms" (+ (long issued-at-ms) contract/token-ttl-ms)
                "jti" jti}]
    (when (contract/valid-token-claims? claims)
      claims)))

(defn token-payload-v1
  "Canonical JSON payload and its portable UTF-8 bytes for a claims map."
  [claims]
  (when (contract/valid-token-claims? claims)
    (let [payload (json-v1/canonical-json-v1 claims)]
      {:payload payload
       :payload-bytes (json-v1/utf8-code-units-v1 payload)
       :payload-b64 (encoding/encode-base64url-v1
                      (json-v1/utf8-code-units-v1 payload))
       :signing-bytes (json-v1/utf8-code-units-v1
                       (contract/token-signing-input-v1 payload))})))

(defn finish-token-v1
  "Finish a prepared token with the adapter-provided 32-byte HMAC result."
  [{:keys [payload-b64]} signature-bytes]
  (when (and (string? payload-b64) (= 32 (count signature-bytes)))
    (str payload-b64 "." (encoding/encode-base64url-v1 signature-bytes))))

(defn parse-token-v1
  "Parse and authenticate-shape-check a v1 token. Signature verification is
  intentionally an injected boolean; this function never consumes or marks
  a token as used."
  [token]
  (when-not (string? token)
    (throw (ex-info "Token must be a string" {:type :malformed-token})))
  (let [parts (str/split token #"\." -1)]
    (when-not (= 2 (count parts))
      (throw (ex-info "Token must contain two base64url parts"
                      {:type :malformed-token})))
    (let [payload (encoding/decode-base64url-v1 (nth parts 0))
          signature (encoding/decode-base64url-v1 (nth parts 1))
          payload-text (json-v1/utf8-decode-v1 payload)
          claims (json-v1/parse-canonical-json-v1 payload-text)]
      (when-not (= 32 (count signature))
        (throw (ex-info "Token signature must be 32 bytes"
                        {:type :malformed-token})))
      (when-not (contract/valid-token-claims? claims)
        (throw (ex-info "Token claims do not match v1 contract"
                        {:type :malformed-token})))
      (when-not (= (+ (long (get claims "iat_ms")) contract/token-ttl-ms)
                   (long (get claims "exp_ms")))
        (throw (ex-info "Token expiry is not exactly 300 seconds"
                        {:type :malformed-token})))
      {:payload payload-text
       :payload-bytes payload
       :signature-bytes signature
       :signing-bytes (json-v1/utf8-code-units-v1
                       (contract/token-signing-input-v1 payload-text))
       :claims claims})))

(defn validate-claims-v1
  "Pure semantic validation. A valid bearer token is reusable on every call
  before `exp_ms`; there is intentionally no consume/replay ledger."
  [claims now-ms expected-aud]
  (cond
    (not (contract/valid-token-claims? claims))
    {:valid false :reason :malformed :claims nil}

    (not (contract/valid-text? expected-aud))
    {:valid false :reason :missing-audience :claims nil}

    (not (contract/valid-ms? now-ms))
    {:valid false :reason :invalid-time :claims nil}

    (not= (+ (long (get claims "iat_ms")) contract/token-ttl-ms)
           (long (get claims "exp_ms")))
    {:valid false :reason :malformed :claims nil}

    (<= (long (get claims "exp_ms")) (long now-ms))
    {:valid false :reason :expired :claims nil}

    (> (long (get claims "iat_ms")) (long now-ms))
    {:valid false :reason :not-yet-valid :claims nil}

    (not= expected-aud (get claims "aud"))
    {:valid false :reason :aud-mismatch :claims nil}

    :else {:valid true :reason nil :claims claims}))
