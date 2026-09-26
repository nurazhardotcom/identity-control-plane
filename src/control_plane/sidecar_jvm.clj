(ns control-plane.sidecar-jvm
  "Synchronous JVM adapter for the pure sidecar v1 core. It does not keep a
  token registry: a valid token is a reusable bearer credential until its
  exact 300000 ms expiry. No reliable memory-wipe claim is made."
  (:require [control-plane.contract-v1 :as contract]
            [control-plane.crypto-jvm :as crypto]
            [control-plane.effect :as effect]
            [control-plane.sidecar-core :as core]))

(defn- now-from [options]
  (let [{:keys [now-ms clock]} options]
    (cond
      (some? now-ms) now-ms
      (some? clock) (effect/now-ms clock)
      :else (throw (IllegalArgumentException.
                    "validate-token-v1 requires :now-ms or :clock")))))

(defn issue-token-v1
  "Issue a deterministic-input custom HMAC bearer token. The caller supplies
  `:issued-at-ms` and `:jti`; this adapter never invents randomness."
  [{:keys [workload audience issued-at-ms jti key]}]
  (let [claims (core/make-claims-v1 {:workload workload
                                     :audience audience
                                     :issued-at-ms issued-at-ms
                                     :jti jti})]
    (when-not claims
      (throw (IllegalArgumentException.
              "issue-token-v1 requires valid workload, audience, issued-at-ms, and jti")))
    (let [kb (crypto/key->bytes key)
          prepared (core/token-payload-v1 claims)
          signature (vec (crypto/bytes->unsigned-vector
                          (crypto/hmac-sha256 kb (:signing-bytes prepared))))
          token (core/finish-token-v1 prepared signature)]
      {:token token
       :jti jti
       :expires-at-ms (get claims "exp_ms")
       :claims claims})))

(defn validate-token-v1
  "Validate signature and strict half-open TTL. A successful validation does
  not consume the token and repeated valid calls are expected to succeed."
  ([token key options]
   (let [expected-aud (:expected-aud options)
         now-ms (now-from options)]
     (when-not (contract/valid-text? expected-aud)
       (throw (IllegalArgumentException.
               "validate-token-v1 requires a non-blank :expected-aud")))
     ;; Validate key policy outside the malformed-token catch: short keys are
     ;; configuration errors, not token failures.
     (crypto/key->bytes key)
     (try
       (let [parsed (core/parse-token-v1 token)
             signature-hex (crypto/bytes->hex
                            (crypto/unsigned-vector->bytes
                             (:signature-bytes parsed)))
             signature-valid? (crypto/verify-hmac?
                               key (:signing-bytes parsed) signature-hex)]
         (if-not signature-valid?
           {:valid false :reason :bad-signature :claims nil}
           (core/validate-claims-v1 (:claims parsed) now-ms expected-aud)))
       (catch clojure.lang.ExceptionInfo _
         {:valid false :reason :malformed :claims nil})
       (catch Exception _
         {:valid false :reason :malformed :claims nil})))))
