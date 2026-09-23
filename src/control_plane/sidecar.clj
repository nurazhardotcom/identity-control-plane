(ns control-plane.sidecar
  "Ephemeral workload credential sidecar: simulates an OIDC token
  exchange for non-human identities. Tokens are HMAC-signed, carry a
  strict 300-second TTL, and their in-memory material is zeroed the
  moment they expire (fail-closed: expired, tampered, or malformed
  tokens never validate).

  Secrets are held as char arrays — never interned Strings — so purge
  can overwrite the exact cells. JVM strings are immutable and cannot
  be reliably wiped, hence the char[] discipline."
  (:require [cheshire.core :as json]
            [clojure.string :as str])
  (:import (java.security MessageDigest SecureRandom)
           (java.util Base64 UUID)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(def ttl-seconds 300)
(def min-key-bytes 16)
(def issuer "identity-control-plane")

(defonce ^:private store (atom {}))

(def ^:private b64url-encoder (-> (Base64/getUrlEncoder) .withoutPadding))
(def ^:private b64url-decoder (Base64/getUrlDecoder))

(defn generate-key
  "Generate a fresh 32-byte HMAC key. Callers own the bytes."
  []
  (let [b (byte-array 32)]
    (.nextBytes (SecureRandom.) b)
    b))

(defn- byte-array? [x]
  (instance? (Class/forName "[B") x))

(defn- key-bytes ^bytes [k]
  (cond
    (byte-array? k) k
    (string? k) (.getBytes ^String k "UTF-8")
    :else (throw (IllegalArgumentException.
                  "HMAC key must be bytes or a string"))))

(defn- check-key! ^bytes [k]
  (let [b (key-bytes k)]
    (when (< (alength b) min-key-bytes)
      (throw (IllegalArgumentException.
              (str "HMAC key must be >= " min-key-bytes " bytes"))))
    b))

(defn- b64u-encode ^String [^bytes b]
  (.encodeToString b64url-encoder b))

(defn- b64u-decode ^bytes [^String s]
  (.decode b64url-decoder s))

(defn- hmac-sha256 ^bytes [^bytes k ^bytes data]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. k "HmacSHA256"))
    (.doFinal mac data)))

(defn- zero-chars! [^chars c]
  (java.util.Arrays/fill c \u0000)
  nil)

(defn live-count
  "Number of credential materials currently held in memory."
  []
  (count @store))

(defn reset-store!
  "Zero every held material and empty the store. Test isolation only."
  []
  (let [old @store]
    (reset! store {})
    (doseq [[_ e] old]
      (zero-chars! ^chars (:material e)))
    (count old)))

(defn purge!
  "Immediately zero and drop the material for jti. Returns true when
  an entry was present, false otherwise."
  [jti]
  (let [entry (get @store jti)]
    (swap! store dissoc jti)
    (if entry
      (do (zero-chars! ^chars (:material entry)) true)
      false)))

(defn purge-expired!
  "Zero and drop every entry with :exp <= now (epoch seconds).
  Returns the number of entries purged."
  [now]
  (let [expired (filterv (fn [[_ e]] (<= (long (:exp e)) (long now)))
                         @store)]
    (doseq [[jti e] expired]
      (swap! store dissoc jti)
      (zero-chars! ^chars (:material e)))
    (count expired)))

(defn- epoch-now []
  (quot (System/currentTimeMillis) 1000))

(defn issue-token
  "Issue an ephemeral workload credential.
  Required: :workload (non-blank), :aud (non-blank), :key (>=16 bytes).
  Optional: :now (epoch seconds, default wall clock), :jti (default random).
  Returns {:token :jti :exp :claims}. The token is
  base64url(payload).base64url(hmac-sha256(payload))."
  [{:keys [workload aud key now jti]}]
  (let [kb (check-key! key)]
    (when (or (nil? workload) (not (string? workload))
              (str/blank? workload))
      (throw (IllegalArgumentException. "issue-token requires :workload")))
    (when (or (nil? aud) (not (string? aud)) (str/blank? aud))
      (throw (IllegalArgumentException. "issue-token requires :aud")))
    (let [iat (long (or now (epoch-now)))
          exp (+ iat ttl-seconds)
          id (or jti (str (UUID/randomUUID)))
          claims (sorted-map "aud" aud "exp" exp "iat" iat
                             "iss" issuer "jti" id "sub" workload)
          payload (b64u-encode (.getBytes ^String (json/generate-string claims)
                                          "UTF-8"))
          sig (b64u-encode (hmac-sha256 kb (.getBytes ^String payload "US-ASCII")))
          token (str payload "." sig)]
      (swap! store assoc id {:material (.toCharArray token) :exp exp})
      {:token token
       :jti id
       :exp exp
       :claims {:iss issuer :sub workload :aud aud
                :iat iat :exp exp :jti id}})))

(defn validate-token
  "Validate a token. Returns {:valid :reason :claims}.
  Reasons for :valid false: :expired :bad-signature :aud-mismatch
  :not-yet-valid :malformed. Expired tokens are purged from memory
  immediately. TTL is strict: the token is valid for [iat, exp) —
  at now == exp it is already expired.
  :expected-aud is required (non-blank): the audience is always
  checked, never silently skipped. Omission throws
  IllegalArgumentException."
  ([token key] (validate-token token key {}))
  ([token key {:keys [now expected-aud]}]
   (let [kb (check-key! key)
         _ (when (or (nil? expected-aud) (not (string? expected-aud))
                     (str/blank? expected-aud))
             (throw (IllegalArgumentException.
                     "validate-token requires :expected-aud")))
         now (long (or now (epoch-now)))]
     (try
       (when-not (string? token)
         (throw (Exception. "not a string")))
       (let [parts (str/split token #"\." -1)]
         (when (not= 2 (count parts))
           (throw (Exception. "token must have 2 parts")))
         (let [[payload-b64 sig-b64] parts
               payload-bytes (.getBytes ^String payload-b64 "US-ASCII")
               expected (hmac-sha256 kb payload-bytes)
               actual (b64u-decode sig-b64)]
           (when-not (MessageDigest/isEqual expected actual)
             (throw (ex-info "bad signature" {:reason :bad-signature})))
           (let [claims (json/parse-string
                         (String. ^bytes (b64u-decode payload-b64) "UTF-8")
                         true)
                 exp (:exp claims)
                 iat (:iat claims)]
             (when-not (and (number? exp) (number? iat))
               (throw (Exception. "missing exp/iat")))
             (cond
               (<= (long exp) now)
               (do (purge! (:jti claims))
                   {:valid false :reason :expired :claims nil})

               (> (long iat) now)
               {:valid false :reason :not-yet-valid :claims nil}

               (not= expected-aud (:aud claims))
               {:valid false :reason :aud-mismatch :claims nil}

               :else
               {:valid true :reason nil :claims claims}))))
       (catch clojure.lang.ExceptionInfo e
         {:valid false :reason (:reason (ex-data e) :malformed) :claims nil})
       (catch Exception _
         {:valid false :reason :malformed :claims nil})))))

(def ^:private demo-key "demo-only-key-0123456789abcdef")
(def ^:private demo-now 1767225600)

(defn demo
  "Deterministic end-to-end transcript: issue, validate, expire, purge.
  Fixed demo key + fixed timestamps, so output is reproducible."
  []
  (reset-store!)
  (println "== sidecar demo (deterministic: key + timestamps fixed) ==")
  (let [{:keys [token jti exp]} (issue-token {:workload "payments-api"
                                              :aud "vault:transit"
                                              :key demo-key
                                              :now demo-now
                                              :jti "demo-jti-0001"})]
    (println (str "issued  jti=" jti " exp=" exp " live=" (live-count)))
    (println (str "token   " token))
    (let [ok (validate-token token demo-key {:now demo-now
                                                      :expected-aud "vault:transit"})]
      (println (str "verify@t+0    valid=" (:valid ok)
                    " sub=" (get-in ok [:claims :sub])
                    " live=" (live-count))))
    (let [expired (validate-token token demo-key {:now (+ demo-now ttl-seconds)
                                                           :expected-aud "vault:transit"})]
      (println (str "verify@t+300  valid=" (:valid expired)
                    " reason=" (:reason expired)
                    " live=" (live-count) " (purged)"))
      (println (str "purge-expired@t+300 -> "
                    (purge-expired! (+ demo-now ttl-seconds))
                    " live=" (live-count)))
      {:jti jti :exp exp :valid true
       :expired-reason (:reason expired)})))

(defn -main [& _args]
  (demo)
  (System/exit 0))
