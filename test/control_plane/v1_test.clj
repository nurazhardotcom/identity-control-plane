(ns control-plane.v1-test
  "Portable v1 known-answer and fail-closed suite for the JVM.

  Every vector here is public: the HMAC key, the `jti`, and every timestamp
  are fixed. No test uses wall-clock time, a random source, a network call, or
  a secret. The suite deliberately covers the claims the documentation makes:
  canonical bytes, strict framing, independent-anchor truncation detection,
  export contracts, and v0/v1 format separation."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [control-plane.contract-v1 :as contract]
            [control-plane.crypto-jvm :as crypto]
            [control-plane.daglog-core :as daglog]
            [control-plane.daglog-jvm :as daglog-jvm]
            [control-plane.effect :as effect]
            [control-plane.encoding-v1 :as encoding]
            [control-plane.json-v1 :as json]
            [control-plane.sidecar-core :as sidecar-core]
            [control-plane.sidecar-jvm :as sidecar])
  (:import (java.io File)))

(def test-key "0123456789abcdef0123456789abcdef")
(def other-key "ffffffffffffffffffffffffffffffff")
(def issued-at 1767225600000)
(def log-id "demo-log-v1")

;; --- fixed known-answer vectors, shared with the Web Crypto suite -----------

(def expected-payload
  "{\"aud\":\"vault:transit\",\"exp_ms\":1767225900000,\"iat_ms\":1767225600000,\"iss\":\"identity-control-plane\",\"jti\":\"fixed-jti-v1\",\"sub\":\"payments-api\",\"v\":1}")
(def expected-token
  "eyJhdWQiOiJ2YXVsdDp0cmFuc2l0IiwiZXhwX21zIjoxNzY3MjI1OTAwMDAwLCJpYXRfbXMiOjE3NjcyMjU2MDAwMDAsImlzcyI6ImlkZW50aXR5LWNvbnRyb2wtcGxhbmUiLCJqdGkiOiJmaXhlZC1qdGktdjEiLCJzdWIiOiJwYXltZW50cy1hcGkiLCJ2IjoxfQ.Y9fIwYmRJ9eAKhxm_dHtLq2nfzFuuqlTC7G_HM-Gl4c")
(def expected-body
  "{\"action\":\"vault.read\",\"actor\":\"payments-api\",\"details\":{\"path\":\"transit/sign\"},\"prev_hash\":\"GENESIS\",\"seq\":1,\"ts_ms\":1767225600000,\"v\":1}")
(def expected-hash
  "22d0146fc3f1d8bf9b41684f5a97db7a168f5b272689136e14740c19884659b5")
(def expected-hmac
  "d4f8db43a68412d74b4e4e04a34c290346bf554b19a96c0d96da5978a7e7f621")
(def expected-log-sha256
  "6768a826411ff4080567046b2be00c582a9d76be4961642a9e6789328b89dd74")
(def expected-anchor-sha256
  "2db3ec472d8f610c7f62e6179e67cfd4c1422573e32d98681b67078d4214de7c")

(def kat-input
  {:ts-ms issued-at
   :actor "payments-api"
   :action "vault.read"
   :details {"path" "transit/sign"}})

(defn- entry-input
  [n]
  {:ts-ms (+ issued-at n)
   :actor "payments-api"
   :action (if (zero? n) "token.issued" "vault.read")
   :details (if (zero? n) {"jti" "fixed-jti-v1"} {"path" "transit/sign"})})

(defn- issue
  []
  (sidecar/issue-token-v1 {:workload "payments-api"
                           :audience "vault:transit"
                           :issued-at-ms issued-at
                           :jti "fixed-jti-v1"
                           :key test-key}))

(defn- one-entry-log
  []
  (daglog-jvm/append-entry-v1 [] test-key kat-input))

(defn- two-entry-log
  []
  (daglog-jvm/append-entry-v1 (one-entry-log) test-key (entry-input 5)))

(defn- anchor-for
  [log]
  (daglog-jvm/create-anchor-v1 log test-key {:log-id log-id
                                            :anchored-at-ms (+ issued-at 300000)}))

(defn- replace-entry
  "Replace one record in a log vector, keeping the rest untouched."
  [log index entry]
  (assoc (vec log) index entry))

(defn- zero-hash
  "A syntactically valid but wrong 64-character lowercase digest."
  []
  (apply str (repeat 64 "0")))

(defn- wrong-hash
  []
  (apply str (repeat 64 "a")))

;; Exactly the shape the v0 recorder writes: one deep-sorted pr-str EDN map
;; per line. The v1 reader must reject it outright.
(def v0-line
  (str "{:action \"vault.read\", :actor \"payments-api\", "
       ":details {:path \"transit/sign\"}, "
       ":hash \"22d0146fc3f1d8bf9b41684f5a97db7a168f5b272689136e14740c19884659b5\", "
       ":hmac \"d4f8db43a68412d74b4e4e04a34c290346bf554b19a96c0d96da5978a7e7f621\", "
       ":prev-hash \"GENESIS\", :seq 1, "
       ":ts \"2026-01-01T00:00:00Z\"}\n"))

(defn- break-first-seq
  "Corrupt the sequence number of the first JSONL record, leaving every other
  byte untouched. Used to prove an export is rejected before it can be used."
  [jsonl]
  (str/replace jsonl "\"seq\":1" "\"seq\":9"))

(defn- tamper-signature
  "Replace a token's signature with a well-formed but wrong 32-byte value, so
  parsing succeeds and only the HMAC check can reject it."
  [token]
  (let [[payload-b64 _] (str/split token #"\." -1)]
    (str payload-b64 "." (apply str (repeat 43 "A")))))

;; --- canonical JSON v1 -----------------------------------------------------

(deftest canonical-json-v1-is-deterministic
  (testing "object names sort by Unicode scalar value, not host map order"
    (is (= "{\"a\":[true,null],\"b\":1}"
           (json/canonical-json-v1 {"b" 1 "a" [true nil]})))
    (is (= "{\"A\":1,\"a\":2,\"b\":3}"
           (json/canonical-json-v1 {"b" 3 "a" 2 "A" 1})))
    (is (= "{\"\":1,\"a\":2}"
           (json/canonical-json-v1 {"a" 2 "" 1}))))
  (testing "no whitespace is emitted anywhere"
    (is (= "[]" (json/canonical-json-v1 [])))
    (is (= "{}" (json/canonical-json-v1 {})))
    (is (= "{\"k\":[1,2,3]}" (json/canonical-json-v1 {"k" [1 2 3]}))))
  (testing "fixed escaping for short forms, controls, and separators"
    (is (= "{\"bs\":\"\\\\\",\"fwd\":\"/\",\"q\":\"\\\"\"}"
           (json/canonical-json-v1 {"q" "\"" "bs" "\\" "fwd" "/"})))
    (is (= "{\"c\":\"\\b\\t\\n\\f\\r\"}"
           (json/canonical-json-v1 {"c" (str (char 0x08) (char 0x09) (char 0x0A)
                                             (char 0x0C) (char 0x0D))})))
    (is (= "{\"u\":\"\\u0000\\u001f\"}"
           (json/canonical-json-v1 {"u" (str (char 0x00) (char 0x1F))})))
    (is (= "{\"sep\":\"\\u2028\\u2029\"}"
           (json/canonical-json-v1 {"sep" (str (char 0x2028) (char 0x2029))})))
    (is (= "{\"emoji\":\"\uD83D\uDE00\"}"
           (json/canonical-json-v1
            {"emoji" (String. (Character/toChars 0x1F600))})))
    (testing "an astral scalar survives a host round trip as a surrogate pair"
      (is (= 2 (count (String. (Character/toChars 0x1F600)))))
      (is (= (json/utf8-code-units-v1 (String. (Character/toChars 0x1F600)))
             [0xF0 0x9F 0x98 0x80]))
      (is (= (String. (Character/toChars 0x1F600))
             (apply str (json/utf8-decode-v1 [0xF0 0x9F 0x98 0x80])))))))

(deftest canonical-json-v1-rejects-out-of-grammar-values
  (testing "only nil, booleans, strings, safe integers, vectors, and maps"
    (is (thrown? clojure.lang.ExceptionInfo (json/canonical-json-v1 {"f" 1.5})))
    (is (thrown? clojure.lang.ExceptionInfo (json/canonical-json-v1 {"f" ##NaN})))
    (is (thrown? clojure.lang.ExceptionInfo (json/canonical-json-v1 {:kw "x"})))
    (is (thrown? clojure.lang.ExceptionInfo (json/canonical-json-v1 {1 "x"})))
    (is (thrown? clojure.lang.ExceptionInfo (json/canonical-json-v1 #{"a"})))
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/canonical-json-v1 {"big" 9007199254740992})))
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/canonical-json-v1 {"big" 1000000000000000000000M}))))
  (testing "nesting is bounded so a hostile payload cannot exhaust the stack"
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/canonical-json-v1
                  (reduce (fn [acc _] [acc]) nil (range 70)))))))

(deftest canonical-json-v1-parses-only-what-it-serializes
  (testing "canonical text round-trips to an identical value"
    (is (= {"a" 1} (json/parse-canonical-json-v1 "{\"a\":1}")))
    (is (= ["x" 2 nil false]
           (json/parse-canonical-json-v1 "[\"x\",2,null,false]"))))
  (testing "non-canonical but semantically equal text parses; only the
            canonical reader rejects it"
    (is (= {"a" 1 "b" 2} (json/parse-json-v1 "{ \"b\" : 2 , \"a\" : 1 }")))
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/parse-canonical-json-v1 "{ \"a\" : 1 }"))))
  (testing "duplicate names, floats, and trailing data are rejected"
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/parse-json-v1 "{\"a\":1,\"a\":2}")))
    (is (thrown? clojure.lang.ExceptionInfo (json/parse-json-v1 "1.0")))
    (is (thrown? clojure.lang.ExceptionInfo (json/parse-json-v1 "1e3")))
    (is (thrown? clojure.lang.ExceptionInfo (json/parse-json-v1 "01")))
    (is (thrown? clojure.lang.ExceptionInfo (json/parse-json-v1 "-")))
    (is (thrown? clojure.lang.ExceptionInfo (json/parse-json-v1 "{} {}")))
    (is (thrown? clojure.lang.ExceptionInfo (json/parse-json-v1 "")))
    (is (thrown? clojure.lang.ExceptionInfo (json/parse-json-v1 "{'a':1}")))
    (is (thrown? clojure.lang.ExceptionInfo (json/parse-json-v1 "{\"a\":1,}"))))
  (testing "integers outside the portable safe range fail closed rather than
            being silently rounded by a host number"
    (is (= {"n" 9007199254740991}
           (json/parse-json-v1 "{\"n\":9007199254740991}")))
    (is (= {"n" -9007199254740991}
           (json/parse-json-v1 "{\"n\":-9007199254740991}")))
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/parse-json-v1 "{\"n\":9007199254740992}")))
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/parse-json-v1 "{\"n\":9007199254740993}")))
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/parse-json-v1 "{\"n\":-9007199254740992}")))
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/parse-json-v1 "{\"n\":12345678901234567890}")))))

(deftest utf8-v1-bytes-round-trip-and-reject-ambiguity
  (testing "scalar values encode to the canonical UTF-8 byte vector"
    (is (= [65 195 169 226 130 172 240 159 152 128]
           (json/utf8-code-units-v1 "A\u00E9\u20AC\uD83D\uDE00")))
    (is (= [] (json/utf8-code-units-v1 "")))
    (is (= "A\u00E9\u20AC\uD83D\uDE00"
           (json/utf8-decode-v1
            (json/utf8-code-units-v1 "A\u00E9\u20AC\uD83D\uDE00")))))
  (testing "overlong, truncated, surrogate, and out-of-range forms fail closed"
    (is (thrown? clojure.lang.ExceptionInfo (json/utf8-decode-v1 [0xC0 0x80])))
    (is (thrown? clojure.lang.ExceptionInfo (json/utf8-decode-v1 [0xE0 0x80 0x80])))
    (is (thrown? clojure.lang.ExceptionInfo (json/utf8-decode-v1 [0xED 0xA0 0x80])))
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/utf8-decode-v1 [0xF5 0x80 0x80 0x80])))
    (is (thrown? clojure.lang.ExceptionInfo (json/utf8-decode-v1 [0xC2])))
    (is (thrown? clojure.lang.ExceptionInfo (json/utf8-decode-v1 [256])))
    (is (thrown? clojure.lang.ExceptionInfo (json/utf8-decode-v1 [-1]))))
  (testing "an unpaired surrogate in a host string is rejected, not replaced"
    (is (not (json/valid-string? (str "a" (char 0xD800) "b"))))
    (is (thrown? clojure.lang.ExceptionInfo
                 (json/utf8-code-units-v1 (str "a" (char 0xD800) "b"))))))

;; --- strict base64url ------------------------------------------------------

(deftest base64url-v1-known-vectors-and-strictness
  (is (= "" (encoding/encode-base64url-v1 [])))
  (is (= "AA" (encoding/encode-base64url-v1 [0])))
  (is (= "AAE" (encoding/encode-base64url-v1 [0 1])))
  (is (= "AAEC" (encoding/encode-base64url-v1 [0 1 2])))
  (is (= "-_9_" (encoding/encode-base64url-v1 [0xFB 0xFF 0x7F])))
  (is (= [0xFB 0xFF 0x7F] (vec (encoding/decode-base64url-v1 "-_9_"))))
  (is (= [0 1 2] (vec (encoding/decode-base64url-v1 "AAEC"))))
  (is (= (json/utf8-code-units-v1 "A\u00E9\u20AC\uD83D\uDE00")
         (encoding/decode-base64url-v1
          (encoding/encode-utf8-base64url-v1 "A\u00E9\u20AC\uD83D\uDE00"))))
  (testing "padding, impossible length, and non-zero tail bits fail closed"
    (is (thrown? clojure.lang.ExceptionInfo (encoding/decode-base64url-v1 "A")))
    (is (thrown? clojure.lang.ExceptionInfo (encoding/decode-base64url-v1 "A==")))
    (is (thrown? clojure.lang.ExceptionInfo (encoding/decode-base64url-v1 "AA A")))
    (is (thrown? clojure.lang.ExceptionInfo (encoding/decode-base64url-v1 "AA+/"))))
    (is (thrown? clojure.lang.ExceptionInfo (encoding/decode-base64url-v1 "AB")))
    (is (thrown? clojure.lang.ExceptionInfo (encoding/decode-base64url-v1 "AAA=")))
    (is (thrown? clojure.lang.ExceptionInfo (encoding/decode-base64url-v1 "A"))))
  (testing "a non-byte input is rejected by the encoder, not coerced"
    (is (thrown? clojure.lang.ExceptionInfo
                 (encoding/encode-base64url-v1 [256])))
    (is (thrown? clojure.lang.ExceptionInfo
                 (encoding/encode-base64url-v1 [-1])))
    (is (thrown? clojure.lang.ExceptionInfo
                 (encoding/encode-base64url-v1 "not-bytes"))))

;; --- sidecar v1 ------------------------------------------------------------

(deftest sidecar-v1-known-answer-and-unsigned-shape
  (let [issued (issue)]
    (is (= expected-payload (:payload (sidecar-core/token-payload-v1 (:claims issued)))))
    (is (= expected-token (:token issued)))
    (is (= (+ issued-at 300000) (:expires-at-ms issued)))
    (is (= "fixed-jti-v1" (:jti issued)))
    (testing "the token is exactly two strict base64url parts"
      (let [[payload-b64 sig-b64] (str/split (:token issued) #"\." -1)]
        (is (= expected-payload (encoding/decode-utf8-base64url-v1 payload-b64)))
        (is (= 32 (count (encoding/decode-base64url-v1 sig-b64))))))))

(deftest sidecar-v1-lifetime-is-a-strict-half-open-300-seconds
  (let [token (:token (issue))
        verdict (fn [now]
                  (sidecar/validate-token-v1
                   token test-key {:now-ms now :expected-aud "vault:transit"}))]
    (testing "valid at iat and one millisecond before exp"
      (is (true? (:valid (verdict issued-at))))
      (is (true? (:valid (verdict (+ issued-at 299999))))))
    (testing "expired exactly at exp: the interval is [iat, exp)"
      (is (= :expired (:reason (verdict (+ issued-at 300000)))))
      (is (= :expired (:reason (verdict (+ issued-at 300001))))))
    (testing "not yet valid before iat"
      (is (= :not-yet-valid (:reason (verdict (dec issued-at))))))
    (testing "the audience is always checked, never skipped"
      (is (= :aud-mismatch
             (:reason (sidecar/validate-token-v1
                       token test-key {:now-ms issued-at
                                       :expected-aud "other"})))))))

(deftest sidecar-v1-validation-is-replayable-and-fail-closed
  (let [token (:token (issue))
        options {:now-ms (+ issued-at 1000) :expected-aud "vault:transit"}]
    (testing "a successful validation consumes nothing: it repeats forever"
      (doseq [_ (range 5)]
        (is (true? (:valid (sidecar/validate-token-v1 token test-key options)))))
      (is (true? (:valid (sidecar/validate-token-v1 token test-key options)))))
    (testing "a tampered signature fails closed without consuming the token"
      (is (= :bad-signature
             (:reason (sidecar/validate-token-v1
                       (tamper-signature token) test-key options))))
      (is (= :malformed
             (:reason (sidecar/validate-token-v1
                       (str "A" (subs token 1)) test-key options))))
      (is (true? (:valid (sidecar/validate-token-v1 token test-key options)))))
    (testing "structurally malformed tokens resolve to :malformed"
      (doseq [bad ["" "no-dot" "a.b.c" "." "not-a-token.at-all" "!!!.???"]]
        (is (= :malformed
               (:reason (sidecar/validate-token-v1 bad test-key options)))
            (str "expected :malformed for " (pr-str bad)))))
    (testing "a re-encoded payload with a 600s lifetime is malformed, and the
              shape check runs before any signature work"
      (let [forged (sidecar-core/finish-token-v1
                    (sidecar-core/token-payload-v1
                     (assoc (:claims (issue)) "exp_ms" (+ issued-at 600000)))
                    (vec (encoding/decode-base64url-v1
                          (second (str/split token #"\." -1)))))]
        (is (= :malformed
               (:reason (sidecar/validate-token-v1 forged test-key options))))))
    (testing "the wrong key never validates, even inside the valid window"
      (is (= :bad-signature
             (:reason (sidecar/validate-token-v1 token other-key options)))))
    (testing "configuration errors throw instead of returning a verdict"
      (is (thrown? IllegalArgumentException
                   (sidecar/validate-token-v1 token "short" options)))
      (is (thrown? IllegalArgumentException
                   (sidecar/validate-token-v1 token test-key
                                                {:expected-aud "vault:transit"})))
      (is (thrown? IllegalArgumentException
                   (sidecar/validate-token-v1 token test-key
                                                {:now-ms issued-at
                                                 :expected-aud ""})))
      (is (thrown? IllegalArgumentException
                   (sidecar/issue-token-v1 {:audience "vault:transit"
                                            :issued-at-ms issued-at
                                            :jti "fixed-jti-v1"
                                            :key test-key})))
      (is (thrown? IllegalArgumentException
                   (sidecar/issue-token-v1 {:workload "payments-api"
                                            :audience "vault:transit"
                                            :issued-at-ms issued-at
                                            :jti "fixed-jti-v1"
                                            :key "short"}))))))

(deftest sidecar-core-validates-claims-purely
  (let [claims (:claims (issue))]
    (is (= {:valid true :reason nil :claims claims}
           (sidecar-core/validate-claims-v1 claims issued-at "vault:transit")))
    (is (= {:valid false :reason :expired :claims nil}
           (sidecar-core/validate-claims-v1
            claims (+ issued-at 300000) "vault:transit")))
    (is (= {:valid false :reason :missing-audience :claims nil}
           (sidecar-core/validate-claims-v1 claims issued-at "")))
    (is (= {:valid false :reason :invalid-time :claims nil}
           (sidecar-core/validate-claims-v1 claims -1 "vault:transit")))
    (testing "a non-300s lifetime is malformed by contract, not by timing"
      (is (= {:valid false :reason :malformed :claims nil}
             (sidecar-core/validate-claims-v1
              (assoc claims "exp_ms" (+ issued-at 600000))
              issued-at "vault:transit"))))
    (testing "a claim set that is not the exact v1 shape is rejected"
      (is (= {:valid false :reason :malformed :claims nil}
             (sidecar-core/validate-claims-v1
              (assoc claims "extra" 1) issued-at "vault:transit"))))))

;; --- daglog v1 -------------------------------------------------------------

(deftest daglog-v1-chain-known-answers
  (let [log1 (one-entry-log)
        log2 (two-entry-log)]
    (is (= expected-body (:canonical-body (daglog/entry-body-v1 [] kat-input))))
    (is (= expected-hash (get (first log1) "hash")))
    (is (= expected-hmac (get (first log1) "hmac")))
    (is (= 1 (get (first log1) "seq")))
    (is (= contract/genesis-prev (get (first log1) "prev_hash")))
    (is (= 2 (get (second log2) "seq")))
    (is (= (get (first log1) "hash") (get (second log2) "prev_hash")))
    (is (true? (:valid (daglog-jvm/verify-log-v1 log2 test-key))))
    (is (= 2 (:entries (daglog-jvm/verify-log-v1 log2 test-key))))
    (is (= (get (last log2) "hash")
           (:tip-hash (daglog-jvm/verify-log-v1 log2 test-key))))
    (is (= {:valid true
            :entries 0
            :head-hash contract/genesis-prev
            :tip-hash contract/genesis-prev}
           (daglog-jvm/verify-log-v1 [] test-key)))
    (testing "an explicit empty details map is still a valid record"
      (let [log (daglog-jvm/append-entry-v1 [] test-key
                                            (assoc kat-input :details {}))]
        (is (= {} (get (first log) "details")))
        (is (true? (:valid (daglog-jvm/verify-log-v1 log test-key))))))))

(deftest daglog-v1-verifier-detects-every-single-record-failure
  (let [log (two-entry-log)
        entry (first log)
        second (second log)]
    (testing "an edited body fails on the digest, not silently"
      (is (= :bad-hash
             (:reason (daglog-jvm/verify-log-v1
                       (replace-entry log 1
                                      (assoc second "action" "vault.admin"))
                       test-key)))))
    (testing "a re-signed-looking but wrong HMAC fails on the HMAC"
      (is (= :bad-hmac
             (:reason (daglog-jvm/verify-log-v1
                       (replace-entry log 1
                                      (assoc second "hmac" (zero-hash)))
                       test-key)))))
    (testing "a reordering is caught by sequence, and a relink by prev_hash"
      (is (= :bad-seq
             (:reason (daglog-jvm/verify-log-v1 [second entry] test-key))))
      (is (= :broken-link
             (:reason (daglog-jvm/verify-log-v1
                       (replace-entry log 0
                                      (assoc entry "prev_hash" (zero-hash)))
                       test-key)))))
    (testing "a sequence edit is reported with its own reason"
      (is (= :bad-seq
             (:reason (daglog-jvm/verify-log-v1
                       (replace-entry log 1 (assoc second "seq" 7))
                       test-key)))))
    (testing "a missing field is a malformed record"
      (is (= :malformed-entry
             (:reason (daglog-jvm/verify-log-v1
                       (replace-entry log 0 (dissoc entry "hmac"))
                       test-key)))))
    (testing "verification with the wrong key fails closed on every record"
      (is (= :bad-hmac (:reason (daglog-jvm/verify-log-v1 log other-key)))))
    (testing "appending after a malformed entry is refused"
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/entry-body-v1 [(dissoc entry "hmac")]
                                         (entry-input 9)))))))

(deftest daglog-v1-pure-step-verifier-and-shape-checks
  (let [entry (first (one-entry-log))
        step {:expected-seq 1
              :expected-prev-hash contract/genesis-prev
              :computed-hash expected-hash
              :hmac-valid? true}]
    (is (= {:valid true :at 1} (daglog/verify-entry-step-v1 entry step)))
    (is (= :bad-seq
           (:reason (daglog/verify-entry-step-v1 (assoc entry "seq" 2) step))))
    (is (= :broken-link
           (:reason (daglog/verify-entry-step-v1
                     (assoc entry "prev_hash" (zero-hash)) step))))
    (is (= :bad-hash
           (:reason (daglog/verify-entry-step-v1
                     entry (assoc step :computed-hash (zero-hash))))))
    (is (= :bad-hmac
           (:reason (daglog/verify-entry-step-v1
                     entry (assoc step :hmac-valid? false)))))
    (is (= :malformed-entry
           (:reason (daglog/verify-entry-step-v1 (dissoc entry "hash") step))))
    (testing "the entry contract is exact-key, hash-shaped, and JSON-v1-valid"
      (is (contract/valid-entry? entry))
      (is (not (contract/valid-entry? (assoc entry "extra" 1))))
      (is (not (contract/valid-entry? (assoc-in entry ["details" "float"] 1.5))))
      (is (not (contract/valid-entry? (assoc entry "hash" (str/upper-case expected-hash)))))
      (is (not (contract/valid-entry? (assoc entry "seq" 0))))
      (is (not (contract/valid-entry? (assoc entry "actor" "  "))))
      (is (not (contract/valid-entry? (assoc entry "ts_ms" -1))))
      (is (not (contract/valid-entry? (assoc entry "prev_hash" "genesis")))))))

(deftest daglog-v1-jsonl-export-is-canonical-and-byte-exact
  (let [log (two-entry-log)
        jsonl (daglog/log->jsonl-v1 log)]
    (is (= 2 (count (str/split-lines jsonl))))
    (is (str/ends-with? jsonl "\n"))
    (is (= log (daglog/jsonl->canonical-log-v1 jsonl)))
    (is (= log (daglog/jsonl->log-v1 jsonl)))
    (is (= (json/utf8-code-units-v1 jsonl) (daglog/log->utf8-v1 log)))
    (testing "an empty log exports to an empty, still-valid, string"
      (is (= "" (daglog/log->jsonl-v1 [])))
      (is (= [] (daglog/jsonl->log-v1 ""))))
    (testing "framing violations are rejected: no trailing LF, no blank records"
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/jsonl->log-v1 (str/trim-newline jsonl))))
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/jsonl->log-v1 (str jsonl "\n"))))
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/jsonl->log-v1 (str "\n" jsonl)))))
    (testing "a structurally broken export never reaches a caller as a log"
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/jsonl->log-v1 (break-first-seq jsonl))))
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/jsonl->canonical-log-v1 (break-first-seq jsonl)))))
    (testing "a v0 EDN line is not v1 JSONL at all"
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/jsonl->log-v1 v0-line))))))

(deftest daglog-v1-semantic-integrity-and-byte-integrity-differ
  (let [log (two-entry-log)
        jsonl (daglog/log->jsonl-v1 log)
        anchor (anchor-for log)
        ;; the same records with one space of leading whitespace on line one
        pretty (str "{ " (subs jsonl 1))]
    (is (= log (daglog/jsonl->log-v1 pretty)))
    (is (true? (:valid (daglog-jvm/verify-log-v1
                        (daglog/jsonl->log-v1 pretty) test-key))))
    (is (= :byte-digest-mismatch
           (:reason (daglog-jvm/verify-anchor-v1 anchor test-key pretty))))
    (testing "the canonical reader rejects the non-canonical representation"
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/jsonl->canonical-log-v1 pretty))))))

(deftest daglog-v1-truncation-needs-an-independent-anchor
  (let [log (two-entry-log)
        jsonl (daglog/log->jsonl-v1 log)
        anchor (anchor-for log)
        prefix (str (first (str/split-lines jsonl)) "\n")]
    (testing "a valid prefix is a valid chain; that is the whole caveat"
      (is (true? (:valid (daglog-jvm/verify-log-v1
                          (daglog/jsonl->log-v1 prefix) test-key))))
      (is (= 1 (:entries (daglog-jvm/verify-log-v1
                          (daglog/jsonl->log-v1 prefix) test-key)))))
    (testing "only the trusted anchor establishes completeness"
      (is (= :entry-count-mismatch
             (:reason (daglog-jvm/verify-anchor-v1 anchor test-key prefix))))
      (is (true? (:valid (daglog-jvm/verify-anchor-v1 anchor test-key jsonl)))))
    (testing "a longer log than the anchor describes is also incomplete"
      (is (= :entry-count-mismatch
             (:reason (daglog-jvm/verify-anchor-v1
                       anchor test-key
                       (daglog/log->jsonl-v1
                        (daglog-jvm/append-entry-v1 log test-key (entry-input 9))))))))
    (testing "each anchor field is compared independently"
      (is (= :head-mismatch
             (:reason (daglog-jvm/verify-anchor-v1
                       (assoc anchor "head_hash" (wrong-hash))
                       test-key jsonl))))
      (is (= :tip-mismatch
             (:reason (daglog-jvm/verify-anchor-v1
                       (assoc anchor "tip_hash" (wrong-hash))
                       test-key jsonl))))
      (is (= :bad-anchor-shape
             (:reason (daglog-jvm/verify-anchor-v1
                       (dissoc anchor "log_sha256") test-key jsonl)))))))

(deftest daglog-v1-anchor-contract
  (let [log (one-entry-log)
        jsonl (daglog/log->jsonl-v1 log)
        anchor (anchor-for log)]
    (is (contract/valid-anchor? anchor))
    (is (= expected-log-sha256 (get anchor "log_sha256")))
    (is (= 1 (get anchor "entries")))
    (is (= expected-hash (get anchor "head_hash")))
    (is (= expected-hash (get anchor "tip_hash")))
    (is (= (+ issued-at 300000) (get anchor "anchored_at_ms")))
    (is (= contract/anchor-kind (get anchor "kind")))
    (is (= log-id (get anchor "log_id")))
    (testing "the anchor is canonical JSON, so its exact bytes can be digested"
      (is (= (json/canonical-json-v1 anchor) (daglog/anchor-export-v1 anchor)))
      (is (= (daglog/anchor-export-v1 anchor)
             (json/canonical-json-v1
              (json/parse-canonical-json-v1 (daglog/anchor-export-v1 anchor))))))
    (testing "an empty or structurally invalid log can never be anchored"
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/make-anchor-v1
                    []
                    {:log-id log-id
                     :anchored-at-ms issued-at
                     :log-sha256 expected-log-sha256})))
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/make-anchor-v1
                    [(assoc (first log) "prev_hash" (zero-hash))]
                    {:log-id log-id
                     :anchored-at-ms issued-at
                     :log-sha256 expected-log-sha256})))
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/anchor-export-v1 (assoc anchor "entries" 0)))))
    (testing "an anchor with an unsafe log id is refused"
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/make-anchor-v1
                    log
                    {:log-id "../escape"
                     :anchored-at-ms issued-at
                     :log-sha256 expected-log-sha256}))))
    (testing "an unverifiable export resolves to a uniform failure shape"
      (doseq [bad ["{not json\n" "{}\n" "[]\n" (str jsonl "\n")]]
        (let [result (daglog-jvm/verify-anchor-v1 anchor test-key bad)]
          (is (false? (:valid result)) (str "expected failure for " (pr-str bad)))
          (is (some? (:reason result)) (str "expected a reason for " (pr-str bad)))))
      (let [result (daglog-jvm/verify-anchor-v1 anchor test-key "{not json\n")]
        (is (= :malformed-export (:reason result)))
        (is (map? (:detail result)))
        (is (string? (get-in result [:detail :message]))))
      (is (= {:valid false :reason :bad-seq :at 9}
             (daglog-jvm/verify-anchor-v1
              anchor test-key (break-first-seq jsonl)))))))

;; --- export contracts ------------------------------------------------------

(deftest export-descriptor-v1-is-a-local-contract-only
  (let [log (one-entry-log)
        anchor (anchor-for log)
        bundle (daglog-jvm/export-bundle-v1 log anchor)
        descriptor (:descriptor bundle)
        text (json/canonical-json-v1 descriptor)]
    (is (= (daglog/log->jsonl-v1 log) (:log-jsonl bundle)))
    (is (= (daglog/anchor-export-v1 anchor) (:anchor-json bundle)))
    (is (= expected-log-sha256 (get-in descriptor ["log" "sha256"])))
    (is (= expected-anchor-sha256 (get-in descriptor ["anchor" "sha256"])))
    (is (contract/valid-export-descriptor? descriptor))
    (is (= "demo-log-v1.jsonl" (get-in descriptor ["log" "filename"])))
    (is (= "demo-log-v1.anchor-v1.json" (get-in descriptor ["anchor" "filename"])))
    (is (= contract/log-media-type (get-in descriptor ["log" "media_type"])))
    (is (= contract/anchor-media-type (get-in descriptor ["anchor" "media_type"])))
    (is (= 1 (get-in descriptor ["log" "entries"])))
    (testing "the descriptor is canonical JSON v1 and carries no credential,
              endpoint, or cloud resource of any kind"
      (is (= text (json/canonical-json-v1 (json/parse-canonical-json-v1 text))))
      (is (not (re-find #"(?i)secret|password|authorization|bearer|r2|s3|aws|api[_-]?key" text)))
      (is (= #{"v" "log" "anchor"} (set (keys descriptor)))))
    (testing "an unsafe log id cannot produce a descriptor"
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog/export-descriptor-v1
                    log (assoc anchor "log_id" "../escape")
                    expected-log-sha256 expected-anchor-sha256))))))

;; --- JVM file adapter ------------------------------------------------------

(deftest native-v1-file-adapter-round-trips-and-fails-closed
  (let [file (File/createTempFile "control-plane-v1" ".jsonl")]
    (.delete file)
    (try
      (daglog-jvm/append-jsonl-file-v1! (str file) test-key (entry-input 0))
      (daglog-jvm/append-jsonl-file-v1! (str file) test-key (entry-input 5))
      (let [verification (daglog-jvm/verify-jsonl-file-v1! (str file) test-key)]
        (is (true? (:valid verification)))
        (is (= 2 (:entries verification))))
      (is (str/ends-with? (slurp file) "\n"))
      (testing "the file bytes are exactly the canonical JSONL export"
        (is (= (daglog/log->jsonl-v1 (daglog/jsonl->canonical-log-v1 (slurp file)))
               (slurp file)))
        (is (= (daglog-jvm/verify-log-v1
                (daglog/jsonl->canonical-log-v1 (slurp file)) test-key)
               (daglog-jvm/verify-jsonl-file-v1! (str file) test-key))))
      (testing "the wrong key is a verification failure, not a clean result"
        (is (= :bad-hmac
               (:reason (daglog-jvm/verify-jsonl-file-v1! (str file) other-key)))))
      (testing "a missing file is an error, never a clean verification"
        (is (thrown? IllegalArgumentException
                     (daglog-jvm/verify-jsonl-file-v1!
                      (str (.getParent file) "absent-v1.jsonl") test-key))))
      (finally (.delete file)))))

(deftest native-v1-file-adapter-refuses-legacy-v0-content
  (let [file (File/createTempFile "control-plane-v0" ".edn")]
    (try
      ;; Exactly the v0 recorder's on-disk shape: one deep-sorted pr-str EDN
      ;; map per line. The v1 reader must refuse it outright.
      (spit file v0-line)
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog-jvm/verify-jsonl-file-v1! (str file) test-key)))
      (is (thrown? clojure.lang.ExceptionInfo
                   (daglog-jvm/append-jsonl-file-v1! (str file) test-key
                                                      kat-input)))
      (testing "the two formats are provably different: v0 uses keyword names"
        (let [line (first (str/split-lines (slurp file)))]
          (is (contains? (edn/read-string line) :prev-hash))
          (is (not (contains? (edn/read-string line) "prev_hash")))
          (is (thrown? clojure.lang.ExceptionInfo
                       (json/parse-json-v1 line)))))
      (finally (.delete file)))))

;; --- effect adapters -------------------------------------------------------

(deftest jvm-crypto-adapter-fails-closed-on-bad-signatures
  (let [input (json/utf8-code-units-v1
              (contract/daglog-signing-input-v1 expected-hash))]
    (is (= expected-hmac (crypto/hmac-sha256-hex test-key input)))
    (is (= expected-hash
           (crypto/sha256-hex (json/utf8-code-units-v1 expected-body))))
    (is (true? (crypto/verify-hmac? test-key input expected-hmac)))
    (testing "a malformed or wrong-length hex signature is false, not a throw"
      (is (false? (crypto/verify-hmac? test-key input nil)))
      (is (false? (crypto/verify-hmac? test-key input "")))
      (is (false? (crypto/verify-hmac? test-key input (subs expected-hmac 0 62))))
      (is (false? (crypto/verify-hmac? test-key input (str/upper-case expected-hmac))))
      (is (false? (crypto/verify-hmac? test-key input (apply str (repeat 64 "z"))))))
    (testing "a too-short key is refused before any digest is computed"
      (is (thrown? IllegalArgumentException
                   (crypto/hmac-sha256-hex "short" input)))
      (is (thrown? IllegalArgumentException (crypto/key->bytes "short"))))
    (testing "byte and text keys are both accepted, and both work"
      (is (= expected-hmac
             (crypto/hmac-sha256-hex (crypto/utf8->bytes test-key) input))))))

(deftest jvm-adapters-satisfy-the-declared-effect-ports
  (let [signing-input (json/utf8-code-units-v1
                       (contract/daglog-signing-input-v1 expected-hash))]
    (testing "the crypto reify matches the direct functions exactly"
      (is (satisfies? effect/CryptoPort crypto/crypto))
      (is (= (crypto/sha256-hex (json/utf8-code-units-v1 expected-body))
             (effect/sha256-hex crypto/crypto
                                (json/utf8-code-units-v1 expected-body))))
      (is (= expected-hmac
             (effect/hmac-sha256-hex crypto/crypto test-key signing-input))))
    (testing "the clock port is a real clock, distinct from the fixed
              timestamps the deterministic suites use"
      (is (satisfies? effect/ClockPort crypto/system-clock))
      (is (pos? (effect/now-ms crypto/system-clock)))
      (is (contract/valid-ms? (effect/now-ms crypto/system-clock))))
    (testing "the archive ports have no implementation in this repository"
      (is (not (some #(satisfies? effect/ImmutableArchivePort %)
                     [crypto/crypto crypto/system-clock]))))))

(deftest portable-cores-import-no-effect-namespace
  (testing "the pure namespaces must not depend on a clock, filesystem, or
            cloud client, or the purity claim in their docstrings is false"
    (doseq [ns-sym ['control-plane.json-v1
                    'control-plane.encoding-v1
                    'control-plane.contract-v1
                    'control-plane.sidecar-core
                    'control-plane.daglog-core]]
      (let [aliases (set (map str (keys (ns-aliases (the-ns ns-sym)))))]
        (is (not (contains? aliases "control-plane.effect"))
            (str ns-sym " must not require control-plane.effect"))
        (is (not (contains? aliases "control-plane.crypto-jvm"))
            (str ns-sym " must not require a crypto adapter"))))))
