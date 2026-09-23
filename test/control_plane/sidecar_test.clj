(ns control-plane.sidecar-test
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [clojure.test :refer [deftest is use-fixtures]]
            [control-plane.daglog :as daglog]
            [control-plane.sidecar :as sidecar])
  (:import (java.io File)))

(def test-key "test-only-key-0123456789abcdef-test-only")
(def now0 1767225600)

(use-fixtures :each (fn [t] (sidecar/reset-store!) (t) (sidecar/reset-store!)))

(deftest token-issuance
  (let [{:keys [token jti exp claims]} (sidecar/issue-token
                                       {:workload "payments-api"
                                        :aud "vault:transit"
                                        :key test-key
                                        :now now0
                                        :jti "fixed-jti-1"})]
    (is (= "fixed-jti-1" jti))
    (is (= (+ now0 300) exp))
    (is (= 2 (count (clojure.string/split token #"\." -1))))
    (is (= {:iss "identity-control-plane" :sub "payments-api"
            :aud "vault:transit" :iat now0 :exp (+ now0 300)
            :jti "fixed-jti-1"}
           claims))
    (is (= 1 (sidecar/live-count)))))

(deftest issuance-arg-validation
  (is (thrown? IllegalArgumentException
               (sidecar/issue-token {:workload "" :aud "a" :key test-key})))
  (is (thrown? IllegalArgumentException
               (sidecar/issue-token {:workload "w" :aud nil :key test-key})))
  (is (thrown? IllegalArgumentException
               (sidecar/issue-token {:workload "w" :aud "a" :key "short"}))))

(deftest ttl-expiry-boundary
  (let [{:keys [token]} (sidecar/issue-token {:workload "w" :aud "a"
                                              :key test-key :now now0})]
    (is (true? (:valid (sidecar/validate-token
                        token test-key {:now (+ now0 299)
                                        :expected-aud "a"}))))
    (let [res (sidecar/validate-token token test-key {:now (+ now0 300)
                                                      :expected-aud "a"})]
      (is (false? (:valid res)))
      (is (= :expired (:reason res))))
    (is (= 0 (sidecar/live-count))
        "expired validation purges memory immediately")))

(deftest signature-and-claims-verification
  (let [{:keys [token]} (sidecar/issue-token {:workload "w" :aud "a"
                                              :key test-key :now now0})]
    (is (true? (:valid (sidecar/validate-token
                        token test-key {:now now0 :expected-aud "a"}))))
    (is (= :aud-mismatch
           (:reason (sidecar/validate-token
                     token test-key {:now now0 :expected-aud "other"}))))
    (is (= :bad-signature
           (:reason (sidecar/validate-token
                     (str "X" (subs token 1)) test-key {:now now0
                                                                 :expected-aud "a"}))))
    (is (= :bad-signature
           (:reason (sidecar/validate-token
                     token "wrong-key-0123456789abcdef-wrong" {:now now0
                                                                        :expected-aud "a"}))))
    (is (= :not-yet-valid
           (:reason (sidecar/validate-token
                     token test-key {:now (- now0 10)
                                              :expected-aud "a"}))))
    (is (= :malformed (:reason (sidecar/validate-token "junk" test-key {:expected-aud "a"}))))
    (is (= :malformed (:reason (sidecar/validate-token nil test-key {:expected-aud "a"}))))
    (is (thrown? IllegalArgumentException
                 (sidecar/validate-token token "short")))))

(deftest expected-aud-is-required
  (let [{:keys [token]} (sidecar/issue-token {:workload "w" :aud "a"
                                              :key test-key :now now0})]
    (is (thrown? IllegalArgumentException
                 (sidecar/validate-token token test-key {:now now0})))
    (is (thrown? IllegalArgumentException
                 (sidecar/validate-token token test-key {:now now0
                                                         :expected-aud ""})))
    (is (true? (:valid (sidecar/validate-token
                        token test-key {:now now0 :expected-aud "a"}))))))

(deftest purge-expired-sweeps-store
  (sidecar/issue-token {:workload "w1" :aud "a" :key test-key :now now0})
  (sidecar/issue-token {:workload "w2" :aud "a" :key test-key :now (+ now0 200)})
  (is (= 2 (sidecar/live-count)))
  (is (= 1 (sidecar/purge-expired! (+ now0 300))))
  (is (= 1 (sidecar/live-count)))
  (is (= 1 (sidecar/purge-expired! (+ now0 500))))
  (is (= 0 (sidecar/live-count))))

(deftest daglog-chain-seals-and-verifies
  (let [log (-> []
                (daglog/append-entry test-key "2026-01-01T00:00:00Z"
                                     "w" "token.issued" {:jti "a"})
                (daglog/append-entry test-key "2026-01-01T00:00:05Z"
                                     "w" "vault.read" {:path "k"})
                (daglog/append-entry test-key "2026-01-01T00:05:00Z"
                                     "s" "token.purged" {:jti "a"}))
        res (daglog/verify-chain log test-key)]
    (is (true? (:valid res)))
    (is (= 3 (:entries res)))
    (is (= [1 2 3] (mapv :seq log)))
    (is (= "GENESIS" (:prev-hash (first log))))
    (is (= (:hash (first log)) (:prev-hash (second log))))))

(deftest daglog-tamper-fails-at-exact-sequence
  (let [log (-> []
                (daglog/append-entry test-key "2026-01-01T00:00:00Z"
                                     "w" "a1" {})
                (daglog/append-entry test-key "2026-01-01T00:00:05Z"
                                     "w" "a2" {:v 1}))]
    (let [bad (daglog/verify-chain
               (assoc-in (vec log) [1 :details :v] 2) test-key)]
      (is (false? (:valid bad)))
      (is (= :bad-hash (:reason bad)))
      (is (= 2 (:at bad))))
    (let [bad (daglog/verify-chain
               (assoc-in (vec log) [0 :hmac] "00") test-key)]
      (is (false? (:valid bad)))
      (is (= :bad-hmac (:reason bad)))
      (is (= 1 (:at bad))))
    (let [bad (daglog/verify-chain
               (assoc-in (vec log) [1 :prev-hash] "bogus") test-key)]
      (is (false? (:valid bad)))
      (is (= :broken-link (:reason bad))))
    (let [bad (daglog/verify-chain log "wrong-key-0123456789abcdef-wrong")]
      (is (false? (:valid bad)))
      (is (= :bad-hmac (:reason bad)))
      (is (= 1 (:at bad))))))

(deftest daglog-file-roundtrip-and-json
  (let [tmp (File/createTempFile "daglog" ".edn")]
    (.delete tmp)
    (daglog/append-to-file! (str tmp) test-key "w" "a1" {:v 1}
                            :ts "2026-01-01T00:00:00Z")
    (daglog/append-to-file! (str tmp) test-key "w" "a2" {:v 2}
                            :ts "2026-01-01T00:00:05Z")
    (let [log (daglog/load-log (str tmp))
          res (daglog/verify-chain log test-key)
          parsed (json/parse-string (daglog/entry->json (first log)) true)]
      (is (true? (:valid res)))
      (is (= 2 (:entries res)))
      (is (= "a1" (:action parsed)))
      (is (= 1 (:seq parsed))))
    (.delete tmp))
  (is (thrown? IllegalArgumentException
               (daglog/load-log "/nonexistent/daglog.edn"))))
