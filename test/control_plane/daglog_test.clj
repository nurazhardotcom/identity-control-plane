(ns control-plane.daglog-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [control-plane.daglog :as daglog])
  (:import (java.io File)))

(def test-key "test-only-key-0123456789abcdef-test-only")

(defn sample-log
  "Deterministic 3-entry chain with fixed timestamps."
  []
  (-> []
      (daglog/append-entry test-key "2026-01-01T00:00:00Z"
                           "w" "a1" {})
      (daglog/append-entry test-key "2026-01-01T00:00:05Z"
                           "w" "a2" {:v 1})
      (daglog/append-entry test-key "2026-01-01T00:00:10Z"
                           "w" "a3" {:v 2})))

(deftest chain-seals-and-verifies
  (let [log (sample-log)
        res (daglog/verify-chain log test-key)]
    (is (true? (:valid res)))
    (is (= 3 (:entries res)))
    (is (= [1 2 3] (mapv :seq log)))))

(deftest reorder-detected-at-exact-sequence
  (let [log (vec (sample-log))]
    (let [reordered (vec (map log [1 0 2]))
          bad (daglog/verify-chain reordered test-key)]
      (is (false? (:valid bad)))
      (is (= :bad-seq (:reason bad)))
      (is (= 2 (:at bad))))
    (let [reordered (vec (map log [0 2 1]))
          bad (daglog/verify-chain reordered test-key)]
      (is (false? (:valid bad)))
      (is (= :bad-seq (:reason bad)))
      (is (= 3 (:at bad))))))

(deftest truncate-detected-at-exact-sequence
  (let [log (vec (sample-log))
        truncated (vec [(log 0) (log 2)])
        bad (daglog/verify-chain truncated test-key)]
    (is (false? (:valid bad)))
    (is (= :bad-seq (:reason bad)))
    (is (= 3 (:at bad)))))

(deftest tampered-hash-chain-detected
  (let [log (vec (sample-log))]
    (let [bad (daglog/verify-chain
               (assoc-in log [1 :hash] "00") test-key)]
      (is (false? (:valid bad)))
      (is (= :bad-hash (:reason bad)))
      (is (= 2 (:at bad))))
    (let [bad (daglog/verify-chain
               (assoc-in log [2 :prev-hash] "bogus") test-key)]
      (is (false? (:valid bad)))
      (is (= :broken-link (:reason bad)))
      (is (= 3 (:at bad))))))

(deftest file-verify-matches-chain-verify
  (let [tmp (File/createTempFile "daglog-stream" ".edn")]
    (.delete tmp)
    (daglog/append-to-file! (str tmp) test-key "w" "a1" {:v 1}
                            :ts "2026-01-01T00:00:00Z")
    (daglog/append-to-file! (str tmp) test-key "w" "a2" {:v 2}
                            :ts "2026-01-01T00:00:05Z")
    (let [streamed (daglog/verify-log-file (str tmp) test-key)
          loaded (daglog/verify-chain (daglog/load-log (str tmp)) test-key)]
      (is (true? (:valid streamed)))
      (is (= 2 (:entries streamed)))
      (is (= loaded streamed)))
    (.delete tmp))
  (is (thrown? IllegalArgumentException
               (daglog/verify-log-file "/nonexistent/daglog.edn" test-key))))

(deftest file-verify-detects-tamper-at-exact-sequence
  (let [tmp (File/createTempFile "daglog-tamper" ".edn")]
    (.delete tmp)
    (daglog/append-to-file! (str tmp) test-key "w" "a1" {}
                            :ts "2026-01-01T00:00:00Z")
    (daglog/append-to-file! (str tmp) test-key "w" "a2" {}
                            :ts "2026-01-01T00:00:05Z")
    (let [lines (str/split-lines (slurp (str tmp)))
          forged (assoc lines 1 (str/replace (lines 1) "\"a2\"" "\"admin\""))]
      (spit (str tmp) (str (str/join "\n" forged) "\n")))
    (let [bad (daglog/verify-log-file (str tmp) test-key)]
      (is (false? (:valid bad)))
      (is (= :bad-hash (:reason bad)))
      (is (= 2 (:at bad))))
    (.delete tmp)))

(deftest file-verify-rejects-malformed-line
  (let [tmp (File/createTempFile "daglog-malformed" ".edn")]
    (.delete tmp)
    (daglog/append-to-file! (str tmp) test-key "w" "a1" {}
                            :ts "2026-01-01T00:00:00Z")
    (spit (str tmp) "not-an-edn-map\n" :append true)
    (is (thrown? IllegalArgumentException
                 (daglog/verify-log-file (str tmp) test-key)))
    (.delete tmp)))
