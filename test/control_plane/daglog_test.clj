(ns control-plane.daglog-test
  (:require [clojure.test :refer :all]
            [control-plane.daglog :as daglog]))

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
