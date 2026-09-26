(ns control-plane.webcrypto-test
  "Headless Web Crypto suite.

  It uses no DOM, Reagent, network, filesystem, or random source. Every key,
  `jti`, and timestamp is a fixed public known-answer vector shared with the
  JVM suite in `control-plane.v1-test`, so the two adapters must produce
  byte-identical tokens, digests, and export descriptors."
  (:require ["fs" :as fs]
            [cljs.test :as t :refer-macros [async deftest is]]
            [clojure.string :as str]
            [control-plane.contract-v1 :as contract]
            [control-plane.daglog-core :as daglog]
            [control-plane.encoding-v1 :as encoding]
            [control-plane.json-v1 :as json]
            [control-plane.webcrypto :as web]))

;; --- fixed public known-answer vectors -------------------------------------

(def test-key "0123456789abcdef0123456789abcdef")
(def other-key "ffffffffffffffffffffffffffffffff")
(def issued-at 1767225600000)
(def log-id "demo-log-v1")

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

(def anchor-args
  {:log-id log-id
   :anchored-at-ms (+ issued-at 300000)})

(defn- entry-input
  [n]
  {:ts-ms (+ issued-at n)
   :actor "payments-api"
   :action (if (zero? n) "token.issued" "vault.read")
   :details (if (zero? n) {"jti" "fixed-jti-v1"} {"path" "transit/sign"})})

(defn- issue-args
  ([ ] (issue-args test-key))
  ([key]
   {:workload "payments-api"
    :audience "vault:transit"
    :issued-at-ms issued-at
    :jti "fixed-jti-v1"
    :key key}))

(defn- check
  "Validate a token at a fixed instant."
  [token key now-ms expected-aud]
  (web/validate-token-v1 token key {:now-ms now-ms
                                    :expected-aud expected-aud}))

(defn- zero-hash
  []
  (apply str (repeat 64 "0")))

(defn- wrong-hash
  []
  (apply str (repeat 64 "a")))

(defn- tamper-signature
  [token]
  (let [payload-b64 (first (.split token "."))]
    (str payload-b64 "." (apply str (repeat 43 "A")))))

(defn- rejects?
  "Resolve to true when the promise rejects, false when it fulfils. Used to
  prove configuration errors reject instead of resolving to a verdict."
  [p]
  (.then p (fn [_] false) (fn [_] true)))

(defn- chain-steps
  "Thread one live promise through `fns`, passing each resolved value to the
   next function. The Web Crypto adapter is asynchronous by specification, so a
   test may never read a returned Promise as if it were already a verdict."
  [fns]
  (reduce (fn [p f] (.then p f))
          (js/Promise.resolve ::none)
          fns))

(defn- chain
  "Append one record and return a Promise for the new log vector."
  [log n]
  (web/append-entry-v1 log test-key (entry-input n)))

(defn- one-record-log
  []
  (web/append-entry-v1 [] test-key kat-input))

(defn- two-record-log
  []
  (.then (one-record-log) (fn [log] (chain log 5))))

(defn- anchored-state
  "Promise for {:log :anchor :jsonl} for the log built by `log-maker`. A
  truncation test needs an anchor over a LONGER log than the export under
  test, so the maker is a parameter rather than a hard-coded one-record log."
  [log-maker]
  (-> (log-maker)
      (.then (fn [log]
               (-> (web/create-anchor-v1 log test-key anchor-args)
                   (.then (fn [anchor]
                            {:log log
                             :anchor anchor
                             :jsonl (daglog/log->jsonl-v1 log)})))))))

(defn- anchored-one-record
  []
  (anchored-state one-record-log))

(defn- anchored-two-record
  []
  (anchored-state two-record-log))

(defn- fail-loudly
  "End an async test. A rejection becomes a failed assertion with the error
  attached, never a silent pass, and `done` runs exactly once even when an
  earlier assertion in the same chain already failed."
  [done e]
  (when-not (.-__cpFinished done)
    (set! (.-__cpFinished done) true)
    (is (nil? e) (str "unexpected rejection: " (pr-str e)))
    (done)))

;; --- portable core ---------------------------------------------------------

(deftest restricted-json-and-utf8-match-the-jvm
  (is (= "{\"a\":[true,null],\"b\":1}"
         (json/canonical-json-v1 {"b" 1 "a" [true nil]})))
  (is (= "{\"A\":1,\"a\":2,\"b\":3}"
         (json/canonical-json-v1 {"b" 3 "a" 2 "A" 1})))
  (is (= [65 195 169 226 130 172 240 159 152 128]
         (json/utf8-code-units-v1 "Aé€\uD83D\uDE00")))
  (is (= "Aé€\uD83D\uDE00"
         (json/utf8-decode-v1 (json/utf8-code-units-v1 "Aé€\uD83D\uDE00"))))
  (is (= {"a" 1} (json/parse-canonical-json-v1 "{\"a\":1}"))))

(deftest restricted-json-rejects-out-of-grammar-values
  (is (thrown? js/Error (json/canonical-json-v1 {"f" 1.5})))
  (is (thrown? js/Error (json/canonical-json-v1 {:kw "x"})))
  (is (thrown? js/Error (json/canonical-json-v1 #{"a"})))
  (is (thrown? js/Error (json/canonical-json-v1 {"big" 9007199254740992})))
  (is (thrown? js/Error (json/utf8-decode-v1 #js [0xC0 0x80])))
  (is (thrown? js/Error (json/utf8-decode-v1 #js [0xED 0xA0 0x80]))))

(deftest cljs-numbers-cannot-accept-an-out-of-range-integer
  ;; A JavaScript double cannot hold every integer above 2^53. The portable
  ;; range check compares the literal text, so a rounded value is never
  ;; accepted and the JVM and browser adapters agree exactly.
  (is (= {"n" 9007199254740991}
         (json/parse-json-v1 "{\"n\":9007199254740991}")))
  (is (= {"n" -9007199254740991}
         (json/parse-json-v1 "{\"n\":-9007199254740991}")))
  (doseq [literal ["9007199254740992"
                   "9007199254740993"
                   "-9007199254740992"
                   "12345678901234567890"]]
    (is (thrown? js/Error (json/parse-json-v1 (str "{\"n\":" literal "}")))
        (str "expected rejection for " literal))))

(deftest strict-framing-rejects-trailing-data
  (doseq [bad ["{} {}" "1.0" "1e3" "01" "{\"a\":1}extra" "{\"a\":1,\"a\":2}"]]
    (is (thrown? js/Error (json/parse-json-v1 bad))
        (str "expected rejection for " (pr-str bad)))))

(deftest strict-base64url-known-vectors
  (is (= "" (encoding/encode-base64url-v1 [])))
  (is (= "AA" (encoding/encode-base64url-v1 [0])))
  (is (= "AAE" (encoding/encode-base64url-v1 [0 1])))
  (is (= "AAEC" (encoding/encode-base64url-v1 [0 1 2])))
  (is (= "-_9_" (encoding/encode-base64url-v1 [0xFB 0xFF 0x7F])))
  (is (= [0xFB 0xFF 0x7F] (vec (encoding/decode-base64url-v1 "-_9_"))))
  (is (thrown? js/Error (encoding/decode-base64url-v1 "A")))
  (is (thrown? js/Error (encoding/decode-base64url-v1 "A==")))
  (is (thrown? js/Error (encoding/decode-base64url-v1 "AA+/"))))

(deftest contract-predicates-are-shared
  (let [body (:body (daglog/entry-body-v1 [] kat-input))]
    (is (= expected-body (json/canonical-json-v1 body)))
    (is (contract/valid-entry-body? body))
    (is (not (contract/valid-entry-body? (assoc body "extra" 1))))
    (is (not (contract/valid-entry? body)))
    (is (= contract/genesis-prev (get body "prev_hash")))
    (is (= 300000 contract/token-ttl-ms))))

;; --- token surface ---------------------------------------------------------

(deftest webcrypto-token-known-answer
  (async done
    (-> (web/issue-token-v1 (issue-args))
        (.then (fn [issued]
                 (is (= expected-token (:token issued)))
                 (is (= (+ issued-at 300000) (:expires-at-ms issued)))
                 (is (= "fixed-jti-v1" (:jti issued)))
                 (is (= expected-payload
                        (json/canonical-json-v1 (:claims issued))))))
        (.then (fn [_] (done)))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-token-is-valid-before-expiry-and-expired-at-expiry
  (async done
    (-> (web/issue-token-v1 (issue-args))
        (.then (fn [_] (check expected-token test-key (+ issued-at 299999)
                              "vault:transit")))
        (.then (fn [just-before]
                 (is (true? (:valid just-before)))
                 ;; deliberate valid replay: there is no consume ledger
                 (check expected-token test-key (+ issued-at 299999)
                        "vault:transit")))
        (.then (fn [replayed]
                 (is (true? (:valid replayed)))
                 (check expected-token test-key (+ issued-at 300000)
                        "vault:transit")))
        (.then (fn [at-expiry]
                 (is (= :expired (:reason at-expiry)))
                 (is (nil? (:claims at-expiry)))
                 (check expected-token test-key (dec issued-at) "vault:transit")))
        (.then (fn [before-iat]
                 (is (= :not-yet-valid (:reason before-iat)))
                 (check expected-token test-key issued-at "other")))
        (.then (fn [wrong-aud]
                 (is (= :aud-mismatch (:reason wrong-aud)))
                 (check expected-token test-key issued-at "vault:transit")))
        (.then (fn [still-valid]
                 (is (true? (:valid still-valid))
                     "no failed check may consume the token")
                 (done)))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-token-fails-closed
  (async done
    (-> (check (tamper-signature expected-token) test-key
               (+ issued-at 1000) "vault:transit")
        (.then (fn [bad-signature]
                 (is (= :bad-signature (:reason bad-signature)))
                 (check "no-dot" test-key (+ issued-at 1000) "vault:transit")))
        (.then (fn [malformed]
                 (is (= :malformed (:reason malformed)))
                 (check expected-token other-key (+ issued-at 1000)
                        "vault:transit")))
        (.then (fn [wrong-key]
                 (is (= :bad-signature (:reason wrong-key)))
                 (check expected-token test-key (+ issued-at 1000)
                        "vault:transit")))
        (.then (fn [unchanged]
                 (is (true? (:valid unchanged)))
                 (done)))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-configuration-errors-reject
  (async done
    (-> (rejects? (web/issue-token-v1 (issue-args "short")))
        (.then (fn [short-issue-key]
                 (is (true? short-issue-key) "a short issue key must reject")
                 (rejects? (check expected-token "short" issued-at
                                    "vault:transit"))))
        (.then (fn [short-key]
                 (is (true? short-key) "a short key must reject, not resolve")
                 (rejects? (web/validate-token-v1
                            expected-token test-key
                            {:expected-aud "vault:transit"}))))
        (.then (fn [no-clock]
                 (is (true? no-clock) "a missing :now-ms must reject")
                 (rejects? (check expected-token test-key issued-at ""))))
        (.then (fn [no-aud]
                 (is (true? no-aud) "a blank :expected-aud must reject")
                 (done)))
        (.catch (fn [e] (fail-loudly done e))))))

;; --- daglog surface --------------------------------------------------------

(deftest webcrypto-daglog-known-answers
  (async done
    (-> (one-record-log)
        (.then (fn [log]
                 (is (= 1 (count log)))
                 (is (= expected-hash (get (first log) "hash")))
                 (is (= expected-hmac (get (first log) "hmac")))
                 (is (= 1 (get (first log) "seq")))
                 (is (= contract/genesis-prev (get (first log) "prev_hash")))
                 (is (= expected-body
                        (json/canonical-json-v1
                         (daglog/body-of-entry-v1 (first log)))))
                 (is (contract/valid-entry? (first log)))
                 (chain log 5)))
        (.then (fn [log]
                 (is (= 2 (get (second log) "seq")))
                 (is (= expected-hash (get (second log) "prev_hash")))
                 (is (= (get (second log) "hash") (:tip-hash
                                                 (daglog/verify-structure-v1 log))))
                 (web/verify-log-v1 log test-key)))
        (.then (fn [verified]
                 (is (true? (:valid verified)))
                 (is (= 2 (:entries verified)))
                 (is (= expected-hash (:head-hash verified))
                     "head is the first record")
                 (done)))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-daglog-detects-tampering
  (async done
    (-> (two-record-log)
        (.then (fn [log2]
                 (let [entry (first log2)
                       next-entry (second log2)
                       edit (fn [i replacement] (assoc (vec log2) i replacement))]
                   (-> (web/verify-log-v1
                        (edit 1 (assoc next-entry "action" "vault.admin"))
                        test-key)
                       (.then (fn [r]
                                (is (= :bad-hash (:reason r)))
                                (web/verify-log-v1
                                 (edit 1 (assoc next-entry "hmac" (zero-hash)))
                                 test-key)))
                       (.then (fn [r]
                                (is (= :bad-hmac (:reason r)))
                                (web/verify-log-v1
                                 (edit 0 (assoc entry "prev_hash" (zero-hash)))
                                 test-key)))
                       (.then (fn [r]
                                (is (= :broken-link (:reason r)))
                                (web/verify-log-v1
                                 (edit 0 (dissoc entry "hmac")) test-key)))
                       (.then (fn [r]
                                (is (= :malformed-entry (:reason r)))
                                (web/verify-log-v1
                                 (edit 1 (assoc next-entry "seq" 7)) test-key)))
                       (.then (fn [r]
                                (is (= :bad-seq (:reason r)))
                                (web/verify-log-v1 log2 other-key)))
                       (.then (fn [r]
                                (is (= :bad-hmac (:reason r)))
                                (web/verify-log-v1 log2 test-key)))
                       (.then (fn [r]
                                (is (true? (:valid r))
                                    "a failed check must not mutate the log")
                                (done)))))))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-empty-log-verifies-but-cannot-be-anchored
  (async done
    (-> (web/verify-log-v1 [] test-key)
        (.then (fn [result]
                 (is (true? (:valid result)))
                 (is (= 0 (:entries result)))
                 (is (= contract/genesis-prev (:head-hash result)))
                 (is (= contract/genesis-prev (:tip-hash result)))
                 (is (= "" (daglog/log->jsonl-v1 [])))
                 (is (= [] (daglog/jsonl->log-v1 "")))
                 (rejects? (web/create-anchor-v1 [] test-key anchor-args))))
        (.then (fn [rejected]
                 (is (true? rejected) "anchoring an empty log must reject")
                 (done)))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-appending-after-a-malformed-record-rejects
  (async done
    (-> (one-record-log)
        (.then (fn [log]
                 (rejects? (web/append-entry-v1
                            [(dissoc (first log) "hmac")]
                            test-key (entry-input 5)))))
        (.then (fn [rejected]
                 (is (true? rejected))
                 (done)))
        (.catch (fn [e] (fail-loudly done e))))))

;; --- anchor and export -----------------------------------------------------

(deftest webcrypto-anchor-contract
  (async done
    (-> (anchored-one-record)
        (.then (fn [state]
                 (let [anchor (:anchor state)]
                   (is (contract/valid-anchor? anchor))
                   (is (= log-id (get anchor "log_id")))
                   (is (= 1 (get anchor "entries")))
                   (is (= expected-hash (get anchor "head_hash")))
                   (is (= expected-hash (get anchor "tip_hash")))
                   (is (= expected-log-sha256 (get anchor "log_sha256")))
                   (is (= (+ issued-at 300000) (get anchor "anchored_at_ms")))
                   (is (= contract/anchor-kind (get anchor "kind")))
                   (is (= (json/canonical-json-v1 anchor)
                          (daglog/anchor-export-v1 anchor))))))
        (.then (fn [_] (done)))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-export-descriptor-matches-the-jvm
  (async done
    (-> (anchored-one-record)
        (.then (fn [state]
                 (.then (web/export-bundle-v1 (:log state) (:anchor state))
                        (fn [bundle] {:state state :bundle bundle}))))
        (.then (fn [{:keys [state bundle]}]
                 (let [d (:descriptor bundle)
                       log-part (get d "log")
                       anchor-part (get d "anchor")]
                   (is (= expected-log-sha256 (get log-part "sha256")))
                   (is (= expected-anchor-sha256 (get anchor-part "sha256")))
                   (is (= 1 (get log-part "entries")))
                   (is (= "demo-log-v1.jsonl" (get log-part "filename")))
                   (is (= "demo-log-v1.anchor-v1.json"
                          (get anchor-part "filename")))
                   (is (= contract/log-media-type (get log-part "media_type")))
                   (is (= contract/anchor-media-type
                          (get anchor-part "media_type")))
                   (is (contract/valid-export-descriptor? d))
                   (is (= (:jsonl state) (:log-jsonl bundle)))
                   (is (= (daglog/anchor-export-v1 (:anchor state))
                          (:anchor-json bundle)))
                   (is (= (:jsonl state)
                          (daglog/log->jsonl-v1
                           (daglog/jsonl->canonical-log-v1
                            (:log-jsonl bundle))))))))
        (.then (fn [_] (done)))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-exact-export-verifies-against-the-anchor
  (async done
    (-> (anchored-two-record)
        (.then (fn [state]
                 (web/verify-anchor-v1 (:anchor state) test-key (:jsonl state))))
        (.then (fn [result]
                 (is (true? (:valid result)))))
        (.then (fn [_] (done)))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-a-valid-prefix-is-not-a-complete-log
  (async done
    ;; The trusted anchor must cover a LONGER log than the export under test,
    ;; otherwise there is no prefix to detect: anchor two records, then verify
    ;; the first record on its own.
    (let [anchored (anchored-two-record)]
      (-> anchored
          (.then (fn [{:keys [anchor jsonl]}]
                   (is (= 2 (get anchor "entries"))
                       "the trusted anchor covers both records")
                   (let [prefix (str (first (.split ^string jsonl "\n")) "\n")]
                     (-> (web/verify-log-v1
                          (daglog/jsonl->log-v1 prefix) test-key)
                         (.then (fn [r]
                                  (is (true? (:valid r))
                                      "the prefix is internally valid")
                                  (is (= 1 (:entries r)))
                                  (web/verify-anchor-v1 anchor test-key prefix)))
                         (.then (fn [r]
                                  (is (= :entry-count-mismatch (:reason r))
                                      "a valid prefix is not a complete log")
                                  (done)))))))
          (.catch (fn [e] (fail-loudly done e)))))))

(deftest webcrypto-semantic-validity-is-not-byte-integrity
  (async done
    (-> (anchored-one-record)
        (.then (fn [state]
                 (let [pretty (str "{ " (subs ^string (:jsonl state) 1))
                       pretty-log (daglog/jsonl->log-v1 pretty)]
                   (is (= 1 (count pretty-log)))
                   (is (thrown? js/Error
                                (daglog/jsonl->canonical-log-v1 pretty)))
                   (chain-steps
                    [(fn [_]
                       (web/verify-log-v1 pretty-log test-key))
                     (fn [r]
                       (is (true? (:valid r)))
                       (web/verify-anchor-v1
                        (:anchor state) test-key pretty))
                     (fn [r]
                       (is (= :byte-digest-mismatch (:reason r))))]))))
        (.then (fn [_] (done)))
        (.catch (fn [e] (fail-loudly done e))))))

(deftest webcrypto-unverifiable-exports-never-verify-clean
  (async done
    (let [check-garbage
          (fn [anchor key]
            (web/verify-anchor-v1 anchor key "{not json\n"))
          check-seq
          (fn [anchor key jsonl]
            (web/verify-anchor-v1
             anchor key (str/replace ^string jsonl "\"seq\":1" "\"seq\":9")))
          check-head
          (fn [anchor key jsonl]
            (web/verify-anchor-v1
             (assoc anchor "head_hash" (wrong-hash)) key jsonl))
          check-shape
          (fn [anchor key jsonl]
            (web/verify-anchor-v1
             (dissoc anchor "log_sha256") key jsonl))]
      (-> (anchored-one-record)
          (.then (fn [state]
                   (let [anchor (:anchor state)
                         jsonl (:jsonl state)]
                     (-> (check-garbage anchor test-key)
                         (.then (fn [garbage]
                                  (is (= :malformed-export (:reason garbage)))
                                  (is (map? (:detail garbage)))
                                  (check-seq anchor test-key jsonl)))
                         (.then (fn [r]
                                  (is (= :bad-seq (:reason r)))
                                  (check-head anchor test-key jsonl)))
                         (.then (fn [r]
                                  (is (= {:valid false :reason :head-mismatch} r))
                                  (check-shape anchor test-key jsonl)))
                         (.then (fn [r]
                                  (is (= {:valid false :reason :bad-anchor-shape} r))
                                  (done)))))))
          (.catch (fn [e] (fail-loudly done e)))))))

;; --- runner ----------------------------------------------------------------

;; A `(deftest` the reader absorbed into a neighbouring form is created as an
;; unbound Var with no `:test` metadata and silently never runs. Comparing the
;; count declared in this source against the count actually registered turns
;; that class of bug into a hard failure instead of a smaller green suite.
;; This is the ClojureScript counterpart of the same check in
;; control-plane.test-runner.
(def this-file "./test/control_plane/webcrypto_test.cljs")

(defn- declared-deftest-count
  "Count top-level `(deftest` forms in this source file. A swallowed
  `(deftest` is invisible to `ns-interns`, so the two counts must agree."
  []
  (count (filter #(str/starts-with? % "(deftest")
                 (str/split-lines (fs/readFileSync this-file "utf-8")))))

(defn- registered-deftest-count
  []
  (count (filter #(:test (meta %))
                 (vals (ns-interns 'control-plane.webcrypto-test)))))

(defn- assert-no-swallowed-tests
  []
  (let [declared (declared-deftest-count)
        registered (registered-deftest-count)]
    (when (not= declared registered)
      (throw (js/Error.
              (str "deftest count mismatch: " declared
                   " declared in " this-file " but " registered
                   " registered as tests; a form is probably unbalanced"))))))

(defn -main [& _args]
  (try
    (assert-no-swallowed-tests)
    (catch :default e
      (println (.-message e))
      (set! (.-exitCode js/process) 1)))
  (t/run-tests 'control-plane.webcrypto-test))

(defmethod t/report [:cljs.test/default :end-run-tests] [m]
  (when-not (t/successful? m)
    (set! (.-exitCode js/process) 1)))
