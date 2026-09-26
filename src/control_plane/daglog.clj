(ns control-plane.daglog
  "Native JVM v0 compatibility recorder. Each entry carries a SHA-256 hash
  chained to its predecessor plus an HMAC-SHA-256 signature. Verification
  detects edits, reordering, and broken links in the supplied records; a
  valid prefix can still verify, so truncation requires an independent trusted
  anchor. New portable records use the v1 JSON/UTF-8 core instead."
  (:require [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.string :as str])
  (:import (java.io File)
           (java.security MessageDigest)
           (java.time Instant)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(def genesis-prev "GENESIS")
(def min-key-bytes 16)
(def env-key-var "CONTROL_PLANE_HMAC_KEY")

(defn- deep-sort [x]
  (cond
    (map? x) (into (sorted-map)
                   (map (fn [[k v]] [k (deep-sort v)]) x))
    (sequential? x) (mapv deep-sort x)
    :else x))

(defn canonical
  "Deterministic serialization of an entry body for hashing."
  [m]
  (pr-str (deep-sort m)))

(defn- hex ^String [^bytes b]
  (let [sb (StringBuilder. (* 2 (alength b)))]
    (doseq [x b]
      (.append sb (format "%02x" (bit-and x 0xff))))
    (str sb)))

(defn sha256-hex ^String [^String s]
  (let [d (MessageDigest/getInstance "SHA-256")]
    (.update d (.getBytes s "UTF-8"))
    (hex (.digest d))))

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

(defn hmac-sha256-hex ^String [k ^String s]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. (check-key! k) "HmacSHA256"))
    (hex (.doFinal mac (.getBytes s "UTF-8")))))

(defn- const-eq? [^String a ^String b]
  (MessageDigest/isEqual (.getBytes a "UTF-8") (.getBytes b "UTF-8")))

(defn- seal-entry [body k]
  (let [h (sha256-hex (canonical body))]
    (assoc body :hash h :hmac (hmac-sha256-hex k h))))

(defn append-entry
  "Pure append: seal {:seq :ts :actor :action :details :prev-hash}
  onto the log vector. Timestamps are caller-supplied (fixed in tests,
  wall clock at the CLI) so hashing stays deterministic."
  [log k ts actor action details]
  (check-key! k)
  (when (or (nil? ts) (not (string? ts)) (str/blank? ts))
    (throw (IllegalArgumentException. "append-entry requires :ts")))
  (doseq [[label v] {"actor" actor "action" action}]
    (when (or (nil? v) (not (string? v)) (str/blank? v))
      (throw (IllegalArgumentException.
              (str "append-entry requires " label)))))
  (let [prev (:hash (last log) genesis-prev)
        body {:seq (inc (count log))
              :ts ts
              :actor actor
              :action action
              :details (or details {})
              :prev-hash prev}]
    (conj (vec log) (seal-entry body k))))

(defn- check-entry
  "Check one entry against its expected sequence number and prev-hash.
  Returns nil when clean, or {:valid false :reason :at} at the break."
  [e want-seq expected-prev k]
  (let [body (dissoc e :hash :hmac)]
    (cond
      (not= want-seq (:seq e))
      {:valid false :reason :bad-seq :at (:seq e)}

      (not= expected-prev (:prev-hash e))
      {:valid false :reason :broken-link :at (:seq e)}

      (not (const-eq? (sha256-hex (canonical body))
                      (str (:hash e))))
      {:valid false :reason :bad-hash :at (:seq e)}

      (not (const-eq? (hmac-sha256-hex k (str (:hash e)))
                      (str (:hmac e))))
      {:valid false :reason :bad-hmac :at (:seq e)}

      :else nil)))

(defn verify-chain
  "Recompute every hash, HMAC, link, and sequence number in the supplied
  records. Returns {:valid true :entries n :tip-hash h} or
  {:valid false :reason :bad-seq|:broken-link|:bad-hash|:bad-hmac
   :at <seq>|nil}."
  [log k]
  (check-key! k)
  (let [entries (vec log)]
    (loop [i 0 expected-prev genesis-prev]
      (if (>= i (count entries))
        {:valid true :entries (count entries)
         :tip-hash (if (seq entries) (:hash (last entries)) genesis-prev)}
        (if-let [bad (check-entry (nth entries i) (inc i) expected-prev k)]
          bad
          (recur (inc i) (:hash (nth entries i))))))))

(defn verify-log-file
  "Stream-verify an EDN-lines daglog file line by line (constant memory,
  safe for logs too large to load). Same result shape as verify-chain.
  Throws on missing files and malformed lines."
  [path k]
  (check-key! k)
  (let [f (File. (str path))]
    (when-not (.isFile f)
      (throw (IllegalArgumentException. (str "No such log file: " path))))
    (with-open [rdr (java.io.BufferedReader. (java.io.FileReader. f))]
      (loop [expected-prev genesis-prev want-seq 1 tip genesis-prev n 0]
        (let [line (.readLine rdr)]
          (cond
            (nil? line)
            {:valid true :entries n :tip-hash tip}

            (str/blank? line)
            (recur expected-prev want-seq tip n)

            :else
            (let [e (edn/read-string line)]
              (when-not (map? e)
                (throw (IllegalArgumentException.
                        (str "Malformed daglog line: " line))))
              (if-let [bad (check-entry e want-seq expected-prev k)]
                bad
                (recur (:hash e) (inc want-seq) (:hash e) (inc n))))))))))

(defn load-log
  "Load an EDN-lines daglog file. Throws on missing files and on any
  malformed line — a half-readable log never verifies as clean."
  [path]
  (let [f (File. (str path))]
    (when-not (.isFile f)
      (throw (IllegalArgumentException. (str "No such log file: " path))))
    (mapv (fn [line]
            (let [e (edn/read-string line)]
              (when-not (map? e)
                (throw (IllegalArgumentException.
                        (str "Malformed daglog line: " line))))
              e))
          (remove str/blank? (str/split-lines (slurp f))))))

(defn append-to-file!
  "Append one sealed entry to an EDN-lines log file (created when
  absent) under an exclusive file lock, so concurrent CLI writers
  serialize instead of interleaving. Returns the sealed entry."
  [path k actor action details & {:keys [ts]}]
  (let [f (File. (str path))]
    (.createNewFile f)
    (with-open [raf (java.io.RandomAccessFile. f "rw")
                chan (.getChannel raf)
                _lock (.lock chan)]
      (let [log (load-log path)
            entry (last (append-entry log k (or ts (str (Instant/now)))
                                     actor action details))]
        (.seek raf (.length raf))
        (.write raf (.getBytes ^String (str (prn-str entry)) "UTF-8"))
        entry))))

(defn entry->json
  "Render one entry as a JSON object string."
  [entry]
  (json/generate-string entry))

(defn read-env-key
  "Read the HMAC key from $CONTROL_PLANE_HMAC_KEY. Throws when the
  variable is missing, blank, or shorter than 16 bytes — the recorder
  refuses to seal entries it cannot authenticate."
  []
  (let [v (System/getenv env-key-var)]
    (when (or (nil? v) (str/blank? v))
      (throw (IllegalArgumentException.
              (str "Missing required key material: set $" env-key-var))))
    (check-key! v)))

(def ^:private demo-key "demo-only-daglog-key-0123456789")

(defn demo
  "Deterministic transcript: seal 3 entries, verify, then prove a
  tampered copy fails at the exact sequence number."
  []
  (println "== daglog demo (deterministic: key + timestamps fixed) ==")
  (let [log (-> []
                (append-entry demo-key "2026-01-01T00:00:00Z"
                              "payments-api" "token.issued" {:jti "demo-jti-0001"})
                (append-entry demo-key "2026-01-01T00:00:05Z"
                              "payments-api" "vault.read" {:path "transit/sign"})
                (append-entry demo-key "2026-01-01T00:05:00Z"
                              "sidecar" "token.purged" {:jti "demo-jti-0001"}))
        ok (verify-chain log demo-key)
        forged (assoc-in (vec log) [1 :action] "vault.admin")
        bad (verify-chain forged demo-key)]
    (println (str "sealed   " (:entries ok) " entries tip="
                  (subs (str (:tip-hash ok)) 0 16) "..."))
    (println (str "verify   valid=" (:valid ok)))
    (println (str "json     " (entry->json (first log))))
    (println (str "forged   valid=" (:valid bad)
                  " reason=" (:reason bad) " at=" (:at bad)))
    {:entries (:entries ok) :tamper bad}))

(defn -main [& args]
  (let [[cmd & rest] (vec args)]
    (cond
      (= cmd "append")
      (let [[path actor action details-edn] rest]
        (when (or (nil? path) (nil? actor) (nil? action))
          (println "Usage: bb daglog append <file> <actor> <action> [details-edn]")
          (System/exit 2))
        (try
          (let [entry (append-to-file!
                       path (read-env-key) actor action
                       (if details-edn (edn/read-string details-edn) {}))]
            (println (str "appended seq=" (:seq entry)
                          " hash=" (:hash entry)))
            (System/exit 0))
          (catch IllegalArgumentException e
            (println (str "DAGLOG ERROR: " (.getMessage e)))
            (System/exit 2))))

      (= cmd "verify")
      (let [[path] rest]
        (when (nil? path)
          (println "Usage: bb daglog verify <file>")
          (System/exit 2))
        (try
          (let [res (verify-log-file path (read-env-key))]
            (prn res)
            (System/exit (if (:valid res) 0 1)))
          (catch IllegalArgumentException e
            (println (str "DAGLOG ERROR: " (.getMessage e)))
            (System/exit 2))))

      :else
      (do (demo)
          (System/exit 0)))))
