(ns control-plane.daglog-core
  "Pure portable daglog v1 core.

  No function here performs I/O or cryptography. An adapter prepares a body,
  obtains SHA-256/HMAC results through its effect port, and feeds those values
  to the pure step verifier. The same canonical JSON/UTF-8 bytes are used by
  JVM and Web Crypto adapters."
  (:require [clojure.string :as str]
            [control-plane.contract-v1 :as contract]
            [control-plane.json-v1 :as json-v1]))

(defn- fail! [message data]
  (throw (ex-info message (assoc data :type :daglog-v1))))

(defn entry-body-v1
  "Prepare the exact v1 entry body for a new record. The log is a vector;
  its last record supplies prev_hash. Timestamps are caller supplied."
  [log input]
  (let [{:keys [ts-ms actor action details]} input]
  (when-not (vector? log)
    (fail! "Daglog v1 log must be a vector" {}))
  (let [previous (peek log)
        previous-hash (if previous
                        (if (contract/valid-entry? previous)
                          (get previous "hash")
                          (fail! "Cannot append after a malformed entry" {}))
                        contract/genesis-prev)
        body {"v" contract/protocol-version
              "seq" (inc (count log))
              "ts_ms" ts-ms
              "actor" actor
              "action" action
              "details" (if (contains? input :details) details {})
              "prev_hash" previous-hash}]
    (when-not (contract/valid-entry-body? body)
      (fail! "Daglog v1 entry body does not satisfy its contract" {:body body}))
    {:body body
     :canonical-body (json-v1/canonical-json-v1 body)
     :body-bytes (json-v1/utf8-code-units-v1
                  (json-v1/canonical-json-v1 body))})))

(defn finish-append-v1
  "Finish a prepared append with adapter-computed digest and HMAC hex values."
  [{:keys [body]} entry-hash entry-hmac]
  (when-not (and (contract/valid-entry-body? body)
                 (contract/valid-hash? entry-hash)
                 (contract/valid-hash? entry-hmac))
    (fail! "Invalid digest or HMAC for daglog v1 append" {}))
  (assoc body "hash" entry-hash "hmac" entry-hmac))

(defn body-of-entry-v1 [entry]
  (when (contract/valid-entry? entry)
    (select-keys entry contract/token-body-keys)))

(defn verify-entry-step-v1
  "Pure one-record verifier. `computed-hash` and `hmac-valid` are effect
  results. Internal consistency cannot prove that a complete log was not
  truncated; compare a trusted anchor for that property."
  [entry {:keys [expected-seq expected-prev-hash computed-hash hmac-valid?]}]
  (cond
    (not (contract/valid-entry? entry))
    {:valid false :reason :malformed-entry :at nil}

    (not= expected-seq (get entry "seq"))
    {:valid false :reason :bad-seq :at (get entry "seq")}

    (not= expected-prev-hash (get entry "prev_hash"))
    {:valid false :reason :broken-link :at (get entry "seq")}

    (or (not (string? computed-hash))
        (not= computed-hash (get entry "hash")))
    {:valid false :reason :bad-hash :at (get entry "seq")}

    (not (true? hmac-valid?))
    {:valid false :reason :bad-hmac :at (get entry "seq")}

    :else {:valid true :at (get entry "seq")}))

(defn verify-structure-v1
  "Check sequence and prev-hash links without claiming cryptographic or
  completeness proof. Adapters add digest/HMAC verification per step."
  [log]
  (when-not (vector? log)
    (fail! "Daglog v1 log must be a vector" {}))
  (loop [i 0 previous contract/genesis-prev]
    (if (>= i (count log))
      {:valid true
       :entries (count log)
       :head-hash (if (seq log) (get (first log) "hash") contract/genesis-prev)
       :tip-hash (if (seq log) (get (peek log) "hash") contract/genesis-prev)}
      (let [entry (nth log i)
            expected-seq (inc i)
            result (if (contract/valid-entry? entry)
                     (if (= expected-seq (get entry "seq"))
                       (if (= previous (get entry "prev_hash"))
                         {:valid true}
                         {:valid false :reason :broken-link :at expected-seq})
                       {:valid false :reason :bad-seq :at (get entry "seq")})
                     {:valid false :reason :malformed-entry :at nil})]
        (if (:valid result)
          (recur (inc i) (get entry "hash"))
          result)))))

(defn log->jsonl-v1
  "Export a structurally valid v1 vector as canonical JSONL. Each record is
  one line and the export ends in LF; no host map printer is involved."
  [log]
  (let [structure (verify-structure-v1 log)]
    (when-not (:valid structure)
      (fail! "Cannot export a structurally invalid daglog" structure))
    (if (empty? log)
      ""
      (str (str/join "\n"
                     (map #(json-v1/canonical-json-v1 %) log))
           "\n"))))

(defn- jsonl-lines-v1
  "Split a JSONL export into its lines.

  Framing is fail-closed: a non-empty export must end in LF, no line may be
  empty, and an unterminated final line is an error. An empty string is the
  canonical representation of an empty log and yields no lines. Only a truly
  empty line is rejected: a line consisting of JSON whitespace is handed to
  the JSON reader, which already rejects it as not a JSON v1 value."
  [s]
  (when-not (string? s)
    (fail! "JSONL v1 input must be a string" {}))
  (if (= "" s)
    []
    (do
      (when-not (= "\n" (subs s (dec (count s))))
        (fail! "A non-empty JSONL v1 export must end in LF" {}))
      ;; The loop must stop once the final LF has been consumed. Without the
      ;; `(>= start (count s))` guard, start reaches the end of a correctly
      ;; LF-terminated export, index-of finds no further LF, and a perfectly
      ;; valid export is rejected as "not LF terminated".
      (loop [start 0 lines []]
        (if (>= start (count s))
          lines
          (let [newline (str/index-of s "\n" start)]
            (when-not newline
              (fail! "JSONL v1 line is not LF terminated" {:offset start}))
            (let [line (subs s start newline)]
              (when (= "" line)
                (fail! "JSONL v1 must not contain blank records" {:offset start}))
              (recur (inc newline) (conj lines line)))))))))

(defn jsonl->log-v1
  "Parse restricted JSONL into v1 entries.

  Framing, JSON, and per-record entry contract failures throw. A structural
  failure (sequence gap or broken link) also throws, carrying the same
  `{:reason :at}` detail `verify-structure-v1` reports, so a half-consistent
  export never reaches a caller as if it were a verified log. Adapters
  surface that detail as a verification reason instead of a parse error."
  [s]
  (let [entries (->> (jsonl-lines-v1 s)
                     (mapv json-v1/parse-json-v1))]
    (doseq [entry entries]
      (when-not (contract/valid-entry? entry)
        (fail! "JSONL v1 record does not satisfy entry contract" {:entry entry})))
    (let [structure (verify-structure-v1 entries)]
      (when-not (:valid structure)
        (fail! "JSONL v1 export has an invalid structure" structure))
      entries)))

(defn jsonl->canonical-log-v1
  "Parse JSONL, require every line to already be canonical JSON v1, and
  apply the same fail-closed structural check as `jsonl->log-v1`."
  [s]
  (let [entries (->> (jsonl-lines-v1 s)
                     (mapv json-v1/parse-canonical-json-v1))]
    (doseq [entry entries]
      (when-not (contract/valid-entry? entry)
        (fail! "Canonical JSONL v1 record does not satisfy entry contract"
               {:entry entry})))
    (let [structure (verify-structure-v1 entries)]
      (when-not (:valid structure)
        (fail! "Canonical JSONL v1 export has an invalid structure" structure))
      entries)))

(defn log->utf8-v1 [log]
  (json-v1/utf8-code-units-v1 (log->jsonl-v1 log)))

(defn make-anchor-v1
  "Build a trusted-anchor candidate. The caller must independently verify the
  log and calculate `log-sha256` over the exact JSONL UTF-8 bytes."
  [log {:keys [log-id anchored-at-ms log-sha256]}]
  (let [structure (verify-structure-v1 log)]
    (when-not (:valid structure)
      (fail! "Cannot anchor a structurally invalid daglog" structure))
    (when (empty? log)
      (fail! "Cannot anchor an empty daglog" {}))
    (let [anchor {"v" contract/protocol-version
                  "kind" contract/anchor-kind
                  "log_id" log-id
                  "entries" (count log)
                  "head_hash" (get (first log) "hash")
                  "tip_hash" (get (peek log) "hash")
                  "log_sha256" log-sha256
                  "anchored_at_ms" anchored-at-ms}]
      (when-not (contract/valid-anchor? anchor)
        (fail! "Anchor does not satisfy v1 contract" {:anchor anchor}))
      anchor)))

(defn verify-anchor-completeness-v1
  "Compare an independently trusted anchor with a candidate log summary.
  This is the only portable truncation check; a chain alone cannot detect a
  valid prefix being presented as the whole log."
  [anchor {:keys [entries head-hash tip-hash log-sha256]}]
  (cond
    (not (contract/valid-anchor? anchor))
    {:valid false :reason :bad-anchor-shape}

    (not= (get anchor "entries") entries)
    {:valid false :reason :entry-count-mismatch :expected (get anchor "entries")
     :actual entries}

    (not= (get anchor "head_hash") head-hash)
    {:valid false :reason :head-mismatch}

    (not= (get anchor "tip_hash") tip-hash)
    {:valid false :reason :tip-mismatch}

    (not= (get anchor "log_sha256") log-sha256)
    {:valid false :reason :byte-digest-mismatch}

    :else {:valid true :reason nil}))

(defn anchor-export-v1 [anchor]
  (when-not (contract/valid-anchor? anchor)
    (fail! "Cannot export an invalid anchor" {}))
  (json-v1/canonical-json-v1 anchor))

(defn export-descriptor-v1
  "Describe two local export bytes for a future private endpoint. This does
  not upload anything and deliberately contains no cloud credentials."
  [_log anchor log-sha256 anchor-sha256]
  (let [descriptor {"v" contract/protocol-version
                    "log" {"filename" (contract/log-filename-v1
                                        (get anchor "log_id"))
                           "media_type" contract/log-media-type
                           "entries" (get anchor "entries")
                           "sha256" log-sha256}
                    "anchor" {"filename" (contract/anchor-filename-v1
                                            (get anchor "log_id"))
                              "media_type" contract/anchor-media-type
                              "sha256" anchor-sha256}}]
    (when-not (contract/valid-export-descriptor? descriptor)
      (fail! "Invalid export descriptor" {:descriptor descriptor}))
    descriptor))
