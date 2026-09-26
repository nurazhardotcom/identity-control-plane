(ns control-plane.json-v1
  "Restricted, deterministic JSON v1 shared by Clojure and ClojureScript.

  The value grammar is intentionally small: nil, booleans, strings, safe
  integers, vectors, and string-keyed maps. Floating-point values, keywords,
  sets, other JavaScript values, non-scalar object keys, duplicate object
  names, and unpaired Unicode surrogates are rejected. Object names are
  ordered by Unicode scalar value, never by host map iteration order.

  Canonical strings are hashed only after conversion to the unsigned UTF-8
  byte vector returned by `utf8-code-units-v1`. JSON escaping is fixed and
  no Unicode normalization is performed."
  (:require [clojure.string :as str]))

(def max-safe-integer 9007199254740991)
(def min-safe-integer -9007199254740991)
(def max-depth 64)

(def ^:private hex-digits (vec "0123456789abcdef"))

(defn- fail! [message data]
  (throw (ex-info message (assoc data :type :json-v1))))

(defn- code-unit [s i]
  #?(:clj (long (.charAt ^String s i))
     :cljs (.charCodeAt s i)))

(defn- high-surrogate? [unit]
  (and (<= 0xD800 unit) (<= unit 0xDBFF)))

(defn- low-surrogate? [unit]
  (and (<= 0xDC00 unit) (<= unit 0xDFFF)))

(defn valid-string?
  "True when the host string contains Unicode scalar values only."
  [s]
  (boolean
   (and (string? s)
        (loop [i 0]
          (if (>= i (count s))
            true
            (let [unit (code-unit s i)]
              (cond
                (high-surrogate? unit)
                (and (< (inc i) (count s))
                     (low-surrogate? (code-unit s (inc i)))
                     (recur (+ i 2)))

                (low-surrogate? unit) false
                :else (recur (inc i)))))))))

(defn- require-string! [s]
  (when-not (valid-string? s)
    (fail! "JSON v1 strings must contain Unicode scalar values only" {}))
  s)

(defn- scalar-points
  "Return Unicode scalar values for a valid host string."
  [s]
  (require-string! s)
  (loop [i 0 points []]
    (if (>= i (count s))
      points
      (let [unit (code-unit s i)]
        (if (high-surrogate? unit)
          (let [low (code-unit s (inc i))]
            (recur (+ i 2)
                   (conj points (+ 0x10000
                                  (bit-shift-left (- unit 0xD800) 10)
                                  (- low 0xDC00)))))
          (recur (inc i) (conj points unit)))))))

(defn- compare-point-sequences [a b]
  (loop [as (seq a) bs (seq b)]
    (cond
      (and (nil? as) (nil? bs)) 0
      (nil? as) -1
      (nil? bs) 1
      :else
      (let [c (compare (long (first as)) (long (first bs)))]
        (if (zero? c)
          (recur (next as) (next bs))
          c)))))

(defn- compare-scalar-names [a b]
  (compare-point-sequences (scalar-points a) (scalar-points b)))

(defn- insert-scalar-name [names name]
  (loop [i 0 result names]
    (if (or (>= i (count result))
            (neg? (compare-scalar-names name (nth result i))))
      (vec (concat (subvec (vec result) 0 i)
                   [name]
                   (subvec (vec result) i)))
      (recur (inc i) result))))

(defn- sorted-scalar-names [names]
  (reduce insert-scalar-name [] names))

(defn- json-string [s]
  (require-string! s)
  (str "\""
       (apply str
         (reduce (fn [chars unit]
                   (cond
                     (= unit 0x22) (conj chars "\\\"")
                     (= unit 0x5C) (conj chars "\\\\")
                     (= unit 0x08) (conj chars "\\b")
                     (= unit 0x09) (conj chars "\\t")
                     (= unit 0x0A) (conj chars "\\n")
                     (= unit 0x0C) (conj chars "\\f")
                     (= unit 0x0D) (conj chars "\\r")
                     (< unit 0x20)
                     (conj chars (str "\\u"
                                       (hex-digits (bit-shift-right unit 12))
                                       (hex-digits (bit-and (bit-shift-right unit 8) 0x0F))
                                       (hex-digits (bit-and (bit-shift-right unit 4) 0x0F))
                                       (hex-digits (bit-and unit 0x0F))))
                     (or (= unit 0x2028) (= unit 0x2029))
                     (conj chars (if (= unit 0x2028) "\\u2028" "\\u2029"))
                     (< unit 0x10000) (conj chars (char unit))
                     :else
                     (let [adjusted (- unit 0x10000)
                           high (+ 0xD800 (bit-shift-right adjusted 10))
                           low (+ 0xDC00 (bit-and adjusted 0x3FF))]
                       (conj chars (char high) (char low)))))
                 []
                 (scalar-points s)))
       "\""))

(defn safe-integer? [x]
  (and (integer? x)
       (<= min-safe-integer x)
       (<= x max-safe-integer)))

(def ^:private safe-magnitude-text "9007199254740991")

(defn- within-safe-range?
  "Check an already-validated integer literal against the portable safe range
  by comparing decimal text, before any host number conversion. Without this,
  a 16-digit literal above 2^53 would be silently rounded by a
  double-based host and could pass `safe-integer?` with the wrong value."
  [text]
  (let [negative? (str/starts-with? text "-")
        digits (if negative? (subs text 1) text)
        digit-count (count digits)]
    (if (< digit-count 16)
      true
      (and (= digit-count 16)
           (not (pos? (compare digits safe-magnitude-text)))))))

(defn valid-value?
  "Check a value against the portable JSON v1 value grammar."
  ([x] (valid-value? x 0))
  ([x depth]
   (and (<= depth max-depth)
        (cond
          (or (nil? x) (boolean? x) (string? x)) (or (not (string? x))
                                                        (valid-string? x))
          (safe-integer? x) true
          (vector? x) (every? #(valid-value? % (inc depth)) x)
          (map? x) (and (every? string? (keys x))
                        (every? #(valid-string? %) (keys x))
                        (every? #(valid-value? % (inc depth)) (vals x)))
          :else false))))

(defn- write-value-v1 [value depth]
  (when (> depth max-depth)
    (fail! "JSON v1 nesting exceeds 64 levels" {:depth depth}))
  (cond
    (nil? value) "null"
    (true? value) "true"
    (false? value) "false"
    (string? value) (json-string value)
    (safe-integer? value) (str value)
    (vector? value)
    (str "[" (str/join "," (map #(write-value-v1 % (inc depth)) value)) "]")
    (map? value)
    (do
      (when-not (every? string? (keys value))
        (fail! "JSON v1 object names must be strings" {}))
      (when-not (every? valid-string? (keys value))
        (fail! "JSON v1 object names must be valid Unicode strings" {}))
      (str "{"
           (str/join
            ","
            (map (fn [k]
                   (str (json-string k) ":"
                        (write-value-v1 (get value k) (inc depth))))
                 (sorted-scalar-names (keys value))))
           "}"))
    :else
    (fail! "Value is outside the restricted JSON v1 grammar" {})))

(defn canonical-json-v1
  "Serialize a restricted value to canonical JSON v1.

  No whitespace is emitted. Vectors represent arrays. Maps must have unique
  string keys (the host map type), and names sort by Unicode scalar value.
  The shortest JSON escape is used except that U+2028/U+2029 are always
  escaped for safe embedding in JavaScript."
  [x]
  (write-value-v1 x 0))

(defn utf8-code-units-v1
  "Encode a valid host string as unsigned UTF-8 code units in a vector.

  Adapters turn this portable vector into a JVM byte[] or a JavaScript
  Uint8Array. Rejecting unpaired surrogates here prevents host encoders from
  silently substituting U+FFFD and changing authenticated bytes."
  [s]
  (reduce (fn [bytes point]
            (cond
              (<= point 0x7F) (conj bytes point)
              (<= point 0x7FF)
              (conj bytes
                    (bit-or 0xC0 (bit-shift-right point 6))
                    (bit-or 0x80 (bit-and point 0x3F)))
              (<= point 0xFFFF)
              (conj bytes
                    (bit-or 0xE0 (bit-shift-right point 12))
                    (bit-or 0x80 (bit-and (bit-shift-right point 6) 0x3F))
                    (bit-or 0x80 (bit-and point 0x3F)))
              :else
              (conj bytes
                    (bit-or 0xF0 (bit-shift-right point 18))
                    (bit-or 0x80 (bit-and (bit-shift-right point 12) 0x3F))
                    (bit-or 0x80 (bit-and (bit-shift-right point 6) 0x3F))
                    (bit-or 0x80 (bit-and point 0x3F)))))
          []
          (scalar-points s)))

(defn- unsigned-byte? [x]
  (and (integer? x) (<= 0 x) (<= x 0xFF)))

(defn utf8-decode-v1
  "Strictly decode unsigned UTF-8 bytes (a sequential collection) to a
  string. Overlong forms, invalid continuation bytes, surrogate code points,
  and values above U+10FFFF are rejected."
  [bytes]
  (when-not (and (sequential? bytes) (every? unsigned-byte? bytes))
    (fail! "UTF-8 input must contain unsigned byte values" {}))
  (loop [i 0 units []]
    (if (>= i (count bytes))
      (apply str units)
      (let [b0 (long (nth bytes i))]
        (cond
          (<= b0 0x7F)
          (recur (inc i) (conj units (char b0)))

          (<= b0 0xC1)
          (fail! "Invalid UTF-8 lead byte" {:offset i})

          (<= b0 0xDF)
          (let [b1 (when (< (inc i) (count bytes))
                     (long (nth bytes (inc i))))]
            (when-not (and (some? b1) (<= 0x80 b1 0xBF))
              (fail! "Invalid UTF-8 continuation byte" {:offset (inc i)}))
            (recur (+ i 2)
                   (conj units
                         (char (bit-or
                                (bit-shift-left (bit-and b0 0x1F) 6)
                                (bit-and b1 0x3F))))))

          (<= b0 0xEF)
          (let [b1 (when (< (inc i) (count bytes))
                     (long (nth bytes (inc i))))
                b2 (when (< (+ i 2) (count bytes))
                     (long (nth bytes (+ i 2))))]
            (when-not (and (some? b1) (some? b2)
                           (<= 0x80 b1 0xBF) (<= 0x80 b2 0xBF))
              (fail! "Invalid UTF-8 continuation byte" {:offset i}))
            (let [point (bit-or (bit-shift-left (bit-and b0 0x0F) 12)
                                (bit-shift-left (bit-and b1 0x3F) 6)
                                (bit-and b2 0x3F))]
              (when (or (< point 0x800) (<= 0xD800 point 0xDFFF))
                (fail! "Invalid UTF-8 scalar value" {:offset i :scalar point}))
              (recur (+ i 3) (conj units (char point)))))

          (<= b0 0xF4)
          (let [b1 (when (< (inc i) (count bytes))
                     (long (nth bytes (inc i))))
                b2 (when (< (+ i 2) (count bytes))
                     (long (nth bytes (+ i 2))))
                b3 (when (< (+ i 3) (count bytes))
                     (long (nth bytes (+ i 3))))]
            (when-not (and (some? b1) (some? b2) (some? b3)
                           (<= 0x80 b1 0xBF) (<= 0x80 b2 0xBF)
                           (<= 0x80 b3 0xBF))
              (fail! "Invalid UTF-8 continuation byte" {:offset i}))
            (let [point (bit-or (bit-shift-left (bit-and b0 0x07) 18)
                                (bit-shift-left (bit-and b1 0x3F) 12)
                                (bit-shift-left (bit-and b2 0x3F) 6)
                                (bit-and b3 0x3F))]
              (when-not (<= 0x10000 point 0x10FFFF)
                (fail! "Invalid UTF-8 scalar value" {:offset i :scalar point}))
              (let [adjusted (- point 0x10000)]
                (recur (+ i 4)
                       (conj units
                             (char (+ 0xD800
                                         (bit-shift-right adjusted 10)))
                             (char (+ 0xDC00
                                         (bit-and adjusted 0x3FF))))))))

          :else
          (fail! "Invalid UTF-8 lead byte" {:offset i}))))))

;; --- Strict JSON parser ---------------------------------------------------

(declare parse-array parse-object)

(defn- whitespace? [unit]
  (or (= unit 0x20) (= unit 0x09) (= unit 0x0A) (= unit 0x0D)))

(defn- digit? [unit]
  (and (<= 0x30 unit) (<= unit 0x39)))

(defn- hex-value [unit]
  (cond
    (<= 0x30 unit 0x39) (- unit 0x30)
    (<= 0x41 unit 0x46) (- unit 0x37)
    (<= 0x61 unit 0x66) (- unit 0x57)
    :else nil))

(defn- literal [state literal-value value]
  (let [n (count literal-value)]
    (when-not (and (<= (+ (:i state) n) (count (:s state)))
                   (= literal-value
                      (subs (:s state) (:i state) (+ (:i state) n))))
      (fail! "Invalid JSON literal" {:offset (:i state)}))
    {:i (+ (:i state) n) :value value}))

(defn- parse-four-hex [state]
  (when (> (+ (:i state) 4) (count (:s state)))
    (fail! "Truncated Unicode escape" {:offset (:i state)}))
  (reduce (fn [unit offset]
            (let [v (hex-value (code-unit (:s state) (+ (:i state) offset)))]
              (when (nil? v)
                (fail! "Invalid Unicode escape" {:offset (+ (:i state) offset)}))
              (bit-or (bit-shift-left unit 4) v)))
          0
          (range 4)))

(defn- parse-string [state]
  (when-not (= (code-unit (:s state) (:i state)) 0x22)
    (fail! "Expected JSON string" {:offset (:i state)}))
  (loop [i (inc (:i state)) chars []]
    (when (>= i (count (:s state)))
      (fail! "Unterminated JSON string" {:offset i}))
    (let [unit (code-unit (:s state) i)]
      (cond
        (= unit 0x22) {:i (inc i) :value (apply str chars)}
        (< unit 0x20) (fail! "Unescaped control character in JSON string" {:offset i})
        (= unit 0x5C)
        (let [i (inc i)]
          (when (>= i (count (:s state)))
            (fail! "Unterminated JSON escape" {:offset i}))
          (let [escape (code-unit (:s state) i)
                simple (case escape
                         0x22 \" 0x5C \\ 0x2F / 0x62 \backspace
                         0x66 \formfeed 0x6E \newline 0x72 \return
                         0x74 \tab nil)]
            (if simple
              (recur (inc i) (conj chars simple))
              (do
                (when-not (= escape 0x75)
                  (fail! "Invalid JSON escape" {:offset i}))
                (let [u (parse-four-hex {:s (:s state) :i (inc i)})]
                  (cond
                    (high-surrogate? u)
                    (let [j (+ i 5)]
                      (when-not (and (< (+ j 5) (count (:s state)))
                                     (= 0x5C (code-unit (:s state) j))
                                     (= 0x75 (code-unit (:s state) (inc j))))
                        (fail! "High surrogate lacks an escaped low surrogate"
                               {:offset i}))
                      (let [low (parse-four-hex {:s (:s state) :i (+ j 2)})]
                        (when-not (low-surrogate? low)
                          (fail! "High surrogate lacks a low surrogate" {:offset i}))
                        (recur (+ j 6)
                               (conj chars (char u) (char low)))))

                    (low-surrogate? u)
                    (fail! "Unpaired low surrogate in JSON string" {:offset i})

                    :else
                    (recur (+ i 5) (conj chars (char u)))))))))
        (high-surrogate? unit)
        (let [low-index (inc i)]
          (when-not (and (< low-index (count (:s state)))
                         (low-surrogate? (code-unit (:s state) low-index)))
            (fail! "Unpaired high surrogate in JSON string" {:offset i}))
          (recur (+ i 2) (conj chars (char unit)
                                (char (code-unit (:s state) low-index)))))
        (low-surrogate? unit)
        (fail! "Unpaired low surrogate in JSON string" {:offset i})
        :else (recur (inc i) (conj chars (char unit)))))))

(defn- parse-number [state]
  (let [s (:s state)
        start (:i state)
        n (count s)
        negative? (= (code-unit s start) 0x2D)
        digit-start (if negative? (inc start) start)
        i (loop [i digit-start]
            (cond
              (>= i n) i
              (digit? (code-unit s i)) (recur (inc i))
              :else i))]
    (when (or (= digit-start i)
              (and (> (- i digit-start) 1)
                   (= 0x30 (code-unit s digit-start))))
      (fail! "Invalid JSON integer" {:offset start}))
    (let [text (subs s start i)]
      (when-not (within-safe-range? text)
        (fail! "JSON integer is outside the portable safe range" {:offset start}))
      (let [value #?(:clj (Long/parseLong text)
                     :cljs (js/Number text))]
        (when-not (safe-integer? value)
          (fail! "JSON integer is outside the portable safe range" {:offset start}))
        {:i i :value value}))))

(defn- skip-whitespace [s i]
  (loop [i i]
    (if (and (< i (count s)) (whitespace? (code-unit s i)))
      (recur (inc i))
      i)))

(defn- parse-value
  "Parse exactly one JSON value, skipping only leading whitespace. Returning
  immediately after a composite value is what makes trailing data such as
  `{} {}` an error instead of a silently accepted second value."
  [state depth]
  (when (> depth max-depth)
    (fail! "JSON nesting exceeds 64 levels" {:offset (:i state)}))
  (let [s (:s state)
        n (count s)
        i (skip-whitespace s (long (:i state)))]
    (when (>= i n)
      (fail! "Unexpected end of JSON input" {:offset i}))
    (let [unit (code-unit s i)]
      (cond
        (= unit 0x7B) (parse-object {:s s :i (inc i)} (inc depth))
        (= unit 0x5B) (parse-array {:s s :i (inc i)} (inc depth))
        (= unit 0x22) (parse-string {:s s :i i})
        (= unit 0x74) (literal {:s s :i i} "true" true)
        (= unit 0x66) (literal {:s s :i i} "false" false)
        (= unit 0x6E) (literal {:s s :i i} "null" nil)
        (or (digit? unit) (= unit 0x2D)) (parse-number {:s s :i i})
        :else (fail! "Unexpected JSON value" {:offset i})))))

(defn- parse-array [state depth]
  (let [s (:s state)
        i (skip-whitespace s (:i state))]
    (when (>= i (count s))
      (fail! "Unterminated JSON array" {:offset i}))
    (if (= (code-unit s i) 0x5D)
      {:i (inc i) :value []}
      (loop [i i values []]
        (let [parsed (parse-value {:s s :i i} (inc depth))
              j (skip-whitespace s (long (:i parsed)))]
          (when (>= j (count s))
            (fail! "Unterminated JSON array" {:offset j}))
          (cond
            (= (code-unit s j) 0x2C)
            (recur (skip-whitespace s (inc j)) (conj values (:value parsed)))

            (= (code-unit s j) 0x5D)
            {:i (inc j) :value (conj values (:value parsed))}

            :else (fail! "Expected comma or closing bracket" {:offset j})))))))

(defn- parse-object [state depth]
  (let [s (:s state)
        i (skip-whitespace s (:i state))]
    (when (>= i (count s))
      (fail! "Unterminated JSON object" {:offset i}))
    (if (= (code-unit s i) 0x7D)
      {:i (inc i) :value {}}
      (loop [i i value {}]
        (when (>= i (count s))
          (fail! "Unterminated JSON object" {:offset i}))
        (when-not (= (code-unit s i) 0x22)
          (fail! "Expected JSON object name" {:offset i}))
        (let [parsed-name (parse-string {:s s :i i})
              name (:value parsed-name)
              _ (when (contains? value name)
                  (fail! "Duplicate JSON object name" {:name name}))
              colon (skip-whitespace s (long (:i parsed-name)))]
          (when (or (>= colon (count s)) (not= (code-unit s colon) 0x3A))
            (fail! "Expected colon after object name" {:offset colon}))
          (let [parsed-value (parse-value
                              {:s s :i (skip-whitespace s (inc colon))}
                              (inc depth))
                delimiter (skip-whitespace s (long (:i parsed-value)))
                next-value (assoc value name (:value parsed-value))]
            (when (>= delimiter (count s))
              (fail! "Unterminated JSON object" {:offset delimiter}))
            (cond
              (= (code-unit s delimiter) 0x2C)
              (recur (skip-whitespace s (inc delimiter)) next-value)

              (= (code-unit s delimiter) 0x7D)
              {:i (inc delimiter) :value next-value}

              :else (fail! "Expected comma or closing brace"
                           {:offset delimiter}))))))))

(defn parse-json-v1
  "Parse restricted JSON v1. The returned data uses nil, booleans, strings,
  safe integer numbers, vectors, and string-keyed maps. Duplicate object
  names and every value outside the restricted grammar are rejected."
  [s]
  (when-not (string? s)
    (fail! "JSON input must be a string" {}))
  (let [parsed (parse-value {:s s :i 0} 0)
        rest-i (skip-whitespace s (long (:i parsed)))]
    (if (= rest-i (count s))
      (:value parsed)
      (fail! "Unexpected data after JSON value" {:offset rest-i}))))

(defn parse-canonical-json-v1
  "Parse restricted JSON and require byte-for-byte canonical text (after
  string decoding), with no leading or trailing whitespace."
  [s]
  (let [value (parse-json-v1 s)]
    (when-not (= s (canonical-json-v1 value))
      (fail! "JSON v1 input is not canonical" {}))
    value))
