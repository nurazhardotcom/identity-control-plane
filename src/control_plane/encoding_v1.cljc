(ns control-plane.encoding-v1
  "Strict unpadded base64url over unsigned byte vectors. This portable codec
  is shared by JVM and browser adapters so token envelopes never depend on a
  host decoder's tolerance."
  (:require [control-plane.json-v1 :as json-v1]))

(def ^:private alphabet
  (vec "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"))

(def ^:private decode-table
  (into {} (map-indexed (fn [i c] [c i]) alphabet)))

(defn- fail! [message data]
  (throw (ex-info message (assoc data :type :base64url-v1))))

(defn- unsigned-byte? [x]
  (and (integer? x) (<= 0 x) (<= x 0xFF)))

(defn encode-base64url-v1
  "Encode a sequential collection of unsigned bytes without padding."
  [bytes]
  (when-not (and (sequential? bytes) (every? unsigned-byte? bytes))
    (fail! "Base64url input must contain unsigned byte values" {}))
  (let [input-bits (for [b bytes bit (range 7 -1 -1)]
                     (bit-and (bit-shift-right (long b) bit) 1))]
    (loop [xs (seq input-bits) buffer 0 bits 0 out []]
      (if-not xs
        (apply str
               (if (pos? bits)
                 (conj out
                       (alphabet (bit-and (bit-shift-left buffer (- 6 bits)) 63)))
                 out))
        (let [buffer' (bit-or (bit-shift-left buffer 1) (long (first xs)))
              bits' (inc bits)]
          (if (= bits' 6)
            (recur (next xs) 0 0 (conj out (alphabet (bit-and buffer' 63))))
            (recur (next xs) buffer' bits' out)))))))

(defn decode-base64url-v1
  "Decode strict unpadded base64url. Padding, whitespace, non-alphabet
  characters, impossible lengths, and non-zero discarded tail bits fail."
  [s]
  (when-not (string? s)
    (fail! "Base64url input must be a string" {}))
  (let [n (count s)]
    (when (and (pos? n) (= 1 (mod n 4)))
      (fail! "Base64url input has impossible length" {:length n}))
    (let [values (mapv (fn [i]
                         (let [c (first (subs s i (inc i)))
                               v (get decode-table c)]
                           (when (nil? v)
                             (fail! "Invalid base64url character"
                                    {:offset i :character c}))
                           v))
                       (range n))
          discarded-bits (if (zero? n) 0 (mod (* 6 n) 8))
          tail-mask (dec (bit-shift-left 1 discarded-bits))
          last-value (peek values)]
      (when (and (pos? discarded-bits)
                 (not= 0 (bit-and (long last-value) tail-mask)))
        (fail! "Base64url input has non-zero discarded bits" {}))
      (let [input-bits (for [value values bit (range 5 -1 -1)]
                         (bit-and (bit-shift-right (long value) bit) 1))]
        (loop [xs (seq input-bits) buffer 0 bits 0 out []]
          (if-not xs
            (if (= bits discarded-bits)
              out
              (fail! "Base64url input ended mid-quantum"
                     {:remaining-bits bits
                      :expected-discarded-bits discarded-bits}))
            (let [buffer' (bit-or (bit-shift-left buffer 1) (long (first xs)))
                  bits' (inc bits)]
              (if (= bits' 8)
                (recur (next xs) 0 0 (conj out (bit-and buffer' 0xFF)))
                (recur (next xs) buffer' bits' out)))))))))

(defn encode-utf8-base64url-v1 [s]
  (encode-base64url-v1 (json-v1/utf8-code-units-v1 s)))

(defn decode-utf8-base64url-v1 [s]
  (json-v1/utf8-decode-v1 (decode-base64url-v1 s)))
