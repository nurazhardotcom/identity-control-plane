(ns control-plane.crypto-jvm
  "JVM effect adapter for the portable cryptographic ports. It uses explicit
  UTF-8 conversion and JCA primitives; it makes no claim that JVM strings,
  GC copies, provider internals, or caller-owned key arrays can be reliably
  wiped."
  (:require [control-plane.effect :as effect]
            [control-plane.json-v1 :as json-v1])
  (:import (java.security MessageDigest)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(def min-key-bytes 16)

(defn- fail! [message]
  (throw (IllegalArgumentException. message)))

(defn- byte-array? [x]
  (instance? (Class/forName "[B") x))

(defn unsigned-vector->bytes ^bytes [xs]
  (when-not (and (sequential? xs) (every? #(and (integer? %) (<= 0 %) (<= % 255)) xs))
    (fail! "Expected unsigned byte values"))
  (byte-array (map int xs)))

(defn bytes->unsigned-vector [bs]
  (when-not (byte-array? bs)
    (fail! "Expected a JVM byte array"))
  (mapv #(bit-and (long %) 0xFF) bs))

(defn utf8->bytes ^bytes [s]
  (unsigned-vector->bytes (json-v1/utf8-code-units-v1 s)))

(defn key->bytes ^bytes [key]
  (let [bs (cond
             (byte-array? key) key
             (string? key) (utf8->bytes key)
             :else (fail! "HMAC key must be UTF-8 bytes or a string"))]
    (when (< (alength ^bytes bs) min-key-bytes)
      (fail! (str "HMAC key must be >= " min-key-bytes " bytes")))
    bs))

(defn bytes->hex
  "Lowercase hexadecimal for a JVM byte array."
  ^String [^bytes bs]
  (let [digits (char-array (* 2 (alength bs)))]
    (dotimes [i (alength bs)]
      (let [b (bit-and (long (aget bs i)) 0xFF)
            hi (bit-shift-right b 4)
            lo (bit-and b 0x0F)]
        (aset digits (* 2 i) (nth "0123456789abcdef" hi))
        (aset digits (inc (* 2 i)) (nth "0123456789abcdef" lo))))
    (String. digits)))

(def ^:private hex-nibbles
  (into {} (map-indexed (fn [i c] [c i]) "0123456789abcdef")))

(defn- nibble [c]
  (let [v (get hex-nibbles c)]
    (when (nil? v)
      (fail! (str "Expected lowercase hexadecimal, found character: " c)))
    v))

(defn hex->bytes
  "Strict 64-character lowercase hexadecimal to a 32-byte array. Uppercase
  digits, wrong length, and unknown characters are rejected."
  ^bytes [hex]
  (when-not (and (string? hex) (= 64 (count hex)))
    (fail! "Expected a 64-character lowercase hexadecimal digest"))
  (let [bs (byte-array 32)]
    (dotimes [i 32]
      (aset bs i
            (unchecked-byte (bit-or (bit-shift-left (nibble (nth hex (* 2 i))) 4)
                                   (nibble (nth hex (inc (* 2 i))))))))
    bs))

(defn sha256-hex
  "Lowercase SHA-256 hex over a portable unsigned-byte sequence."
  ^String [input-bytes]
  (let [bs (unsigned-vector->bytes input-bytes)
        digest (MessageDigest/getInstance "SHA-256")]
    (bytes->hex (.digest digest bs))))

(defn hmac-sha256 ^bytes [key input-bytes]
  (let [k (key->bytes key)
        bs (unsigned-vector->bytes input-bytes)
        mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. k "HmacSHA256"))
    (.doFinal mac bs)))

(defn hmac-sha256-hex ^String [key input-bytes]
  (bytes->hex (hmac-sha256 key input-bytes)))

(defn verify-hmac?
  "Compare a computed HMAC with a 64-character lowercase hexadecimal
  signature over the raw 32 bytes. A malformed signature fails closed
  instead of throwing, so verification never depends on a thrown error."
  [key input-bytes signature-hex]
  (let [expected (hmac-sha256 key input-bytes)]
    (try
      (MessageDigest/isEqual expected (hex->bytes signature-hex))
      (catch IllegalArgumentException _ false))))

(def crypto
  (reify effect/CryptoPort
    (sha256-hex [_ input-bytes] (sha256-hex input-bytes))
    (hmac-sha256-hex [_ key-bytes input-bytes]
      (hmac-sha256-hex key-bytes input-bytes))))

(def system-clock
  (reify effect/ClockPort
    (now-ms [_] (System/currentTimeMillis))))
