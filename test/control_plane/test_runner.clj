(ns control-plane.test-runner
  "Entry point for the portable v1 JVM suite.

  The native v0 suites run under Babashka (`bb test`) because they depend on
  the cheshire/JVM runtime Babashka provides. This runner covers only the
  portable v1 surface, and it exits non-zero on any failure or error so CI
  cannot pass on a silently-skipped namespace.

  Clojure's reader absorbs an unbalanced `)` into the following form, so a
  `deftest` nested inside another `deftest` body is registered without
  `:test` metadata and silently never runs. The guard below turns that class
  of mistake into a hard failure instead of a quietly smaller test count."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :as t]
            control-plane.v1-test)
  (:gen-class))

(def test-namespaces
  "Namespace symbol paired with the classpath path of its source file."
  [['control-plane.v1-test "control_plane/v1_test.clj"]])

(defn- registered-test-count
  "Count vars in a namespace that actually carry `:test` metadata. Vars are
  looked up through `ns-publics`/`ns-interns` values, which are Vars, and a
  Var's own metadata is what `deftest` attaches `:test` to."
  [ns-sym]
  (count (filter #(:test (meta %)) (vals (ns-interns ns-sym)))))

(defn- source-deftest-count
  "Count top-level `(deftest` forms in a test source file. A `(deftest` the
  reader absorbed into a preceding form is invisible to `ns-interns`, so the
  two counts must agree."
  [path]
  (->> (str/split-lines (slurp (io/resource path)))
       (filter #(str/starts-with? % "(deftest"))
       count))

(defn- check-no-swallowed-tests
  "Fail loudly when a source `deftest` did not register as a real test."
  []
  (doseq [[ns-sym path] test-namespaces]
    (let [declared (source-deftest-count path)
          registered (registered-test-count ns-sym)]
      (when (not= declared registered)
        (throw (ex-info (str "deftest count mismatch for " ns-sym
                             ": " declared " declared in " path
                             " but " registered " registered as tests;"
                             " a form is probably unbalanced")
                        {:namespace ns-sym
                         :declared declared
                         :registered registered}))))))

(defn -main [& _args]
  (check-no-swallowed-tests)
  (let [result (apply t/run-tests (map first test-namespaces))
        failures (+ (:fail result 0) (:error result 0))]
    (when (pos? failures)
      (println "FAIL:" failures "failure(s)/error(s) across"
               (count test-namespaces) "namespace(s)"))
    (System/exit (if (zero? failures) 0 1))))
