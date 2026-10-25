(asdf:defsystem "nrecon" :description "Top-level parent system for nrecon subsystems" :components ())
(asdf:defsystem "nrecon/core"
  :description "Core pipeline, module registry, and authorization policy for nrecon"
  :version "0.1.0"
  :license "MIT"
  :serial t
  :pathname "src/core/"
  :components
  ((:file "package")
   (:file "records")
   (:file "modules")
   (:file "authorization")
   (:file "pipeline"))
  :depends-on
  ("cl-dataflow-kit"
   "cl-concurrent-kit"
   "cl-boundary-kit"
   "cl-log-kit")
  :in-order-to
  ((asdf:test-op (asdf:test-op "nrecon/core-test"))))

(asdf:defsystem "nrecon/fuzz"
  :depends-on ("nrecon/core" "cl-concurrent-kit" "cl-boundary-kit"
               "cl-http-kit/client" "cl-regex-kit" "cl-resilience-kit"
               "cl-codec-kit")
  :serial t
  :pathname "src/fuzz/"
  :components
  ((:file "package")
   (:file "records")
   (:file "wordlist")
   (:file "template")
   (:file "matcher")
   (:file "transport")
   (:file "engine"))
  :in-order-to
  ((asdf:test-op (asdf:test-op "nrecon/fuzz-test"))))

(asdf:defsystem "nrecon/net"
  :depends-on
  ("nrecon/core" "cl-boundary-kit" "cl-pcap-kit" "cl-cffi-kit" "cffi")
  :serial t
  :pathname "src/net/"
  :components
  ((:file "package")
   (:file "records")
   (:file "dissector")
   (:file "protocols")
   (:file "discovery")
   (:file "capture"))
  :in-order-to
  ((asdf:test-op (asdf:test-op "nrecon/net-test"))))

(asdf:defsystem "nrecon/attack"
  :depends-on ("nrecon/core" "nrecon/net" "cl-boundary-kit" "cl-pcap-kit")
  :serial t
  :pathname "src/attack/"
  :components
  ((:file "package")
   (:file "frames")
   (:file "gate")
   (:file "module"))
  :in-order-to
  ((asdf:test-op (asdf:test-op "nrecon/attack-test"))))

(asdf:defsystem "nrecon/wire"
  :depends-on ("nrecon/core" "cl-json-kit" "cl-boundary-kit"
               "cl-concurrent-kit" "cl-date-kit")
  :serial t
  :pathname "src/wire/"
  :components
  ((:file "package")
   (:file "json-values")
   (:file "results")
   (:file "describe")
   (:file "dry-run")
   (:file "io")
   (:file "mcp"))
  :in-order-to
  ((asdf:test-op (asdf:test-op "nrecon/wire-test"))))

(asdf:defsystem "nrecon/tui"
  :depends-on
  ("nrecon/core" "cl-tui-kit" "cl-history-kit")
  :pathname "src/tui/"
  :components ())

(asdf:defsystem "nrecon/cli"
  :depends-on
  ("nrecon/core" "cl-cli" "cl-json-kit" "cl-concurrent-kit"
   "nrecon/fuzz" "nrecon/net" "nrecon/attack" "nrecon/wire")
  :serial t
  :pathname "src/cli/"
  :components ((:file "package") (:file "main"))
  :in-order-to
  ((asdf:test-op (asdf:test-op "nrecon/cli-test"))))

(asdf:defsystem "nrecon/core-test"
  :depends-on ("nrecon/core" "cl-weave")
  :serial t
  :pathname "tests/core/"
  :components
  ((:file "package")
   (:file "suite"))
  :perform (asdf:test-op (operation system)
    (declare (ignore operation system))
    (uiop:symbol-call :nrecon/core-test :run-tests)))
(asdf:defsystem "nrecon/wire-test"
  :depends-on ("nrecon/wire" "cl-weave")
  :serial t
  :pathname "src/wire/"
  :components ((:file "wire-tests"))
  :perform (asdf:test-op (operation system)
    (declare (ignore operation system))
    (uiop:symbol-call :nrecon/wire-test :run-tests)))
(asdf:defsystem "nrecon/net-test"
  :depends-on ("nrecon/net" "cl-weave")
  :serial t
  :pathname "src/net/"
  :components ((:file "net-tests"))
  :perform (asdf:test-op (operation system)
    (declare (ignore operation system))
    (uiop:symbol-call :nrecon/net-test :run-tests)))
(asdf:defsystem "nrecon/attack-test"
  :depends-on ("nrecon/attack" "cl-weave")
  :serial t
  :pathname "src/attack/"
  :components ((:file "attack-tests"))
  :perform (asdf:test-op (operation system)
    (declare (ignore operation system))
    (uiop:symbol-call :nrecon/attack-test :run-tests)))
(asdf:defsystem "nrecon/fuzz-test"
  :depends-on ("nrecon/fuzz" "cl-weave")
  :serial t
  :pathname "tests/fuzz/"
  :components ((:file "package") (:file "suite"))
  :perform (asdf:test-op (operation system)
    (declare (ignore operation system))
    (uiop:symbol-call :nrecon/fuzz-test :run-tests)))
(asdf:defsystem "nrecon/cli-test"
  :depends-on ("nrecon/cli" "cl-weave")
  :serial t
  :pathname "src/cli/"
  :components ((:file "cli-tests"))
  :perform (asdf:test-op (operation system)
                         (declare (ignore operation system))
                         (uiop:symbol-call :nrecon/cli-test :run-tests)))
(asdf:defsystem "nrecon/cli/executable"
  :depends-on ("nrecon/cli")
  :build-operation "program-op"
  :build-pathname "nrecon"
  :entry-point "nrecon.cli:main")
