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
  :depends-on
  ("nrecon/core" "cl-http-kit" "cl-regex-kit" "cl-resilience-kit")
  :pathname "src/fuzz/"
  :components ())

(asdf:defsystem "nrecon/net"
  :depends-on
  ("nrecon/core" "cl-pcap-kit")
  :pathname "src/net/"
  :components ())

(asdf:defsystem "nrecon/attack"
  :depends-on
  ("nrecon/core" "nrecon/net")
  :pathname "src/attack/"
  :components ())

(asdf:defsystem "nrecon/wire"
  :depends-on
  ("nrecon/core" "cl-json-kit")
  :pathname "src/wire/"
  :components ())

(asdf:defsystem "nrecon/tui"
  :depends-on
  ("nrecon/core" "cl-tui-kit" "cl-history-kit")
  :pathname "src/tui/"
  :components ())

(asdf:defsystem "nrecon/cli"
  :depends-on
  ("nrecon/core"
   "cl-cli"
   "nrecon/fuzz"
   "nrecon/net"
   "nrecon/attack"
   "nrecon/wire"
   "nrecon/tui")
  :pathname "src/cli/"
  :components ())

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
