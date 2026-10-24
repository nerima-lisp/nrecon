(defpackage #:nrecon/core-test
  (:use #:cl #:nrecon.core)
  (:shadowing-import-from #:cl-weave #:describe)
  (:import-from #:cl-weave #:expect #:it)
  (:export #:run-tests))
