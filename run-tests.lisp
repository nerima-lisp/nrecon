(require "asdf")

(let ((root
       (uiop:pathname-directory-pathname
        (or *load-truename* *load-pathname* (uiop:getcwd)))))
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,root) :inherit-configuration))
  (handler-case
      (progn
        (asdf:test-system "nrecon/core")
        (uiop:symbol-call :cl-weave :clear-tests)
        (asdf:test-system "nrecon/wire"))
    (error (condition)
      (format *error-output* "~&nrecon tests failed: ~A~%" condition)
      (finish-output *error-output*)
      (uiop:quit 1))))

(finish-output *standard-output*)
(uiop:quit 0)
