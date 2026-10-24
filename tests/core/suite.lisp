(in-package #:nrecon/core-test)

(defun %test-module-run (input context)
  (declare (ignore context))
  input)

(define-module core-test-module
  :capabilities (:read)
  :options (:target)
  :run %test-module-run)

(describe "nrecon core records"
  (it "constructs independent job and result data"
    (let* ((options (list :depth 2))
           (job (make-job :id "job-1" :target "lab.example" :options options))
           (result (make-result :job-id (job-id job)
                                :value '(:hosts ("lab.example"))
                                :metadata (list :source "fixture"))))
      (setf (getf options :depth) 9)
      (expect (job-options job) :to-equal '(:depth 2))
      (expect (job-target job) :to-equal "lab.example")
      (expect (result-job-id result) :to-equal "job-1")
      (expect (result-status result) :to-be :completed)
      (expect (result-value result) :to-equal '(:hosts ("lab.example"))))))

(describe "module declarations"
  (it "registers module metadata and its run continuation"
    (let ((module (find-module 'core-test-module)))
      (expect (module-name module) :to-equal "core-test-module")
      (expect (module-capabilities module) :to-equal '(:read))
      (expect (module-options module) :to-equal '(:target))
      (expect (funcall (module-run module) :input nil) :to-be :input)
      (expect (not (null (member module (list-modules) :test #'eq))) :to-be t))))

(describe "CPS dataflow pipelines"
  (it "passes synchronous stage results to the terminal continuation"
    (let* ((pipeline
             (make-cps-pipeline
              (list (lambda (input context)
                      (declare (ignore context))
                      (+ input 3))
                    (lambda (input context)
                      (declare (ignore context))
                      (* input 4)))))
           (result
             (run-cps-pipeline
              pipeline 2
              :continuation
              (lambda (value context)
                (declare (ignore context))
                (1+ value)))))
      (expect result :to-be 21)))
  (it "chains pending promises before invoking later stages"
    (let* ((pending (cl-concurrent-kit:make-promise))
           (pipeline
             (make-cps-pipeline
              (list (lambda (input context)
                      (declare (ignore input context))
                      pending)
                    (lambda (input context)
                      (declare (ignore context))
                      (+ input 2)))))
           (result (run-cps-pipeline pipeline :start)))
      (expect (cl-concurrent-kit:promise-p result) :to-be t)
      (expect (cl-concurrent-kit:promise-settled-p result) :to-be nil)
      (cl-concurrent-kit:deliver pending 40)
      (expect (cl-concurrent-kit:await result) :to-be 42)))
  (it "routes fan-out results into distinct merge ports"
    (let* ((pipeline
             (make-cps-pipeline
              (list
               (cl-dataflow-kit:make-node
                "source"
                :inputs '("input")
                :outputs '("value")
                :handler
                (lambda (input context)
                  (declare (ignore context))
                  input))
               (cl-dataflow-kit:make-node
                "left"
                :inputs '("input")
                :outputs '("value")
                :handler
                (lambda (input context)
                  (declare (ignore context))
                  (1+ input)))
               (cl-dataflow-kit:make-node
                "right"
                :inputs '("input")
                :outputs '("value")
                :handler
                (lambda (input context)
                  (declare (ignore context))
                  (* input 2)))
               (cl-dataflow-kit:make-node
                "merge"
                :inputs '("left" "right")
                :outputs '("value")
                :handler
                (lambda (inputs context)
                  (declare (ignore context))
                  (list :left (cdr (assoc "left" inputs :test #'string=))
                        :right (cdr (assoc "right" inputs :test #'string=))))))
              :edges
              (list
               (cl-dataflow-kit:make-edge
                "source" "left" :from-port "value" :to-port "input")
               (cl-dataflow-kit:make-edge
                "source" "right" :from-port "value" :to-port "input")
               (cl-dataflow-kit:make-edge
                "left" "merge" :from-port "value" :to-port "left")
               (cl-dataflow-kit:make-edge
                "right" "merge" :from-port "value" :to-port "right")))))
      (expect (run-cps-pipeline pipeline 10)
              :to-equal
              '(:left 11 :right 20))))
  (it "runs sibling handlers concurrently when requested"
    (let* ((barrier (cl-concurrent-kit:make-barrier 2))
           (timeout (cl-date-kit:duration-of-seconds 2))
           (pipeline
             (make-cps-pipeline
              (list
               (cl-dataflow-kit:make-node
                "source"
                :inputs '("input")
                :outputs '("value")
                :handler
                (lambda (input context)
                  (declare (ignore context))
                  input))
               (cl-dataflow-kit:make-node
                "left"
                :inputs '("input")
                :outputs '("value")
                :handler
                (lambda (input context)
                  (declare (ignore context))
                  (cl-concurrent-kit:await-barrier
                   barrier :timeout timeout)
                  (1+ input)))
               (cl-dataflow-kit:make-node
                "right"
                :inputs '("input")
                :outputs '("value")
                :handler
                (lambda (input context)
                  (declare (ignore context))
                  (cl-concurrent-kit:await-barrier
                   barrier :timeout timeout)
                  (+ input 2)))
               (cl-dataflow-kit:make-node
                "merge"
                :inputs '("left" "right")
                :outputs '("value")
                :handler
                (lambda (inputs context)
                  (declare (ignore context))
                  (+ (cdr (assoc "left" inputs :test #'string=))
                     (cdr (assoc "right" inputs :test #'string=))))))
              :edges
              (list
               (cl-dataflow-kit:make-edge
                "source" "left" :from-port "value" :to-port "input")
               (cl-dataflow-kit:make-edge
                "source" "right" :from-port "value" :to-port "input")
               (cl-dataflow-kit:make-edge
                "left" "merge" :from-port "value" :to-port "left")
               (cl-dataflow-kit:make-edge
                "right" "merge" :from-port "value" :to-port "right")))))
      (expect (run-cps-pipeline pipeline 0 :parallel t) :to-be 3))))

(describe "authorization policy"
  (it "allows an in-scope lab host under the default lab-only policy"
    (let* ((policy (make-authorization-policy
                    :actions '(:scan)
                    :allowlist '("example.com")))
           (target (make-authorization-target
                    :host "api.example.com"
                    :lab-p t))
           (decision (authorize-action policy :scan target)))
      (expect (authorization-decision-allowed-p decision) :to-be t)
      (expect (authorization-decision-reason decision) :to-be :allowed)))
  (it "allows an allowlisted target when lab-only mode is disabled"
    (let* ((policy (make-authorization-policy
                    :actions '(:scan)
                    :allowlist '("example.com")
                    :lab-only-p nil))
           (target (make-authorization-target :host "example.com" :lab-p nil))
           (decision (authorize-action policy :scan target)))
      (expect (authorization-decision-allowed-p decision) :to-be t)
      (expect (authorization-decision-reason decision) :to-be :allowed)))
  (it "denies a hostname that only shares an allowlist suffix"
    (let* ((policy (make-authorization-policy
                    :actions '(:scan)
                    :allowlist '("example.com")))
           (target (make-authorization-target :host "notexample.com" :lab-p t))
           (decision (authorize-action policy :scan target)))
      (expect (authorization-decision-allowed-p decision) :to-be nil)
      (expect (authorization-decision-reason decision)
              :to-be
              :target-not-allowlisted)))
  (it "denies actions outside the configured scope"
    (let* ((policy (make-authorization-policy
                    :actions '(:scan)
                    :allowlist '("example.com")))
           (target (make-authorization-target
                    :host "example.com"
                    :lab-p t))
           (decision (authorize-action policy :capture target)))
      (expect (authorization-decision-allowed-p decision) :to-be nil)
      (expect (authorization-decision-reason decision)
              :to-be
              :action-out-of-scope)))
  (it "denies a policy without an allowlist"
    (let* ((policy (make-authorization-policy :actions '(:scan)))
           (target (make-authorization-target :host "example.com" :lab-p t))
           (decision (authorize-action policy :scan target)))
      (expect (authorization-decision-allowed-p decision) :to-be nil)
      (expect (authorization-decision-reason decision) :to-be :empty-allowlist)))
  (it "denies a missing target"
    (let* ((policy (make-authorization-policy
                    :actions '(:scan)
                    :allowlist '("example.com")))
           (decision (authorize-action policy :scan nil)))
      (expect (authorization-decision-allowed-p decision) :to-be nil)
      (expect (authorization-decision-reason decision) :to-be :target-required)))
  (it "denies a target outside the allowlist"
    (let* ((policy (make-authorization-policy
                    :actions '(:scan)
                    :allowlist '("example.com")))
           (target (make-authorization-target :host "other.example" :lab-p t))
           (decision (authorize-action policy :scan target)))
      (expect (authorization-decision-allowed-p decision) :to-be nil)
      (expect (authorization-decision-reason decision)
              :to-be
              :target-not-allowlisted)))
  (it "requires an explicit lab marker by default"
    (let* ((policy (make-authorization-policy
                    :actions '(:scan)
                    :allowlist '("example.com")))
           (target (make-authorization-target :host "example.com"))
           (decision (authorize-action policy :scan target)))
      (expect (authorization-decision-allowed-p decision) :to-be nil)
      (expect (authorization-decision-reason decision) :to-be :target-not-lab)))
  (it "matches IPv4 addresses against CIDR ranges"
    (let* ((policy (make-authorization-policy
                    :actions '(:scan)
                    :allowlist '("192.168.10.17/24")))
           (target (make-authorization-target
                    :host "192.168.10.99"
                    :lab-p t))
           (decision (authorize-action policy :scan target)))
      (expect (authorization-decision-allowed-p decision) :to-be t)))
  (it "fails closed for unsupported allowlist forms"
    (let* ((policy (make-authorization-policy
                    :actions '(:scan)
                    :allowlist '("https://example.com")))
           (target (make-authorization-target
                    :host "example.com"
                    :lab-p t))
           (decision (authorize-action policy :scan target)))
      (expect (authorization-decision-allowed-p decision) :to-be nil)
      (expect (authorization-decision-reason decision)
              :to-be
              :target-not-allowlisted))))

(defun run-tests ()
  (let* ((plan (cl-weave:list-tests
                :reporter :sexp
                :stream (make-broadcast-stream)))
         (test-count (length plan)))
    (unless (plusp test-count)
      (error "The nrecon core test suite selected no tests."))
    (format t "~&Running ~D nrecon core tests.~%" test-count)
    (unless (cl-weave:run-all :reporter :spec :pass-with-no-tests nil)
      (error "One or more nrecon core tests failed."))
    (format t "~&Passed ~D nrecon core tests.~%" test-count)
    test-count))
