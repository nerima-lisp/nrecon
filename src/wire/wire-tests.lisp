(defpackage #:nrecon/wire-test
  (:use #:cl)
  (:shadowing-import-from #:cl-weave #:describe)
  (:import-from #:cl-weave #:expect #:it)
  (:import-from #:nrecon.core
   #:make-authorization-policy
   #:make-job
   #:make-result)
  (:import-from #:nrecon.wire
   #:describe-manifest
   #:handle-mcp-request
   #:plan-job
   #:render-plan
   #:render-results
   #:write-results)
  (:export #:run-tests))

(in-package #:nrecon/wire-test)

(defmacro with-wire-test-module ((run-count) &body body)
  `(let* ((registry nrecon.core::*module-registry*)
          (module-name "nrecon-wire-tests-fixture")
          (,run-count 0))
     (multiple-value-bind (previous-module present-p)
         (gethash module-name registry)
       (unwind-protect
            (progn
              (nrecon.core::%register-module
               (nrecon.core:make-module
                :name module-name
                :capabilities '(:scan)
                :options '(:target :depth)
                :run (lambda (&rest arguments)
                       (declare (ignore arguments))
                       (incf ,run-count)
                       :executed))
               :replace t)
              ,@body)
         (if present-p
             (setf (gethash module-name registry) previous-module)
             (remhash module-name registry))))))

(defmacro expect-string-snapshot (actual expected)
  `(expect ,actual
           :to-match-inline-snapshot
           (let ((*print-case* :downcase)
                 (*print-circle* t)
                 (*print-length* nil)
                 (*print-level* nil)
                 (*print-pretty* nil))
             (write-to-string ,expected :escape t :readably nil))))

(defun wire-test-results ()
  (list (make-result :job-id "result-1"
                     :status :completed
                     :value "ok"
                     :metadata nil)
        (make-result :job-id "result-2"
                     :status :failed
                     :value "timeout"
                     :metadata nil)))

(describe "nrecon wire result rendering"
  (it "renders a stable JSON array snapshot"
    (expect-string-snapshot
     (render-results (wire-test-results) :format :json)
     "[{\"job_id\":\"result-1\",\"metadata\":null,\"status\":\"completed\",\"value\":\"ok\"},{\"job_id\":\"result-2\",\"metadata\":null,\"status\":\"failed\",\"value\":\"timeout\"}]"))
  (it "renders one NDJSON event per line"
    (expect-string-snapshot
     (render-results (wire-test-results) :format :ndjson)
     (format nil "{\"job_id\":\"result-1\",\"metadata\":null,\"status\":\"completed\",\"value\":\"ok\"}~%{\"job_id\":\"result-2\",\"metadata\":null,\"status\":\"failed\",\"value\":\"timeout\"}")))
  (it "renders a stable human-readable table snapshot"
    (expect-string-snapshot
     (render-results (wire-test-results) :format :table)
     (format nil "job_id | status | value~%result-1 | completed | ok~%result-2 | failed | timeout~%"))))

(describe "nrecon wire manifest"
  (it "describes registered module capabilities, options, and schema"
    (with-wire-test-module (run-count)
      (let* ((manifest (describe-manifest))
             (modules (gethash "modules" manifest))
             (entry (find "nrecon-wire-tests-fixture"
                          modules
                          :key (lambda (module) (gethash "name" module))
                          :test #'string=)))
        (expect (not (null entry)) :to-be t)
        (expect-string-snapshot
         (json-kit:stringify entry :sort-keys t)
         "{\"capabilities\":[\"scan\"],\"name\":\"nrecon-wire-tests-fixture\",\"options\":[\"target\",\"depth\"],\"schema\":{\"additionalProperties\":false,\"properties\":{\"depth\":{},\"target\":{}},\"type\":\"object\"}}"))
      (expect run-count :to-be 0))))

(describe "nrecon wire dry-run planning"
  (it "renders a denied plan without invoking the module"
    (with-wire-test-module (run-count)
      (let* ((job (make-job :id "dry-run-1"
                            :target "example.invalid"
                            :options nil))
             (policy (make-authorization-policy
                      :actions '(:scan)
                      :allowlist '("example.invalid")))
             (plan (plan-job "nrecon-wire-tests-fixture"
                             job
                             :authorization-policy policy))
             (rendered (render-plan "nrecon-wire-tests-fixture"
                                    job
                                    :authorization-policy policy))
             (actions (gethash "actions" plan))
             (action (aref actions 0)))
        (expect (gethash "authorized" plan) :to-be json-kit:+json-false+)
        (expect (gethash "allowed" action) :to-be json-kit:+json-false+)
        (expect (gethash "reason" action) :to-equal "target-not-lab")
        (expect-string-snapshot
         rendered
         "{\"actions\":[{\"action\":\"scan\",\"allowed\":false,\"reason\":\"target-not-lab\"}],\"authorized\":false,\"dry_run\":true,\"job_id\":\"dry-run-1\",\"module\":\"nrecon-wire-tests-fixture\",\"target\":\"example.invalid\"}")
        (expect run-count :to-be 0)))))

(defun wire-mcp-request (id method params &optional (version "2026-07-28"))
  (let ((request-params (make-hash-table :test #'equal))
        (meta (make-hash-table :test #'equal)))
    (when params
      (maphash (lambda (key value)
                 (setf (gethash key request-params) value))
               params))
    (setf (gethash "io.modelcontextprotocol/protocolVersion" meta) version
          (gethash "io.modelcontextprotocol/clientCapabilities" meta)
          (make-hash-table :test #'equal)
          (gethash "_meta" request-params) meta)
    (let ((request (make-hash-table :test #'equal)))
      (setf (gethash "jsonrpc" request) "2.0"
            (gethash "id" request) id
            (gethash "method" request) method
            (gethash "params" request) request-params)
      request)))

(defun wire-mcp-arguments (&rest pairs)
  (let ((arguments (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr
          do (setf (gethash key arguments) value))
    arguments))

(describe "nrecon wire MCP request handling"
  (it "discovers its supported stateless protocol"
    (let* ((response (handle-mcp-request
                      (wire-mcp-request 1 "server/discover" nil)))
           (result (gethash "result" response)))
      (expect (gethash "jsonrpc" response) :to-equal "2.0")
      (expect (aref (gethash "supportedVersions" result) 0)
              :to-equal "2026-07-28")
      (expect (gethash "resultType" result) :to-equal "complete")
      (expect (gethash "ttlMs" result) :to-equal 0)))
  (it "lists modules with a required target field"
    (with-wire-test-module (run-count)
      (let* ((response (handle-mcp-request
                        (wire-mcp-request 2 "tools/list" nil)))
             (tools (gethash "tools" (gethash "result" response)))
             (tool (find "nrecon-wire-tests-fixture"
                         tools
                         :key (lambda (entry) (gethash "name" entry))
                         :test #'string=))
             (schema (gethash "inputSchema" tool)))
        (expect (not (null tool)) :to-be t)
        (expect (gethash "type" (gethash "target" (gethash "properties" schema)))
                :to-equal "string")
        (expect (find "target" (gethash "required" schema) :test #'string=)
                :to-equal "target")
        (expect run-count :to-be 0))))
  (it "denies tool calls by default without invoking a module"
    (with-wire-test-module (run-count)
      (let* ((params (wire-mcp-arguments
                      "name" "nrecon-wire-tests-fixture"
                      "arguments" (wire-mcp-arguments "target" "example.invalid")))
             (response (handle-mcp-request
                        (wire-mcp-request 3 "tools/call" params)))
             (result (gethash "result" response)))
        (expect (gethash "isError" result) :to-be t)
        (expect (gethash "authorized" (gethash "structuredContent" result))
                :to-be json-kit:+json-false+)
        (expect run-count :to-be 0))))
  (it "rejects undeclared tool options"
    (with-wire-test-module (run-count)
      (let* ((params (wire-mcp-arguments
                      "name" "nrecon-wire-tests-fixture"
                      "arguments" (wire-mcp-arguments
                                   "target" "example.invalid"
                                   "unknown" t)))
             (response (handle-mcp-request
                        (wire-mcp-request 4 "tools/call" params))))
        (expect (gethash "code" (gethash "error" response)) :to-be -32602)
        (expect run-count :to-be 0))))
  (it "runs only an allowlisted lab tool and returns its value"
    (with-wire-test-module (run-count)
      (let* ((params (wire-mcp-arguments
                      "name" "nrecon-wire-tests-fixture"
                      "arguments" (wire-mcp-arguments
                                   "target" "example.invalid"
                                   "depth" 2)))
             (policy (make-authorization-policy
                      :actions '(:scan)
                      :allowlist '("example.invalid")))
             (response (handle-mcp-request
                        (wire-mcp-request 5 "tools/call" params)
                        :authorization-policy policy
                        :target-lab-p t
                        :timeout (cl-date-kit:duration-of-seconds 1)))
             (result (gethash "result" response)))
        (expect (gethash "isError" result) :to-be json-kit:+json-false+)
        (expect (gethash "structuredContent" result) :to-equal "executed")
        (expect run-count :to-be 1))))
  (it "rejects unsupported protocol versions"
    (let* ((response (handle-mcp-request
                      (wire-mcp-request 6 "server/discover" nil "1900-01-01")))
           (error-object (gethash "error" response))
           (supported (gethash "supported" (gethash "data" error-object))))
      (expect (gethash "code" error-object) :to-be -32022)
      (expect (length supported) :to-be 1)
      (expect (aref supported 0) :to-equal "2026-07-28"))))

(describe "nrecon wire boundary output"
  (it "writes NDJSON events through the boundary console one line at a time"
    (let* ((console (cl-boundary-kit:make-test-console))
           (results (wire-test-results)))
      (write-results results :format :ndjson :console console)
      (expect (cl-boundary-kit:test-console-output console)
              :to-equal
              (list
               "{\"job_id\":\"result-1\",\"metadata\":null,\"status\":\"completed\",\"value\":\"ok\"}"
               "{\"job_id\":\"result-2\",\"metadata\":null,\"status\":\"failed\",\"value\":\"timeout\"}"))))
  (it "preserves JSON false and null values during normalization"
    (expect-string-snapshot
     (render-results
      (list (make-result :job-id "sentinels"
                         :value json-kit:+json-false+
                         :metadata json-kit:+json-null+)))
     "[{\"job_id\":\"sentinels\",\"metadata\":null,\"status\":\"completed\",\"value\":false}]")))

(defun run-tests ()
  (let* ((plan (cl-weave:list-tests
                :reporter :sexp
                :stream (make-broadcast-stream)))
         (selected-count (length plan)))
    (unless (plusp selected-count)
      (error "The nrecon wire test suite selected no tests."))
    (format t "~&Selected ~D nrecon wire tests.~%" selected-count)
    (let* ((events (cl-weave:run nil :reporter :spec :stream *standard-output*))
           (normalized (cl-weave::normalize-run-results events))
           (passed-count (count :pass normalized
                                :key #'cl-weave::test-event-status)))
      (format t "Passed ~D of ~D selected nrecon wire tests.~%"
              passed-count selected-count)
      (unless (and (= selected-count (length normalized))
                   (= selected-count passed-count))
        (error "The nrecon wire test suite passed ~D of ~D selected tests."
               passed-count selected-count))
      passed-count)))
