(defpackage #:nrecon/cli-test
  (:use #:cl)
  (:shadowing-import-from #:cl-weave #:describe)
  (:import-from #:cl-weave #:expect #:it)
  (:import-from #:nrecon.core #:make-job)
  (:export #:run-tests))

(in-package #:nrecon/cli-test)

(defun %invoke-cli (arguments &optional (input ""))
  (let* ((*standard-input* (make-string-input-stream input))
         (stdout (make-string-output-stream))
         (stderr (make-string-output-stream))
         (code (cl-cli:run-app
                (nrecon.cli:make-app)
                :argv (cons "nrecon" arguments)
                :stdout stdout
                :stderr stderr
                :color :never
                :width 80)))
    (values code
            (get-output-stream-string stdout)
            (get-output-stream-string stderr))))

(defun %contains (string substring)
  (not (null (search substring string))))

(defun %mcp-discover-line ()
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}")

(describe "nrecon CLI commands"
  (it "renders a fuzz dry-run plan without executing HTTP requests"
    (multiple-value-bind (code output error-output)
        (%invoke-cli '("--format" "json"
                       "--dry-run"
                       "--lab"
                       "--allow-host" "example.invalid"
                       "--allow-action" "http"
                       "fuzz" "http://example.invalid/FUZZ"))
      (expect code :to-be 0)
      (expect (%contains output "\"dry_run\":true") :to-be t)
      (expect (%contains output "\"module\":\"fuzz\"") :to-be t)
      (expect error-output :to-equal "")))
  (it "prints the module manifest as JSON with describe --json"
    (multiple-value-bind (code output error-output)
        (%invoke-cli '("describe" "--json"))
      (expect code :to-be 0)
      (expect (%contains output "\"modules\"") :to-be t)
      (expect (%contains output "\"name\":\"fuzz\"") :to-be t)
      (expect error-output :to-equal "")))
  (it "formats the non-persistent session status through each wire result format"
    (dolist (format '("json" "ndjson" "table"))
      (multiple-value-bind (code output error-output)
          (%invoke-cli (list "--format" format "session"))
        (expect code :to-be 0)
        (expect (%contains output "ready") :to-be t)
        (expect (%contains output "session") :to-be t)
        (expect error-output :to-equal ""))))
  (it "serves MCP JSON-RPC over standard input and output and rejects oversized input"
    (multiple-value-bind (code output error-output)
        (%invoke-cli (list "serve" "--mcp") (concatenate (quote string)
                                                           (%mcp-discover-line)
                                                           (string #\Newline)))
      (expect code :to-be 0)
      (expect (%contains output "\"jsonrpc\":\"2.0\"") :to-be t)
      (expect (%contains output "\"supportedVersions\"") :to-be t)
      (expect error-output :to-equal ""))
    (let ((nrecon.cli::*mcp-max-line-bytes* 4))
      (multiple-value-bind (code output error-output)
          (%invoke-cli (list "serve" "--mcp") "12345")
        (expect code :to-be 2)
        (expect (%contains output "\"code\":-32700") :to-be t)
        (expect error-output :to-equal ""))))
  (it "denies an attack by default before the registered runner can send"
    (multiple-value-bind (code output error-output)
        (%invoke-cli '("--format" "json"
                       "attack"
                       "--action" "arp-spoof"
                       "--source-mac" "02:00:00:00:00:11"
                       "--target-mac" "02:00:00:00:00:22"
                       "--spoofed-ip" "192.0.2.1"
                       "192.0.2.10"))
      (expect code :to-be 2)
      (expect (%contains output "\"authorized\":false") :to-be t)
      (expect (%contains error-output "nrecon attack audit") :to-be t))
    (let* ((sent nil)
           (job (make-job :id "cli-deny"
                          :target "192.0.2.10"
                          :options '(:action :arp-spoof
                                     :source-mac "02:00:00:00:00:11"
                                     :target-mac "02:00:00:00:00:22"
                                     :spoofed-ip "192.0.2.1"
                                     :target-ip "192.0.2.10")))
           (outcome
             (handler-case
                 (progn
                   (nrecon.attack:run-attack
                    job
                    (list :target-lab-p t
                          :audit-fn (lambda (record)
                                      (declare (ignore record))
                                      t)
                          :sender (lambda (packet timeout)
                                    (declare (ignore packet timeout))
                                    (setf sent t)))))
               (nrecon.attack:attack-authorization-denied () :denied))))
      (expect outcome :to-be :denied)
      (expect sent :to-be nil))))

(describe "MCP console input bounds"
  (it "counts UTF-8 bytes before completing a line"
    (let ((nrecon.cli::*mcp-max-line-bytes* 2)
          (console
            (make-instance
             'nrecon.cli::%mcp-console
             :delegate (cl-boundary-kit:make-test-console)
             :input-stream (make-string-input-stream (format nil "é~%")))))
      (multiple-value-bind (line status)
          (cl-boundary-kit:console-read-line console)
        (expect line :to-equal "é")
        (expect status :to-be :line)))
    (let ((nrecon.cli::*mcp-max-line-bytes* 2)
          (console
            (make-instance
             'nrecon.cli::%mcp-console
             :delegate (cl-boundary-kit:make-test-console)
             :input-stream (make-string-input-stream (format nil "éé~%")))))
      (multiple-value-bind (line status)
          (cl-boundary-kit:console-read-line console)
        (expect line :to-be-null)
        (expect status :to-be :too-large)))))

(defun run-tests ()
  (let* ((plan (cl-weave:list-tests
                :reporter :sexp
                :stream (make-broadcast-stream)))
         (test-count (length plan)))
    (unless (plusp test-count)
      (error "The nrecon CLI test suite selected no tests."))
    (format t "~&Running ~D nrecon CLI tests.~%" test-count)
    (unless (cl-weave:run-all :reporter :spec :pass-with-no-tests nil)
      (error "One or more nrecon CLI tests failed."))
    (format t "~&Passed ~D nrecon CLI tests.~%" test-count)
    test-count))
