(in-package #:nrecon.wire)

(defparameter *mcp-timeout* (cl-date-kit:duration-of-seconds 30))

(defun %mcp-object (&rest pairs)
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr
          do (setf (gethash key object) value))
    object))

(defun %mcp-error-response (id code message &optional data)
  (let ((error-object (%mcp-object "code" code "message" message)))
    (when data
      (setf (gethash "data" error-object) data))
    (%mcp-object "jsonrpc" "2.0"
                 "id" id
                 "error" error-object)))

(defun %mcp-complete-result (fields)
  (setf (gethash "resultType" fields) "complete"
        (gethash "_meta" fields)
        (%mcp-object
         "io.modelcontextprotocol/serverInfo"
         (%mcp-object "name" "nrecon" "version" "0.1.0")))
  fields)

(defun %mcp-response (id result)
  (%mcp-object "jsonrpc" "2.0" "id" id "result" result))

(defun %mcp-request-version (params)
  (let ((meta (and (hash-table-p params) (gethash "_meta" params))))
    (unless (and (hash-table-p meta)
                 (stringp (gethash "io.modelcontextprotocol/protocolVersion" meta))
                 (hash-table-p
                  (gethash "io.modelcontextprotocol/clientCapabilities" meta)))
      (return-from %mcp-request-version
        (values nil :invalid-params)))
    (let ((version (gethash "io.modelcontextprotocol/protocolVersion" meta)))
      (unless (string= version "2026-07-28")
        (return-from %mcp-request-version
          (values version :unsupported-version)))
      (values version nil))))

(defun %mcp-tool-schema (schema)
  (let* ((copy (%json-value schema))
         (properties (gethash "properties" copy))
         (required (gethash "required" copy))
         (required-array
           (if (and (vectorp required) (not (stringp required)))
               required
               #())))
    (unless (hash-table-p properties)
      (error "Module input schema must define an object of properties."))
    (setf (gethash "target" properties)
          (%mcp-object "type" "string")
          (gethash "additionalProperties" copy)
          json-kit:+json-false+)
    (setf (gethash "required" copy)
          (if (find "target" required-array :test #'string=)
              required-array
              (concatenate 'vector required-array #("target"))))
    copy))

(defun %mcp-tools ()
  (let* ((manifest (describe-manifest))
         (modules (gethash "modules" manifest)))
    (map 'vector
         (lambda (module)
           (%mcp-object
            "name" (gethash "name" module)
            "description"
            (format nil "Run the nrecon ~A module for a target host."
                    (gethash "name" module))
            "inputSchema" (%mcp-tool-schema (gethash "schema" module))))
         modules)))

(defun %mcp-valid-arguments-p (module arguments)
  (let ((options (module-options module)))
    (block valid
      (maphash (lambda (key value)
                 (declare (ignore value))
                 (unless (and (stringp key)
                              (or (string= key "target")
                                  (some (lambda (option)
                                          (string= key
                                                   (etypecase option
                                                     (string option)
                                                     (symbol
                                                      (string-downcase
                                                       (symbol-name option))))))
                                        options)))
                   (return-from valid nil)))
               arguments)
      t)))

(defun %mcp-options (arguments)
  (let ((options (make-hash-table :test #'equal)))
    (maphash (lambda (key value)
               (unless (string= key "target")
                 (setf (gethash key options) (%json-value value))))
             arguments)
    options))

(defun %mcp-module-result (value)
  (if (typep value 'result)
      (%mcp-object "job_id" (%json-value (result-job-id value))
                   "status" (%json-value (result-status value))
                   "value" (%json-value (result-value value))
                   "metadata" (%json-value (result-metadata value)))
      (%json-value value)))

(defun %mcp-tool-response (id value &key is-error)
  (let* ((structured (%mcp-module-result value))
         (content
           (vector
            (%mcp-object "type" "text"
                         "text" (json-kit:stringify structured :sort-keys t))))
         (fields (%mcp-object "content" content
                              "isError" (if is-error
                                            t
                                            json-kit:+json-false+)
                              "structuredContent" structured)))
    (%mcp-response id (%mcp-complete-result fields))))

(defun %mcp-call-tool (id params authorization-policy target-lab-p timeout)
  (let ((name (gethash "name" params))
        (arguments (gethash "arguments" params)))
    (unless (and (stringp name) (hash-table-p arguments))
      (return-from %mcp-call-tool
        (%mcp-error-response id -32602 "Invalid tool call parameters.")))
    (let* ((module (find-module name))
           (target-host (gethash "target" arguments)))
      (unless module
        (return-from %mcp-call-tool
          (%mcp-error-response id -32602 "Unknown nrecon tool.")))
      (unless (%mcp-valid-arguments-p module arguments)
        (return-from %mcp-call-tool
          (%mcp-error-response id -32602 "Tool arguments contain an unknown option.")))
      (unless (stringp target-host)
        (return-from %mcp-call-tool
          (%mcp-error-response id -32602 "Tool arguments require a target string.")))
      (let* ((job (make-job :id id
                            :target target-host
                            :options (%mcp-options arguments)))
             (plan (plan-job name job
                             :authorization-policy authorization-policy
                             :target-lab-p target-lab-p)))
        (unless (eq (gethash "authorized" plan) t)
          (return-from %mcp-call-tool
            (%mcp-tool-response id plan :is-error t)))
        (check-type timeout cl-date-kit:duration)
        (unless (cl-date-kit:duration-positive-p timeout)
          (error "MCP timeout must be positive."))
        (handler-case
            (let* ((pipeline
                     (nrecon.core:make-cps-pipeline
                      (list (module-run module))))
                   (outcome
                     (multiple-value-bind (promise control)
                         (nrecon.core:run-cps-pipeline
                          pipeline job :timeout timeout)
                       (declare (ignore control))
                       (cl-concurrent-kit:await promise)))
                   (failed-p
                     (and (typep outcome 'result)
                          (not (eq (result-status outcome) :completed)))))
              (%mcp-tool-response id outcome :is-error failed-p))
          (error ()
            (%mcp-tool-response id "Tool execution failed." :is-error t)))))))

(defun handle-mcp-request (request
                           &key authorization-policy (target-lab-p nil)
                             (timeout *mcp-timeout*))
  (unless (hash-table-p request)
    (return-from handle-mcp-request
      (%mcp-error-response json-kit:+json-null+ -32600 "Invalid request.")))
  (multiple-value-bind (id has-id-p) (gethash "id" request)
    (unless has-id-p
      (return-from handle-mcp-request nil))
    (unless (or (stringp id)
                (numberp id)
                (eq id json-kit:+json-null+))
      (return-from handle-mcp-request
        (%mcp-error-response json-kit:+json-null+ -32600 "Invalid request.")))
    (unless (and (equal (gethash "jsonrpc" request) "2.0")
                 (stringp (gethash "method" request)))
      (return-from handle-mcp-request
        (%mcp-error-response id -32600 "Invalid request.")))
    (let ((params (gethash "params" request)))
      (multiple-value-bind (version error-kind)
          (%mcp-request-version params)
        (declare (ignore version))
        (when (eq error-kind :invalid-params)
          (return-from handle-mcp-request
            (%mcp-error-response id -32602 "Request metadata is invalid.")))
        (when (eq error-kind :unsupported-version)
          (return-from handle-mcp-request
            (%mcp-error-response
             id -32022 "Unsupported protocol version"
             (%mcp-object "supported" #("2026-07-28")
                          "requested"
                          (gethash "io.modelcontextprotocol/protocolVersion"
                                   (gethash "_meta" params))))))
        (cond
          ((string= (gethash "method" request) "server/discover")
           (%mcp-response
            id
            (%mcp-complete-result
             (%mcp-object "supportedVersions" #("2026-07-28")
                          "capabilities" (%mcp-object "tools" (%mcp-object))
                          "ttlMs" 0
                          "cacheScope" "private"))))
          ((string= (gethash "method" request) "tools/list")
           (%mcp-response
            id
            (%mcp-complete-result
             (%mcp-object "tools" (%mcp-tools)
                          "ttlMs" 0
                          "cacheScope" "private"))))
          ((string= (gethash "method" request) "tools/call")
           (if (hash-table-p params)
               (%mcp-call-tool id params authorization-policy target-lab-p timeout)
               (%mcp-error-response id -32602 "Tool call parameters are invalid.")))
          (t
           (%mcp-error-response id -32601 "Method not found.")))))))
