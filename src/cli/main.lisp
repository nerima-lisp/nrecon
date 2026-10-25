(in-package #:nrecon.cli)

(defparameter +output-formats+ '("json" "ndjson" "table"))
(defparameter *mcp-max-line-bytes* (* 16 1024 1024))
(defparameter +authorization-actions+
  '("http" "passive-capture" "arp-spoof" "dns-spoof" "mitm-proxy"))

(defun %object (&rest pairs)
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr
          do (setf (gethash key object) value))
    object))

(defun %format-keyword (invocation)
  (intern (string-upcase (or (option-value invocation :format) "json"))
          :keyword))

(defun %authorization-actions (invocation)
  (mapcar (lambda (name) (intern (string-upcase name) :keyword))
          (option-value invocation :allow-action)))

(defun %authorization-policy (invocation)
  (nrecon.core:make-authorization-policy
   :actions (%authorization-actions invocation)
   :allowlist (option-value invocation :allow-host)))

(defun %json-boolean (value)
  (if value t json-kit:+json-false+))

(defun %emit-results (invocation results)
  (write-string
   (nrecon.wire:render-results results :format (%format-keyword invocation))
   (invocation-stdout invocation))
  (terpri (invocation-stdout invocation))
  (finish-output (invocation-stdout invocation)))

(defun %emit-result (invocation id value &key (status :completed) metadata)
  (%emit-results invocation
                 (list (nrecon.core:make-result :job-id id
                                                :status status
                                                :value value
                                                :metadata metadata))))

(defun %emit-plan (invocation plan)
  (if (eq (%format-keyword invocation) :table)
      (%emit-result invocation "dry-run" plan)
      (progn
        (write-string plan (invocation-stdout invocation))
        (terpri (invocation-stdout invocation))
        (finish-output (invocation-stdout invocation)))))

(defun %parse-uri-host (uri)
  (let ((scheme-end (search "://" uri)))
    (unless scheme-end
      (error "Fuzz URI must include an http:// or https:// authority."))
    (unless (member (string-downcase (subseq uri 0 scheme-end))
                    (list "http" "https")
                    :test (function string=))
      (error "Fuzz URI scheme must be http or https."))
    (let* ((start (+ scheme-end 3))
           (end (or (position-if (lambda (character)
                                   (find character "/?#"))
                                 uri :start start)
                    (length uri)))
           (authority (subseq uri start end))
           (host-start (1+ (or (position #\@ authority :from-end t) -1)))
           (host-port (subseq authority host-start)))
      (when (zerop (length host-port))
        (error "Fuzz URI has no host."))
      (if (char= (char host-port 0) #\[)
          (let ((close (position #\] host-port)))
            (unless close
              (error "Fuzz URI has an invalid bracketed host."))
            (subseq host-port 1 close))
          (let ((colon (position #\: host-port)))
            (subseq host-port 0 colon))))))

(defun %string-pairs (pairs)
  (map 'vector (lambda (pair) (vector (car pair) (cdr pair))) pairs))

(defun %require-module (name)
  (or (nrecon.core:find-module name)
      (error "The ~A module is not registered." name)))

(defun %fuzz-result-json (result)
  (let* ((request (nrecon.fuzz:fuzz-result-request result))
         (response (nrecon.fuzz:fuzz-result-response result)))
    (%object
     "depth" (nrecon.fuzz:fuzz-result-depth result)
     "matched" (%json-boolean (nrecon.fuzz:fuzz-result-matched-p result))
     "request"
     (%object "body" (nrecon.fuzz:fuzz-request-body request)
              "depth" (nrecon.fuzz:fuzz-request-depth request)
              "headers" (%string-pairs (nrecon.fuzz:fuzz-request-headers request))
              "host" (nrecon.fuzz:fuzz-request-host request)
              "method" (nrecon.fuzz:fuzz-request-method request)
              "uri" (nrecon.fuzz:fuzz-request-uri request)
              "word_values" (coerce
                             (nrecon.fuzz:fuzz-request-word-values request)
                             'vector))
     "response"
     (%object "body" (nrecon.fuzz:fuzz-response-body response)
              "headers" (%string-pairs (nrecon.fuzz:fuzz-response-headers response))
              "lines" (nrecon.fuzz:fuzz-response-lines response)
              "size" (nrecon.fuzz:fuzz-response-size response)
              "status" (nrecon.fuzz:fuzz-response-status response)
              "words" (nrecon.fuzz:fuzz-response-words response)))))

(defun %fuzz-command (invocation)
  (let* ((uri (positional-value invocation :uri))
         (host (%parse-uri-host uri))
         (lab-p (option-value invocation :lab))
         (policy (%authorization-policy invocation))
         (module (%require-module (quote fuzz)))
         (job (nrecon.core:make-job :id "fuzz" :target host :options nil)))
    (if (option-value invocation :dry-run)
        (%emit-plan invocation
                    (nrecon.wire:render-plan (nrecon.core:module-name module) job
                                             :authorization-policy policy
                                             :target-lab-p lab-p))
        (let* ((words (option-value invocation :word))
               (wordlists (append (when words (list words))
                                  (option-value invocation :wordlist)))
               (template
                 (nrecon.fuzz:make-request-template
                  :method (or (option-value invocation :method) "GET")
                  :uri uri
                  :host (option-value invocation :host)
                  :lab-p lab-p)))
          (unless wordlists
            (error "Provide at least one --word or --wordlist for active fuzzing."))
          (let* ((promise
                   (funcall (nrecon.core:module-run module)
                            template
                            :wordlists wordlists
                            :policy policy
                            :concurrency (or (option-value invocation :concurrency) 4)
                            :requests-per-second (or (option-value invocation :rate) 10)
                            :timeout (or (option-value invocation :timeout) 10)
                            :max-depth (or (option-value invocation :max-depth) 0)))
                 (results (cl-concurrent-kit:await promise)))
            (%emit-results
             invocation
             (mapcar (lambda (result)
                       (nrecon.core:make-result
                        :job-id "fuzz"
                        :value (%fuzz-result-json result)))
                     results)))))))

(defun %network-host-json (host)
  (%object
   "ip_addresses" (coerce (nrecon.net:network-host-ip-addresses host) 'vector)
   "mac_addresses" (coerce (nrecon.net:network-host-mac-addresses host) 'vector)
   "names" (coerce (nrecon.net:network-host-names host) 'vector)
   "protocols" (coerce (nrecon.net:network-host-protocols host) 'vector)))

(defun %recon-command (invocation)
  (let* ((offline-file (option-value invocation :offline-file))
         (device (option-value invocation :device))
         (timeout (or (option-value invocation :timeout) 5))
         (promiscuous-p (option-value invocation :promiscuous))
         (target (or offline-file device))
         (job (nrecon.core:make-job
               :id "recon"
               :target target
               :options (list :offline-file offline-file
                              :device device
                              :timeout timeout
                              :promiscuous-p promiscuous-p)))
         (policy (%authorization-policy invocation))
         (module (%require-module (quote net)))
         (lab-p (option-value invocation :lab)))
    (when (and offline-file device)
      (error "Specify only one of --offline-file and --device."))
    (if (option-value invocation :dry-run)
        (%emit-plan invocation
                    (nrecon.wire:render-plan (nrecon.core:module-name module) job
                                             :authorization-policy policy
                                             :target-lab-p lab-p))
        (multiple-value-bind (hosts packets status)
            (funcall (nrecon.core:module-run module) job nil)
          (%emit-result invocation "recon"
                        (%object "hosts" (map (quote vector)
                                              (function %network-host-json)
                                              hosts)
                                 "packet_count" (length packets)
                                 "status" status))))))

(defun %hex-octets (text)
  (let ((digits (remove-if (lambda (character)
                             (find character ":- _"))
                           text)))
    (unless (and (evenp (length digits)) (plusp (length digits)))
      (error "Frame hex must contain a non-empty even number of hex digits."))
    (let ((bytes (make-array (/ (length digits) 2)
                             :element-type '(unsigned-byte 8))))
      (loop for index from 0 below (length digits) by 2
            for byte = (handler-case
                           (parse-integer digits :start index :end (+ index 2)
                                          :radix 16 :junk-allowed nil)
                         (error ()
                           (error "Frame contains a non-hexadecimal byte.")))
            do (setf (aref bytes (/ index 2)) byte))
      bytes)))

(defun %attack-options (invocation action target)
  (let ((options (%object "action" action
                          "target-ip" target)))
    (dolist (name '(:target-mac :source-mac :spoofed-ip :query-name
                    :answer-ip :interface :source-destination-mac
                    :destination-mac :interface-mac))
      (let ((value (option-value invocation name)))
        (when value
          (setf (gethash (string-downcase (symbol-name name)) options) value))))
    (when (option-value invocation :frame)
      (setf (gethash "frame" options)
            (%hex-octets (option-value invocation :frame))))
    (when (option-value invocation :timeout)
      (setf (gethash "timeout" options) (option-value invocation :timeout)))
    options))

(defun %attack-audit (invocation record)
  (format (invocation-stderr invocation) "nrecon attack audit: ~S~%" record)
  (finish-output (invocation-stderr invocation))
  t)

(defun %attack-command (invocation)
  (let* ((action-name (option-value invocation :action))
         (action (intern (string-upcase action-name) :keyword))
         (target-host (positional-value invocation :target))
         (lab-p (option-value invocation :lab))
         (policy (%authorization-policy invocation))
         (job (nrecon.core:make-job
               :id "attack"
               :target target-host
               :options (%attack-options invocation action target-host))))
    (if (option-value invocation :dry-run)
        (%emit-plan invocation
                    (nrecon.wire:render-plan "attack" job
                                             :authorization-policy policy
                                             :target-lab-p lab-p))
        (let* ((module (nrecon.core:find-module 'attack))
               (interface (option-value invocation :interface))
               (sender (lambda (bytes timeout)
                         (declare (ignore bytes timeout))
                         (error "An allowed attack requires --interface.")))
               (context (list :authorization-policy policy
                              :target-lab-p lab-p
                              :audit-fn (lambda (record)
                                         (%attack-audit invocation record))
                              :sender (unless interface sender))))
          (unless module
            (error "The attack module is not registered."))
          (handler-case
              (let ((outcome (funcall (nrecon.core:module-run module)
                                      job context)))
                (%emit-result invocation "attack"
                              (%object "action" action-name
                                       "result" outcome)))
            (nrecon.attack:attack-authorization-denied (condition)
              (%emit-result invocation "attack"
                            (%object "action" action-name
                                     "authorized" json-kit:+json-false+
                                     "error" (princ-to-string condition))
                            :status :failed)
              2))))))

(defun %describe-command (invocation)
  (let ((manifest (nrecon.wire:describe-manifest)))
    (if (option-value invocation :json)
        (progn
          (write-string (json-kit:stringify manifest :sort-keys t)
                        (invocation-stdout invocation))
          (terpri (invocation-stdout invocation))
          (finish-output (invocation-stdout invocation)))
        (%emit-results
         invocation
         (map 'list (lambda (module)
                      (nrecon.core:make-result
                       :job-id (gethash "name" module)
                       :value module))
              (gethash "modules" manifest)))))
  0)

(defun %session-command (invocation)
  (progn
    (%emit-result
     invocation
     "session"
     (%object "modules"
              (map 'vector #'nrecon.core:module-name
                   (nrecon.core:list-modules))
              "persistent" json-kit:+json-false+
              "status" "ready"))
    0))

(defun %mcp-error (code message)
  (%object "jsonrpc" "2.0"
           "id" json-kit:+json-null+
           "error" (%object "code" code "message" message)))
(defun %read-mcp-line (stream)
  (let ((buffer (make-string-output-stream))
        (byte-count 0))
    (loop for character = (read-char stream nil nil)
          do (cond
               ((null character)
                (return
                  (if (zerop byte-count)
                      (values nil :eof)
                      (values (get-output-stream-string buffer) :line))))
               ((char= character #\Newline)
                (return
                  (values (get-output-stream-string buffer) :line)))
               (t
                (incf byte-count
                      (let ((code (char-code character)))
                        (cond
                          ((<= code #x7f) 1)
                          ((<= code #x7ff) 2)
                          ((<= code #xffff) 3)
                          (t 4))))
                (when (> byte-count *mcp-max-line-bytes*)
                  (return (values nil :too-large)))
                (write-char character buffer))))))

(defun %serve-command (invocation)
  (let* ((output (invocation-stdout invocation))
         (policy (%authorization-policy invocation))
         (lab-p (option-value invocation :lab)))
    (loop
      (multiple-value-bind (line status)
          (%read-mcp-line *standard-input*)
        (case status
          (:eof (return))
          (:too-large
           (write-string
            (json-kit:stringify (%mcp-error -32700 "Parse error.")
                                :sort-keys t)
            output)
           (terpri output)
           (finish-output output)
           (return-from %serve-command 2))
          (:line
           (let* ((request (handler-case
                               (json-kit:parse line)
                             (error () :parse-error)))
                  (response (if (eq request :parse-error)
                                (%mcp-error -32700 "Parse error.")
                                (nrecon.wire:handle-mcp-request
                                 request
                                 :authorization-policy policy
                                 :target-lab-p lab-p))))
             (when response
               (write-string (json-kit:stringify response :sort-keys t) output)
               (terpri output)
               (finish-output output)))))))
    0))

(defun %safe-handler (function)
  (lambda (invocation)
    (handler-case
        (let ((result (funcall function invocation)))
          (if (integerp result) result 0))
      (error (condition)
        (format (invocation-stderr invocation) "nrecon: ~A~%" condition)
        (finish-output (invocation-stderr invocation))
        2))))

(defun make-app ()
  (cl-cli:make-app
   :name "nrecon"
   :version "0.1.0"
   :summary "Network reconnaissance and fuzzing tools."
   :description "A non-interactive CLI for fuzzing, passive reconnaissance, authorized attacks, module description, and MCP stdio service."
   :require-command t
   :global-options
   (list (make-option :name "format" :kind :value
                      :choices +output-formats+ :default "json"
                      :description "Result format: json, ndjson, or table.")
         (make-option :name "dry-run" :kind :flag
                      :description "Render an authorization plan without network access.")
         (make-option :name "lab" :kind :flag
                      :description "Mark the target as an explicitly authorized lab target.")
         (make-option :name "allow-host" :kind :value :multiple-p t
                      :description "Add a hostname or IPv4 range to the authorization allowlist.")
         (make-option :name "allow-action" :kind :value :multiple-p t
                      :choices +authorization-actions+
                      :description "Authorize an action capability."))
   :commands
   (list
    (make-command
     :name "fuzz"
     :description "Fuzz a URL containing one or more FUZZ placeholders."
     :positionals (list (make-positional :key :uri :required-p t
                                         :description "HTTP URL template."))
     :options (list (make-option :name "word" :kind :value :multiple-p t
                                 :description "Substitution value; may be repeated.")
                    (make-option :name "wordlist" :kind :value :multiple-p t
                                 :value-hint :file
                                 :description "Wordlist file; may be repeated.")
                    (make-option :name "method" :kind :value :default "GET")
                    (make-option :name "host" :kind :value
                                 :description "Optional HTTP Host header value.")
                    (make-option :name "concurrency" :kind :value :type :integer
                                 :default 4)
                    (make-option :name "rate" :kind :value :type :integer
                                 :default 10)
                    (make-option :name "timeout" :kind :value :type :integer
                                 :default 10)
                    (make-option :name "max-depth" :kind :value :type :integer
                                 :default 0))
     :handler (%safe-handler #'%fuzz-command))
    (make-command
     :name "recon"
     :description "Discover hosts from an offline capture or a live interface."
     :options (list (make-option :name "offline-file" :kind :value
                                 :value-hint :file)
                    (make-option :name "device" :kind :value)
                    (make-option :name "timeout" :kind :value :type :integer
                                 :default 5)
                    (make-option :name "promiscuous" :kind :flag))
     :handler (%safe-handler #'%recon-command))
    (make-command
     :name "attack"
     :description "Run an attack action through the core authorization and audit gate."
     :positionals (list (make-positional :key :target :required-p t
                                         :description "Target IP address or hostname."))
     :options (list (make-option :name "action" :kind :value :required-p t
                                 :choices '("arp-spoof" "dns-spoof" "mitm-proxy"))
                    (make-option :name "interface" :kind :value)
                    (make-option :name "source-mac" :kind :value)
                    (make-option :name "target-mac" :kind :value)
                    (make-option :name "spoofed-ip" :kind :value)
                    (make-option :name "query-name" :kind :value)
                    (make-option :name "answer-ip" :kind :value)
                    (make-option :name "destination-mac" :kind :value)
                    (make-option :name "interface-mac" :kind :value)
                    (make-option :name "frame" :kind :value)
                    (make-option :name "timeout" :kind :value :type :integer
                                 :default 1))
     :handler (%safe-handler #'%attack-command))
    (make-command
     :name "session"
     :description "Report module availability and session persistence status."
     :handler #'%session-command)
    (make-command
     :name "serve"
     :description "Serve MCP JSON-RPC requests over standard input and output."
     :options (list (make-option :name "mcp" :kind :flag
                                 :description "Use MCP JSON-RPC stdio (the default)."))
     :handler (%safe-handler #'%serve-command))
    (make-command
     :name "describe"
     :description "Describe registered modules and their capabilities."
     :options (list (make-option :name "json" :kind :flag
                                 :description "Print the full manifest as JSON."))
     :handler (%safe-handler #'%describe-command)))))

(defun main ()
  (uiop:quit (run-app (make-app)
                      :argv (application-argv)
                      :color :auto
                      :width :auto)))
