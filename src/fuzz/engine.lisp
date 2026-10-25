(in-package #:nrecon.fuzz)

(defun %materialize-wordlist-source (source)
  (cond
    ((stringp source) (read-wordlist-file source))
    ((pathnamep source) (read-wordlist-file source))
    ((streamp source) (read-wordlist-stream source))
    ((functionp source) (wordlist-from-generator source))
    ((listp source) (copy-list source))
    ((vectorp source) (coerce source 'list))
    (t (error "Unsupported wordlist source: ~S." source))))

(defun %validate-fuzz-options (template wordlists
                                        policy
                                        concurrency
                                        requests-per-second
                                        timeout
                                        max-depth
                                        matchers
                                        filters
                                        transport-function)
  (check-type template request-template)
  (check-type wordlists list)
  (check-type policy nrecon.core:authorization-policy)
  (check-type concurrency (integer 1 *))
  (check-type timeout (real 0 *))
  (when (zerop timeout)
    (error "HTTP timeout must be greater than zero."))
  (check-type max-depth (integer 0 *))
  (when requests-per-second
    (check-type requests-per-second (real 0 *))
    (when (zerop requests-per-second)
      (error "Requests per second must be greater than zero or NIL.")))
  (check-type matchers list)
  (unless (every #'functionp matchers)
    (error "Matchers must be a list of functions."))
  (check-type filters list)
  (unless (every #'functionp filters)
    (error "Filters must be a list of functions."))
  (when transport-function
    (check-type transport-function function))
  (when (zerop (%request-template-fuzz-count template))
    (error "The request template must contain at least one FUZZ placeholder.")))

(defun %classify-fuzz-result (result matchers filters)
  (let* ((response (fuzz-result-response result))
         (matched-p
          (or (null matchers)
              (some
               (lambda (matcher)
                 (funcall matcher response))
               matchers)))
         (filtered-p
          (some
           (lambda (filter)
             (funcall filter response))
           filters)))
    (setf (fuzz-result-matched-p result) (and matched-p (not filtered-p)))
    result))

(defun %child-directory-template-uri (uri)
  (multiple-value-bind (parsed host) (%parse-fuzz-uri uri)
    (declare (ignore host))
    (let* ((path (or (http-kit:http-uri-path parsed) "/"))
           (query (http-kit:http-uri-query parsed)))
      (when
          (and (plusp (length path)) (char= (char path (1- (length path))) #\/))
        (format nil
                "~A://~A~A~@[?~A~]"
                (http-kit:http-uri-scheme parsed)
                (http-kit:http-uri-authority parsed)
                (concatenate 'string path "FUZZ")
                query)))))

(defun %recursive-fuzz-requests (results template wordlists max-depth seen)
  (when (search "FUZZ" (request-template-uri template) :test #'char=)
    (loop for result in results
          when (and (fuzz-result-matched-p result)
                    (< (fuzz-result-depth result) max-depth))
            append (let ((child-uri
                          (%child-directory-template-uri
                           (fuzz-request-uri (fuzz-result-request result)))))
                     (when (and child-uri (not (gethash child-uri seen)))
                       (setf (gethash child-uri seen) t)
                       (%expand-request-template
                        (make-request-template :method
                                               (request-template-method
                                                template)
                                               :uri
                                               child-uri
                                               :host
                                               (request-template-host template)
                                               :headers
                                               (request-template-headers
                                                template)
                                               :body
                                               (request-template-body template)
                                               :lab-p
                                               (request-template-lab-p template))
                        wordlists
                        :depth
                        (1+ (fuzz-result-depth result))))))))

(defun %run-fuzz-waves (initial-requests pipeline
                        concurrency
                        control
                        template
                        wordlists
                        max-depth)
  (let ((pending initial-requests)
        (all-results nil)
        (seen (make-hash-table :test #'equal)))
    (loop while pending
          do (when (nrecon.core:pipeline-run-cancelled-p control)
               (return all-results))
             (multiple-value-bind (batch-promise batch-control)
                 (nrecon.core:run-cps-pipeline-batch
                  pipeline
                  pending
                  :max-in-flight concurrency
                  :buffer-size 1
                  :control control)
               (declare (ignore batch-control))
               (let* ((batch-records (cl-concurrent-kit:await batch-promise))
                      (wave-results
                        (loop for record in batch-records
                              when (and
                                    (eq (nrecon.core:result-status record)
                                        :completed)
                                    (nrecon.core:result-value record))
                                collect (nrecon.core:result-value record))))
                 (setf all-results (nconc all-results wave-results)
                       pending (%recursive-fuzz-requests
                                wave-results template wordlists max-depth seen))))
          finally (return all-results))))

(defun run-fuzz (template &key
                          wordlists
                          policy
                          (concurrency 4)
                          (requests-per-second 10.0)
                          (timeout 10.0)
                          (max-depth 0)
                          matchers
                          filters
                          transport-function)
  (let ((wordlists wordlists))
    (%validate-fuzz-options template
                            wordlists
                            policy
                            concurrency
                            requests-per-second
                            timeout
                            max-depth
                            matchers
                            filters
                            transport-function)
    (setf wordlists (mapcar (function %materialize-wordlist-source) wordlists))
    (let* ((initial-requests (%expand-request-template template wordlists))
           (client (%make-fuzz-client transport-function))
           (boundary (%make-fuzz-boundary client))
           (limiter
             (when requests-per-second
               (cl-resilience-kit:make-rate-limiter
                :capacity 1
                :refill-rate requests-per-second)))
           (pipeline
             (nrecon.core:make-cps-pipeline
              (list
               (lambda (request context)
                 (declare (ignore context))
                 (let ((response
                         (%send-fuzz-request request client boundary policy
                                             (request-template-lab-p template)
                                             timeout limiter)))
                   (when response
                     (%make-fuzz-result :request request
                                        :response response
                                        :depth
                                        (fuzz-request-depth request)))))
               (lambda (result context)
                 (declare (ignore context))
                 (when result
                   (%classify-fuzz-result result matchers filters))))))
           (orchestration
             (nrecon.core:make-cps-pipeline
              (list
               (lambda (request-batch context)
                 (declare (ignore context))
                 (%run-fuzz-waves
                  (aref request-batch 0)
                  pipeline
                  concurrency
                  (nrecon.core:current-pipeline-run-control)
                  template
                  wordlists
                  max-depth)))))
           (control (nrecon.core:make-pipeline-run-control)))
      (nrecon.core:run-cps-pipeline orchestration
                                    (vector initial-requests)
                                    :control control))))

(define-module fuzz
               :capabilities
               (:http)
               :options
               (wordlists policy
                          requests-per-second
                          concurrency
                          timeout
                          max-depth
                          matchers
                          filters)
               :run
               run-fuzz)
