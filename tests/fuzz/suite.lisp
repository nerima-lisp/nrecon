(in-package #:nrecon/fuzz-test)

(define-matcher success
                (and (status = 200)
                     (size >= 4)
                     (words >= 4)
                     (lines >= 2)
                     (regex "needle")))
(define-matcher not-404 (not (status = 404)))
(define-matcher size-at-least-four (size >= 4))

(define-filter excluded (or (status = 404) (size > 100)))

(defun %test-policy (&optional (allowlist '("lab.example")))
  (nrecon.core:make-authorization-policy :actions '(:http) :allowlist allowlist))

(defun %make-http-response (status body)
  (http-kit:make-http-response :status
                               status
                               :body
                               (map '(vector (unsigned-byte 8))
                                    #'char-code
                                    body)))

(defun %request-uri-string (request)
  (let ((uri (http-kit:http-request-uri request)))
    (if (stringp uri)
        uri
        (http-kit:http-uri-string uri))))

(defun %request-header-pairs (request)
  (mapcar
   (lambda (header)
     (cons (http-kit:http-header-name header)
           (http-kit:http-header-content header)))
   (http-kit:http-request-headers request)))

(defun %request-header-value (request name)
  (loop for (header-name . value) in (%request-header-pairs request)
        when (string-equal header-name name)
          return value))

(defun %request-body-string (request)
  (let ((body (http-kit:http-request-body request)))
    (if (stringp body)
        body
        (map 'string #'code-char body))))

(defun %request-combination-key (request)
  (let* ((uri (%request-uri-string request))
         (path-query
          (loop for path in '("one" "two")
                thereis (loop for query in '("red" "blue")
                              when (search (format nil "/~A?item=~A" path query)
                                           uri)
                                return (list path query))))
         (host (%request-header-value request "Host"))
         (fuzz-header
          (loop for (name . value) in (%request-header-pairs request)
                when (member name
                             '("X-Alpha-Header" "X-Beta-Header")
                             :test
                             #'string-equal)
                  return (list (string-downcase name) value))))
    (when (and path-query host fuzz-header)
      (list (first path-query)
            (second path-query)
            (string-downcase host)
            (first fuzz-header)
            (second fuzz-header)
            (%request-body-string request)))))

(describe "nrecon fuzz request templates"
          (it
           "expands every FUZZ position as a Cartesian product in real HTTP requests"
           (let* ((template
                   (make-request-template :method
                                          "GET"
                                          :uri
                                          "http://origin.lab.example/FUZZ?item=FUZZ"
                                          :host
                                          "FUZZ.lab.example"
                                          :headers
                                          '(("X-FUZZ-Header" . "value-FUZZ"))
                                          :body
                                          "payload-FUZZ"
                                          :lab-p
                                          t))
                  (wordlists
                   '(("one" "two") ("red" "blue")
                     ("north" "south")
                     ("Alpha" "Beta")
                     ("left" "right")
                     ("red" "blue")))
                  (requests nil))
             (multiple-value-bind (promise control)
                 (run-fuzz template
                           :wordlists
                           wordlists
                           :policy
                           (%test-policy)
                           :concurrency
                           1
                           :max-depth
                           0
                           :transport-function
                           (lambda (request &key timeout)
                             (declare (ignore timeout))
                             (push request requests)
                             (%make-http-response 200 "ok")))
               (expect (cl-concurrent-kit:promise-p promise) :to-be t)
               (expect (typep control 'nrecon.core:pipeline-run-control)
                       :to-be
                       t)
               (let* ((results (cl-concurrent-kit:await promise))
                      (requests (nreverse requests))
                      (keys (mapcar #'%request-combination-key requests)))
                 (expect (length results) :to-be 64)
                 (expect (length requests) :to-be 64)
                 (expect (every #'identity keys) :to-be t)
                 (expect (length (remove-duplicates keys :test #'equal))
                         :to-be
                         64)
                 (expect
                  (every
                   (lambda (key)
                     (and (member (first key) '("one" "two") :test #'string=)
                          (member (second key) '("red" "blue") :test #'string=)
                          (member (third key)
                                  '("north.lab.example" "south.lab.example")
                                  :test
                                  #'string=)
                          (member (fourth key)
                                  '("x-alpha-header" "x-beta-header")
                                  :test
                                  #'string=)
                          (member (fifth key)
                                  '("value-left" "value-right")
                                  :test
                                  #'string=)
                          (member (sixth key)
                                  '("payload-red" "payload-blue")
                                  :test
                                  #'string=)))
                   keys)
                  :to-be
                  t))))))

(describe "nrecon fuzz response matchers and filters"
  (it "evaluates each matcher and filter condition independently"
    (flet ((response (status body words lines)
             (nrecon.fuzz::%make-fuzz-response
              :status status :headers nil :body body
              :size (length body) :words words :lines lines)))
      (let* ((matching-body (format nil "needle alpha beta~%gamma"))
             (matched (response 200 matching-body 4 2))
             (wrong-status (response 201 matching-body 4 2))
             (too-few-words (response 200 (format nil "needle alpha~%gamma") 3 2))
             (too-few-lines (response 200 "needle alpha beta gamma" 4 1))
             (wrong-regex (response 200 (format nil "other alpha beta~%gamma") 4 2))
             (small-size (response 200 "abc" 1 1))
             (valid-size (response 200 "abcd" 1 1))
             (not-found (response 404 matching-body 4 2))
             (large-response
              (response 200 (make-string 101 :initial-element (char "x" 0)) 1 1))
             (hundred-byte-response
              (response 200 (make-string 100 :initial-element (char "x" 0)) 1 1)))
        (expect (success matched) :to-be t)
        (expect (success wrong-status) :to-be nil)
        (expect (success too-few-words) :to-be nil)
        (expect (success too-few-lines) :to-be nil)
        (expect (success wrong-regex) :to-be nil)
        (expect (size-at-least-four small-size) :to-be nil)
        (expect (size-at-least-four valid-size) :to-be t)
        (expect (not-404 matched) :to-be t)
        (expect (not-404 not-found) :to-be nil)
        (expect (excluded not-found) :to-be t)
        (expect (excluded large-response) :to-be t)
        (expect (excluded hundred-byte-response) :to-be nil)
        (expect (excluded matched) :to-be nil))))
  (it "derives response metrics from HTTP body text"
    (let* ((body (format nil "needle alpha beta~%gamma"))
           (template (make-request-template :uri
                                             "http://origin.lab.example/FUZZ"
                                             :lab-p t)))
      (multiple-value-bind (promise control)
          (run-fuzz template
                    :wordlists (list (list "metrics"))
                    :policy (%test-policy)
                    :concurrency 1 :max-depth 0
                    :matchers (list (function success))
                    :transport-function
                    (lambda (request &key timeout)
                      (declare (ignore request timeout))
                      (%make-http-response 200 body)))
        (declare (ignore control))
        (let* ((results (cl-concurrent-kit:await promise))
               (result (first results))
               (response (fuzz-result-response result)))
          (expect (length results) :to-be 1)
          (expect (fuzz-result-matched-p result) :to-be t)
          (expect (fuzz-response-size response) :to-be (length body))
          (expect (fuzz-response-words response) :to-be 4)
          (expect (fuzz-response-lines response) :to-be 2))))))

(describe "nrecon fuzz recursion limits"
          (it "recurses through matched directory responses only to max-depth"
              (let* ((template
                      (make-request-template :uri
                                             "http://origin.lab.example/FUZZ/"
                                             :lab-p
                                             t))
                     (requests nil))
                (multiple-value-bind (promise control)
                    (run-fuzz template
                              :wordlists
                              (list '("one/" "two/"))
                              :policy
                              (%test-policy)
                              :concurrency
                              1
                              :max-depth
                              1
                              :matchers
                              (list #'success)
                              :transport-function
                              (lambda (request &key timeout)
                                (declare (ignore timeout))
                                (push request requests)
                                (%make-http-response 200 (format nil "needle alpha beta~%gamma"))))
                  (declare (ignore control))
                  (let ((results (cl-concurrent-kit:await promise)))
                    (expect (mapcar #'fuzz-result-depth results)
                            :to-equal
                            '(0 0 1 1 1 1))
                    (expect (every #'fuzz-result-matched-p results) :to-be t)
                    (expect (length requests) :to-be 6))))))

(describe "nrecon fuzz rate limiting"
  (it "spaces requests after the initial rate-limiter capacity is consumed"
    (let* ((words (list "first" "second" "third"))
           (template (make-request-template :uri
                                             "http://origin.lab.example/FUZZ"
                                             :lab-p t))
           (timestamps nil))
      (multiple-value-bind (promise control)
          (run-fuzz template
                    :wordlists (list words)
                    :policy (%test-policy)
                    :concurrency 1
                    :requests-per-second 2.0
                    :max-depth 0
                    :transport-function
                    (lambda (request &key timeout)
                      (declare (ignore request timeout))
                      (push (get-internal-real-time) timestamps)
                      (%make-http-response 200 "ok")))
        (declare (ignore control))
        (let ((results (cl-concurrent-kit:await promise)))
          (setf timestamps (nreverse timestamps))
          (expect (length results) :to-be 3)
          (expect (length timestamps) :to-be 3)
          (expect
           (>=
            (/ (- (car (last timestamps)) (first timestamps))
               internal-time-units-per-second)
            0.8)
           :to-be t))))))

(describe "nrecon fuzz concurrency limits"
          (it "keeps simultaneous transport calls at the configured cap"
              (let* ((barrier (cl-concurrent-kit:make-barrier 2))
                     (barrier-timeout (cl-date-kit:duration-of-seconds 3))
                     (counter-lock (cl-concurrent-kit:make-lock))
                     (active 0)
                     (peak 0)
                     (calls 0)
                     (template
                      (make-request-template :uri
                                             "http://origin.lab.example/FUZZ"
                                             :lab-p
                                             t)))
                (multiple-value-bind (promise control)
                    (run-fuzz template
                              :wordlists
                              (list '("one" "two" "three" "four"))
                              :policy
                              (%test-policy)
                              :concurrency
                              2
                              :requests-per-second
                              nil
                              :max-depth
                              0
                              :transport-function
                              (lambda (request &key timeout)
                                (declare (ignore request timeout))
                                (cl-concurrent-kit:with-lock-held (counter-lock)
                                                                  (incf calls)
                                                                  (incf active)
                                                                  (setf peak (max
                                                                              peak
                                                                              active)))
                                (unwind-protect
                                    (progn
                                      (cl-concurrent-kit:await-barrier barrier
                                                                       :timeout
                                                                       barrier-timeout)
                                      (%make-http-response 200 "ok"))
                                  (cl-concurrent-kit:with-lock-held
                                   (counter-lock)
                                   (decf active)))))
                  (declare (ignore control))
                  (let ((results (cl-concurrent-kit:await promise)))
                    (expect (length results) :to-be 4)
                    (expect calls :to-be 4)
                    (expect peak :to-be 2))))))

(describe "nrecon fuzz authorization"
          (it "denies an out-of-allowlist Host before invoking transport"
              (let* ((template
                      (make-request-template :uri
                                             "http://origin.lab.example/FUZZ"
                                             :host
                                             "FUZZ.example"
                                             :lab-p
                                             t))
                     (calls 0)
                     (denial-reason nil))
                (handler-case (multiple-value-bind (promise control)
                                  (run-fuzz template
                                            :wordlists
                                            (list '("blocked"))
                                            :policy
                                            (%test-policy)
                                            :concurrency
                                            1
                                            :max-depth
                                            0
                                            :transport-function
                                            (lambda (request &key timeout)
                                              (declare (ignore request timeout))
                                              (incf calls)
                                              (%make-http-response 200
                                                                   "should not run")))
                                (declare (ignore control))
                                (cl-concurrent-kit:await promise))
                  (error (condition)
                    (setf denial-reason (princ-to-string condition))))
                (expect
                 (not
                  (null
                   (search "target-not-allowlisted"
                           denial-reason
                           :test
                           (function char-equal))))
                 :to-be
                 t)
                (expect calls :to-be 0)))
          (it "rejects numeric host aliases before invoking transport"
              (dolist (template
                       (list (make-request-template :uri
                                                    "http://127.1/FUZZ"
                                                    :lab-p
                                                    t)
                             (make-request-template :uri
                                                    "http://origin.lab.example/FUZZ"
                                                    :host
                                                    "2130706433"
                                                    :lab-p
                                                    t)))
                (let ((calls 0)
                      (denial-reason nil))
                  (handler-case (multiple-value-bind (promise control)
                                    (run-fuzz template
                                              :wordlists
                                              (list '("blocked"))
                                              :policy
                                              (%test-policy
                                               (list "lab.example"
                                                     "127.1"
                                                     "2130706433"))
                                              :concurrency
                                              1
                                              :max-depth
                                              0
                                              :transport-function
                                              (lambda (request &key timeout)
                                                (declare (ignore request timeout))
                                                (incf calls)
                                                (%make-http-response
                                                 200
                                                 "should not run")))
                                  (declare (ignore control))
                                  (cl-concurrent-kit:await promise))
                    (error (condition)
                      (setf denial-reason (princ-to-string condition))))
                  (expect
                          (not
                           (null
                            (search "Ambiguous numeric HTTP host spelling"
                                    denial-reason
                                    :test
                                    (function char-equal))))
                          :to-be
                          t)
                  (expect calls :to-be 0)))))

(defun run-tests ()
  (let* ((plan (cl-weave:list-tests
                :reporter :sexp
                :stream (make-broadcast-stream)))
         (test-count (length plan)))
    (unless (plusp test-count)
      (error "The nrecon fuzz test suite selected no tests."))
    (format t "~&Selected ~D nrecon fuzz tests.~%" test-count)
    (let* ((events (cl-weave:run nil
                                 :reporter :spec
                                 :stream *standard-output*
                                 :bail nil))
           (normalized (cl-weave::normalize-run-results events))
           (executed-count (length normalized))
           (passed-count
             (count :pass normalized
                    :key (function cl-weave::test-event-status))))
      (unless (= executed-count test-count)
        (error "Expected ~D nrecon fuzz test results, received ~D."
               test-count executed-count))
      (unless (= passed-count test-count)
        (error "Expected all ~D nrecon fuzz tests to pass, received ~D passes."
               test-count passed-count))
      (format t "Passed ~D of ~D selected nrecon fuzz tests.~%"
              passed-count test-count)
      passed-count)))

(describe "nrecon fuzz wordlist sources"
          (it "reads files and streams and exhausts generator output"
              (let* ((filesystem
                      (cl-boundary-kit:make-test-filesystem :initial-files
                                                            (list
                                                             (cons "words.txt"
                                                                   (format nil
                                                                           "alpha~%beta~%")))))
                     (stream
                      (make-string-input-stream (format nil "first~%second~%")))
                     (generated '("north" "south")))
                (expect (read-wordlist-file "words.txt" filesystem)
                        :to-equal
                        '("alpha" "beta"))
                (expect (read-wordlist-stream stream)
                        :to-equal
                        '("first" "second"))
                (expect
                 (wordlist-from-generator
                  (lambda ()
                    (if generated
                        (values (pop generated) t)
                        (values nil nil))))
                 :to-equal
                 '("north" "south")))))
