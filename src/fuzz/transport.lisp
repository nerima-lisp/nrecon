(in-package #:nrecon.fuzz)
(defun %http-control-character-p (string)
  (some (lambda (character)
          (let ((code (char-code character)))
            (or (< code 32) (= code 127))))
        string))

(defun %parse-fuzz-uri (uri)
  (when (%http-control-character-p uri)
    (error "HTTP request URI contains a control character."))
  (when (find #\# uri)
    (error "HTTP request URI must not contain a fragment."))
  (let* ((parsed (http-kit:parse-http-uri uri))
         (scheme (http-kit:http-uri-scheme parsed))
         (host (http-kit:http-uri-host parsed))
         (authority (http-kit:http-uri-authority parsed)))
    (when (and authority (find #\@ authority))
      (error "HTTP request URI must not contain user information."))
    (unless
        (and (stringp scheme)
             (member (string-downcase scheme) '("http" "https") :test #'string=)
             (stringp host)
             (plusp (length host)))
      (error "HTTP request URI must be an absolute HTTP or HTTPS URI: ~S." uri))
    (values parsed host)))

(defun %host-header-name-p (name)
  (string-equal name "Host"))

(defun %host-header-target (value)
  (when
      (or (zerop (length value))
          (%http-control-character-p value)
          (find #\@ value)
          (find #\/ value)
          (find #\? value)
          (find #\# value))
    (error "Invalid Host header value: ~S." value))
  (let* ((parsed (http-kit:parse-http-uri (format nil "http://~A" value)))
         (host (http-kit:http-uri-host parsed))
         (path (http-kit:http-uri-path parsed))
         (query (http-kit:http-uri-query parsed)))
    (unless
        (and (stringp host)
             (plusp (length host))
             (or (null path) (string= path "") (string= path "/"))
             (null query))
      (error "Invalid Host header authority: ~S." value))
    host))

(defun %authorize-http-host (policy host lab-p)
  (let* ((normalized-host
           (if (and (plusp (length host))
                    (char= (char host (1- (length host))) #\.))
               (subseq host 0 (1- (length host)))
               host))
         (host-labels
           (loop with start = 0
                 for end = (position #\. normalized-host :start start)
                 collect (subseq normalized-host start end)
                 while end
                 do (setf start (1+ end))))
         (numeric-labels-p
           (every
            (lambda (label)
              (or (and (plusp (length label))
                       (every (lambda (character)
                                (digit-char-p character 10))
                              label))
                  (and (>= (length label) 2)
                       (char= (char label 0) #\0)
                       (char-equal (char label 1) #\x))))
            host-labels))
         (canonical-ipv4-p
           (and (= (length host-labels) 4)
                (every (lambda (label)
                         (and (plusp (length label))
                              (every (lambda (character)
                                       (digit-char-p character 10))
                                     label)
                              (or (= (length label) 1)
                                  (not (char= (char label 0) #\0)))))
                       host-labels)
                (every (lambda (label)
                         (<= (parse-integer label) 255))
                       host-labels))))
    (when (and numeric-labels-p (not canonical-ipv4-p))
      (error "Ambiguous numeric HTTP host spelling is not allowed: ~A." host))
    (let ((decision
           (nrecon.core:authorize-action
            policy
            :http
            (nrecon.core:make-authorization-target :host host :lab-p lab-p))))
      (unless (nrecon.core:authorization-decision-allowed-p decision)
        (error "HTTP request denied by authorization policy (~A): ~A."
               (nrecon.core:authorization-decision-reason decision)
               host)))))

(defun %validated-request-headers (fuzz-request uri-host policy lab-p)
  (let ((headers (fuzz-request-headers fuzz-request)))
    (unless
        (and (listp headers)
             (every
              (lambda (header)
                (and (consp header)
                     (stringp (car header))
                     (stringp (cdr header))))
              headers))
      (error "Fuzz request headers must be string name/value pairs."))
    (let ((host-headers
           (remove-if-not
            (lambda (header)
              (%host-header-name-p (car header)))
            headers)))
      (when (> (length host-headers) 1)
        (error "A request may contain only one Host header."))
      (when (and (fuzz-request-host fuzz-request) host-headers)
        (error "Use either the template Host field or a Host header, not both."))
      (%authorize-http-host policy uri-host lab-p)
      (let ((override
             (or (fuzz-request-host fuzz-request)
                 (and host-headers (cdar host-headers)))))
        (when override
          (%authorize-http-host policy (%host-header-target override) lab-p))
        (if (fuzz-request-host fuzz-request)
            (append (list (cons "Host" (fuzz-request-host fuzz-request)))
                    headers)
            (copy-tree headers))))))

(defun %make-fuzz-client (transport-function)
  (let ((transport
          (when transport-function
            (lambda (request &rest transport-options)
              (funcall transport-function
                       request
                       :timeout (getf transport-options :timeout))))))
    (http-kit/client:make-http-client
     :transport-function transport
     :redirect-policy
     (http-kit/client:make-http-redirect-policy :max-redirects 0)
     :retry-policy
     (http-kit/client:make-http-retry-policy :max-attempts 1))))

(defun %make-fuzz-boundary (client)
  (cl-boundary-kit:make-network-boundary :request-fn
                                         (lambda (request &key timeout)
                                           (multiple-value-bind (response
                                                                 effective-request)
                                               (http-kit/client:http-client-send
                                                client
                                                request
                                                :timeout
                                                timeout)
                                             (declare (ignore effective-request))
                                             response))))

(defun %make-http-request (fuzz-request client policy lab-p)
  (multiple-value-bind (parsed-uri uri-host)
      (%parse-fuzz-uri (fuzz-request-uri fuzz-request))
    (let* ((headers
            (%validated-request-headers fuzz-request uri-host policy lab-p))
           (request
            (http-kit/client:http-client-request client
                                                 (fuzz-request-method
                                                  fuzz-request)
                                                 (http-kit:http-uri-string
                                                  parsed-uri)
                                                 :headers
                                                 headers
                                                 :body
                                                 (fuzz-request-body
                                                  fuzz-request))))
      request)))

(defun %response-body-octets (body)
  (cond
    ((null body) (make-array 0 :element-type '(unsigned-byte 8)))
    ((stringp body) (cl-codec-kit:string-to-octets body :encoding :utf-8))
    ((typep body '(vector (unsigned-byte 8))) body)
    (t (error "Unsupported HTTP response body type: ~S." (type-of body)))))

(defun %response-word-count (body)
  (loop with in-word-p = nil
        with words = 0
        for character across body
        for whitespace-p = (find character
                                 #(#\Space #\Tab #\Newline #\Return #\Page))
        do (cond
             (whitespace-p
              (setf in-word-p nil))
             ((not in-word-p)
              (incf words)
              (setf in-word-p t)))
        finally (return words)))

(defun %response-line-count (body)
  (if (zerop (length body))
      0
      (+ (count #\Newline body)
         (if (char= (char body (1- (length body))) #\Newline)
             0
             1))))

(defun %make-fuzz-response-record (response)
  (unless (typep response 'http-kit:http-response)
    (error "HTTP transport returned an invalid response: ~S." response))
  (let* ((octets (%response-body-octets (http-kit:http-response-body response)))
         (body
          (cl-codec-kit:octets-to-string octets :encoding :utf-8 :errorp nil)))
    (%make-fuzz-response :status
                         (http-kit:http-response-status response)
                         :headers
                         (copy-tree (http-kit:http-response-headers response))
                         :body
                         body
                         :size
                         (length octets)
                         :words
                         (%response-word-count body)
                         :lines
                         (%response-line-count body))))

(defun %send-fuzz-request (fuzz-request client
                                        boundary
                                        policy
                                        lab-p
                                        timeout
                                        limiter)
  (let* ((control (nrecon.core:current-pipeline-run-control))
         (request (%make-http-request fuzz-request client policy lab-p)))
    (when (and control (nrecon.core:pipeline-run-cancelled-p control))
      (return-from %send-fuzz-request
        nil))
    (when limiter
      (unless
          (cl-resilience-kit:rate-limiter-acquire limiter
                                                  :tokens
                                                  1
                                                  :wait-p
                                                  t
                                                  :max-wait
                                                  timeout
                                                  :signal-on-reject-p
                                                  t)
        (error "HTTP request rate limit was not acquired before timeout.")))
    (when (and control (nrecon.core:pipeline-run-cancelled-p control))
      (return-from %send-fuzz-request
        nil))
    (%make-fuzz-response-record
     (cl-boundary-kit:network-boundary-request boundary
                                               request
                                               :timeout
                                               timeout))))
