(in-package #:nrecon.fuzz)

(defun make-request-template (&key (method "GET")
                                   uri
                                   host
                                   headers
                                   body
                                   (lab-p nil))
  (check-type method string)
  (check-type uri string)
  (when host
    (check-type host string))
  (check-type headers list)
  (check-type lab-p (member nil t))
  (when (search "FUZZ" method :test #'char=)
    (error "FUZZ is not allowed in the request method."))
  (dolist (header headers)
    (unless (and (consp header) (stringp (car header)) (stringp (cdr header)))
      (error "Request headers must be an alist of string name/value pairs.")))
  (%make-request-template :method
                          (copy-seq method)
                          :uri
                          (copy-seq uri)
                          :host
                          (and host (copy-seq host))
                          :headers
                          (mapcar
                           (lambda (header)
                             (cons (copy-seq (car header))
                                   (copy-seq (cdr header))))
                           headers)
                          :body
                          (if (stringp body)
                              (copy-seq body)
                              body)
                          :lab-p
                          lab-p))

(defun %count-fuzz-in-string (string)
  (loop with start = 0
        for position = (search "FUZZ" string :start2 start :test #'char=)
        while position
        sum 1
        do (setf start (+ position 4))))

(defun %request-template-string-fields (template)
  (append (list (request-template-uri template))
          (when (request-template-host template)
            (list (request-template-host template)))
          (loop for header in (request-template-headers template)
                append (list (car header) (cdr header)))
          (when (stringp (request-template-body template))
            (list (request-template-body template)))))

(defun %request-template-fuzz-count (template)
  (loop for string in (%request-template-string-fields template)
        sum (%count-fuzz-in-string string)))

(defun %wordlist-source-words (source)
  (let ((words
         (cond
           ((listp source) (copy-list source))
           ((vectorp source) (coerce source 'list))
           (t (error "Wordlist sources must be lists or vectors.")))))
    (dolist (word words)
      (check-type word string))
    words))

(defun %substitute-fuzz-values (string word-values)
  (let ((remaining-word-values word-values)
        (start 0))
    (let ((result
            (with-output-to-string (output)
              (loop for position = (search "FUZZ" string
                                           :start2 start
                                           :test (function char=))
                    while position
                    do (write-string string output :start start :end position)
                       (unless remaining-word-values
                         (error "Not enough words for FUZZ occurrences."))
                       (write-string (car remaining-word-values) output)
                       (setf remaining-word-values (cdr remaining-word-values)
                             start (+ position 4))
                    finally (write-string string output :start start)))))
      (values result remaining-word-values))))

(defun %expand-request-template-with-values (template word-values depth)
  (let ((remaining-word-values word-values))
    (labels ((replace-field (string)
               (multiple-value-bind (replacement remaining)
                   (%substitute-fuzz-values string remaining-word-values)
                 (setf remaining-word-values remaining)
                 replacement))
             (replace-headers (headers)
               (mapcar
                (lambda (header)
                  (cons (replace-field (car header))
                        (replace-field (cdr header))))
                headers)))
      (let* ((uri (replace-field (request-template-uri template)))
             (host
              (and (request-template-host template)
                   (replace-field (request-template-host template))))
             (headers (replace-headers (request-template-headers template)))
             (body
              (if (stringp (request-template-body template))
                  (replace-field (request-template-body template))
                  (request-template-body template))))
        (unless (null remaining-word-values)
          (error "Too many words for FUZZ occurrences."))
        (%make-fuzz-request :method
                            (copy-seq (request-template-method template))
                            :uri
                            uri
                            :host
                            host
                            :headers
                            headers
                            :body
                            body
                            :word-values
                            (mapcar #'copy-seq word-values)
                            :depth
                            depth)))))

(defun %expand-request-template (template wordlists &key (depth 0))
  (check-type template request-template)
  (check-type wordlists list)
  (check-type depth (integer 0 *))
  (let* ((fuzz-count (%request-template-fuzz-count template))
         (sources (mapcar #'%wordlist-source-words wordlists))
         (source-count (length sources))
         (position-sources
          (cond
            ((= source-count 1)
             (make-list fuzz-count :initial-element (first sources)))
            ((= source-count fuzz-count) sources)
            (t
             (error "Provide one wordlist or one wordlist per FUZZ occurrence."))))
         (combinations (list nil)))
    (dolist (source position-sources)
      (setf combinations (loop for prefix in combinations
                               append (loop for word in source
                                            collect (append prefix (list word))))))
    (mapcar
     (lambda (word-values)
       (%expand-request-template-with-values template word-values depth))
     combinations)))
