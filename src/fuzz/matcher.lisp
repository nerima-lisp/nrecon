(in-package #:nrecon.fuzz)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun %fuzz-proper-list-p (value)
    (do ((tail value (cdr tail)))
      ((not (consp tail)) (null tail))))
  (defun %fuzz-token-p (value name)
    (and (symbolp value) (string-equal (symbol-name value) name)))
  (defun %fuzz-invalid-predicate (form)
    (error "Invalid fuzz predicate form: ~S" form))
  (defun %fuzz-field-accessor (field)
    (cond
      ((%fuzz-token-p field "STATUS") 'fuzz-response-status)
      ((%fuzz-token-p field "SIZE") 'fuzz-response-size)
      ((%fuzz-token-p field "WORDS") 'fuzz-response-words)
      ((%fuzz-token-p field "LINES") 'fuzz-response-lines)
      (t nil)))
  (defun %fuzz-comparison-function (operator)
    (cond
      ((%fuzz-token-p operator "=") '=)
      ((%fuzz-token-p operator "/=") '/=)
      ((%fuzz-token-p operator "<") '<)
      ((%fuzz-token-p operator "<=") '<=)
      ((%fuzz-token-p operator ">") '>)
      ((%fuzz-token-p operator ">=") '>=)
      (t nil)))
  (defun %fuzz-predicate-expansion (form response)
    (unless (and (%fuzz-proper-list-p form) (consp form))
      (%fuzz-invalid-predicate form))
    (let ((operator (first form)))
      (cond
        ((or (%fuzz-token-p operator "AND") (%fuzz-token-p operator "OR"))
         (let ((combiner
                (if (%fuzz-token-p operator "AND")
                    'and
                    'or)))
           (cons combiner
                 (mapcar
                  (lambda (subform)
                    (%fuzz-predicate-expansion subform response))
                  (rest form)))))
        ((%fuzz-token-p operator "NOT")
          (unless (= (length form) 2)
            (%fuzz-invalid-predicate form))
          `(not ,(%fuzz-predicate-expansion (second form) response)))
        ((%fuzz-token-p operator "REGEX")
          (unless (and (= (length form) 2) (stringp (second form)))
            (%fuzz-invalid-predicate form))
          `(cl-regex-kit:is-match-p
            (load-time-value (cl-regex-kit:compile-regex ,(second form)) t)
            (fuzz-response-body ,response)
            :timeout
            1.0))
        (t
         (let ((accessor (%fuzz-field-accessor operator))
               (comparison (%fuzz-comparison-function (second form)))
               (threshold (third form)))
           (unless
               (and (= (length form) 3) accessor comparison (realp threshold))
             (%fuzz-invalid-predicate form))
           `(,comparison (,accessor ,response) ,threshold))))))
  (defun %fuzz-predicate-definition (name form)
    (unless (and (symbolp name) name (not (keywordp name)))
      (%fuzz-invalid-predicate name))
    (let ((response (gensym "RESPONSE-")))
      `(defun ,name (,response)
         ,(%fuzz-predicate-expansion form response)))))

(defmacro define-matcher (name form)
  (%fuzz-predicate-definition name form))

(defmacro define-filter (name form)
  (%fuzz-predicate-definition name form))
