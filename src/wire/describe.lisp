(in-package #:nrecon.wire)

(defun describe-manifest ()
  (let ((manifest (make-hash-table :test #'equal)))
    (setf (gethash "modules" manifest)
          (map 'vector
               (lambda (module)
                 (let ((entry (make-hash-table :test #'equal))
                       (schema (make-hash-table :test #'equal))
                       (properties (make-hash-table :test #'equal))
                       (options (module-options module)))
                   (unless (or (null options) (consp options))
                     (error "Unsupported option declaration for module ~A: ~S."
                            (module-name module) options))
                   (dolist (option options)
                     (let ((name
                             (cond
                               ((and (symbolp option) option)
                                (string-downcase (symbol-name option)))
                               ((stringp option) option)
                               (t
                                (error "Unsupported option declaration for module ~A: ~S."
                                       (module-name module) option)))))
                       (when (zerop (length name))
                         (error "Option names must be non-empty for module ~A."
                                (module-name module)))
                       (when (nth-value 1 (gethash name properties))
                         (error "Duplicate option declaration for module ~A: ~A."
                                (module-name module) name))
                       (setf (gethash (copy-seq name) properties)
                             (make-hash-table :test #'equal))))
                   (setf (gethash "type" schema) "object"
                         (gethash "properties" schema) properties
                         (gethash "additionalProperties" schema)
                         json-kit:+json-false+
                         (gethash "name" entry) (module-name module)
                         (gethash "capabilities" entry)
                         (%json-value (module-capabilities module))
                         (gethash "options" entry) (%json-value options)
                         (gethash "schema" entry) schema)
                   entry))
               (list-modules)))
    manifest))
