(in-package #:nrecon.wire)

(defun render-results (results &key (format :json))
  (let ((objects
          (map 'vector
               (lambda (result)
                 (let ((object (make-hash-table :test #'equal)))
                   (setf (gethash "job_id" object)
                         (%json-value (result-job-id result))
                         (gethash "status" object)
                         (%json-value (result-status result))
                         (gethash "value" object)
                         (%json-value (result-value result))
                         (gethash "metadata" object)
                         (%json-value (result-metadata result)))
                   object))
               results)))
    (case format
      (:json
       (json-kit:stringify objects :sort-keys t))
      (:ndjson
       (format nil "~{~A~^~%~}"
               (map 'list (lambda (object)
                            (json-kit:stringify object :sort-keys t))
                    objects)))
      (:table
       (labels ((cell (value)
                  (if (stringp value)
                      value
                      (json-kit:stringify value :sort-keys t))))
         (format nil "job_id | status | value~%~{~A~%~}"
                 (map 'list (lambda (object)
                              (format nil "~A | ~A | ~A"
                                      (cell (gethash "job_id" object))
                                      (cell (gethash "status" object))
                                      (cell (gethash "value" object))))
                      objects))))
      (otherwise
       (error "Unknown result format: ~S." format))))
)