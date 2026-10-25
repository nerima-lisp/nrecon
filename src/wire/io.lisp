(in-package #:nrecon.wire)

(defun write-results (results &key (format :json) console)
  (let ((console (or console (cl-boundary-kit:make-console))))
    (ecase format
      (:ndjson
       (map nil (lambda (result)
                  (cl-boundary-kit:console-write-line
                   console
                   (render-results (list result) :format :ndjson)))
            results))
      ((:json :table)
       (cl-boundary-kit:console-write-line
        console
        (render-results results :format format))))
    results))
