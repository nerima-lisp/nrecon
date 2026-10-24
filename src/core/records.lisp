(in-package #:nrecon.core)

(defstruct (job (:constructor %make-job (&key id target options)))
  id
  target
  options)

(defun make-job (&key id target options)
  (%make-job :id id
             :target (if (stringp target) (copy-seq target) (copy-tree target))
             :options (copy-tree options)))

(defstruct (result (:constructor %make-result (&key job-id status value metadata)))
  job-id
  status
  value
  metadata)

(defun make-result (&key job-id (status :completed) value metadata)
  (unless (member status '(:completed :failed :cancelled :timed-out) :test #'eq)
    (error "Result status must be :COMPLETED, :FAILED, :CANCELLED, or :TIMED-OUT, got ~S."
           status))
  (%make-result :job-id job-id
                :status status
                :value value
                :metadata (copy-tree metadata)))
