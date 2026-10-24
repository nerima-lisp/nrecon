(in-package #:nrecon.core)

(defstruct (cps-pipeline (:constructor %make-cps-pipeline (&key stages nodes)))
  stages
  nodes)

(defun make-cps-pipeline (stages)
  (unless (and (listp stages) (every #'functionp stages))
    (error "Pipeline stages must be a list of functions."))
  (let ((nodes
          (loop for stage in stages
                for index from 0
                collect
                (let ((stage-function stage))
                  (cl-dataflow-kit:make-node
                   (format nil "nrecon-stage-~D" index)
                   :inputs '("input")
                   :outputs '("output")
                   :handler
                   (lambda (input context)
                     (%map-async input
                                 (lambda (resolved-input)
                                   (funcall stage-function
                                            resolved-input
                                            context)))))))))
    (%make-cps-pipeline :stages (copy-list stages)
                        :nodes nodes)))

(defun %flatten-promise (value)
  (if (cl-concurrent-kit:promise-p value)
      (cl-concurrent-kit:promise-then value #'%flatten-promise)
      value))

(defun %map-async (value function)
  (%flatten-promise
   (if (cl-concurrent-kit:promise-p value)
       (cl-concurrent-kit:promise-then value function)
       (funcall function value))))

(defun %identity-continuation (value context)
  (declare (ignore context))
  value)

(defun run-cps-pipeline (pipeline input
                         &key context (continuation #'%identity-continuation))
  (check-type pipeline cps-pipeline)
  (check-type continuation function)
  (let* ((terminal-function continuation)
         (terminal-node
           (cl-dataflow-kit:make-node
            "nrecon-terminal"
            :inputs '("input")
            :outputs '("output")
            :handler
            (lambda (value dataflow-context)
              (%map-async value
                          (lambda (resolved-value)
                            (funcall terminal-function
                                     resolved-value
                                     dataflow-context))))))
         (dataflow-pipeline
           (cl-dataflow-kit:make-pipeline
            :stages (append (cps-pipeline-nodes pipeline)
                            (list terminal-node)))))
    (cl-dataflow-kit:run-pipeline dataflow-pipeline
                                  :input input
                                  :context context)))
