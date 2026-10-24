(in-package #:nrecon.core)

(defstruct (cps-pipeline
             (:constructor %make-cps-pipeline (dataflow-pipeline)))
  dataflow-pipeline)

(defun make-cps-pipeline (nodes-or-stages &key edges)
  "Build a linear pipeline from stage functions or a DAG from DFK nodes and edges.
DAG nodes declare named input/output ports; EDGES names each connected port."
  (unless (listp nodes-or-stages)
    (error "Pipeline nodes or stages must be a list."))
  (cond
    ((or (null nodes-or-stages)
         (every #'functionp nodes-or-stages))
     (when edges
       (error "Edges are only valid with cl-dataflow-kit nodes."))
     (let* ((stages (or nodes-or-stages
                        (list (lambda (input context)
                                (declare (ignore context))
                                input))))
            (nodes
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
                         (%map-async
                          input
                          (lambda (resolved-input)
                            (funcall stage-function
                                     resolved-input
                                     context)))))))))
       (%make-cps-pipeline
        (cl-dataflow-kit:make-pipeline :stages nodes))))
    ((every #'cl-dataflow-kit:node-p nodes-or-stages)
     (unless (and (listp edges)
                  (every #'cl-dataflow-kit:edge-p edges))
       (error "DAG edges must be a list of cl-dataflow-kit edges."))
     (let ((graph (cl-dataflow-kit:make-graph)))
       (dolist (node nodes-or-stages)
         (let ((handler (cl-dataflow-kit:node-handler node)))
           (cl-dataflow-kit:add-node
            graph
            (cl-dataflow-kit:make-node
             (cl-dataflow-kit:node-name node)
             :inputs (cl-dataflow-kit:node-inputs node)
             :outputs (cl-dataflow-kit:node-outputs node)
             :metadata (cl-dataflow-kit:node-metadata node)
             :handler
             (lambda (input context)
               (%map-async
                input
                (lambda (resolved-input)
                  (funcall handler resolved-input context))))))))
       (dolist (edge edges)
         (cl-dataflow-kit:add-edge
          graph
          (cl-dataflow-kit:edge-from edge)
          (cl-dataflow-kit:edge-to edge)
          :from-port (cl-dataflow-kit:edge-from-port edge)
          :to-port (cl-dataflow-kit:edge-to-port edge)))
       (%make-cps-pipeline
        (cl-dataflow-kit:make-pipeline :graph graph))))
    (t
     (error "Pipeline input must be all stage functions or all DFK nodes."))))

(defun %flatten-promise (value)
  (if (cl-concurrent-kit:promise-p value)
      (cl-concurrent-kit:promise-then value #'%flatten-promise)
      value))

(defun %map-async (value function)
  (labels ((resolve-cons (original resolved-car resolved-cdr)
             (cond
               ((cl-concurrent-kit:promise-p resolved-car)
                (cl-concurrent-kit:promise-then
                 resolved-car
                 (lambda (value)
                   (resolve-cons original value resolved-cdr))))
               ((cl-concurrent-kit:promise-p resolved-cdr)
                (cl-concurrent-kit:promise-then
                 resolved-cdr
                 (lambda (value)
                   (resolve-cons original resolved-car value))))
               ((and (eq resolved-car (car original))
                     (eq resolved-cdr (cdr original)))
                original)
               (t
                (cons resolved-car resolved-cdr))))
           (resolve-tree (candidate)
             (cond
               ((cl-concurrent-kit:promise-p candidate)
                (cl-concurrent-kit:promise-then candidate #'resolve-tree))
               ((consp candidate)
                (resolve-cons candidate
                              (resolve-tree (car candidate))
                              (resolve-tree (cdr candidate))))
               (t
                candidate))))
    (let ((resolved-input (resolve-tree value)))
      (%flatten-promise
       (if (cl-concurrent-kit:promise-p resolved-input)
           (cl-concurrent-kit:promise-then
            resolved-input
            (lambda (resolved-value)
              (resolve-tree (funcall function resolved-value))))
           (resolve-tree (funcall function resolved-input)))))))

(defun %identity-continuation (value context)
  (declare (ignore context))
  value)

(defun run-cps-pipeline (pipeline input
                         &key context parallel
                           (continuation #'%identity-continuation))
  "Run PIPELINE with INPUT. PARALLEL delegates sibling execution to DFK.
Return a value for synchronous runs and a promise when asynchronous results flow
through the pipeline or terminal continuation."
  (check-type pipeline cps-pipeline)
  (check-type continuation function)
  (multiple-value-bind (value pipeline-context)
      (cl-dataflow-kit:run-pipeline-with-context
       (cps-pipeline-dataflow-pipeline pipeline)
       :input input
       :context context
       :parallel parallel)
    (%map-async value
                (lambda (resolved-value)
                  (funcall continuation
                           resolved-value
                           pipeline-context)))))
