(in-package #:nrecon.core)

(defstruct (cps-pipeline
             (:constructor %make-cps-pipeline
                 (dataflow-pipeline nodes edges graph-p)))
  dataflow-pipeline
  nodes
  edges
  graph-p)

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
        (%build-dataflow-pipeline nodes nil nil)
        nodes
        nil
        nil)))
    ((every #'cl-dataflow-kit:node-p nodes-or-stages)
     (unless (and (listp edges)
                  (every #'cl-dataflow-kit:edge-p edges))
       (error "DAG edges must be a list of cl-dataflow-kit edges."))
     (let ((nodes (copy-list nodes-or-stages))
           (edges (copy-list edges)))
       (%make-cps-pipeline
        (%build-dataflow-pipeline nodes edges t)
        nodes
        edges
        t)))
    (t
     (error "Pipeline input must be all stage functions or all DFK nodes."))))

(defun %flatten-promise (value)
  "Resolve nested promises into one promise for the leaf value."
  (if (not (cl-concurrent-kit:promise-p value))
      value
      (let ((flattened (cl-concurrent-kit:make-promise)))
        (labels ((settle (candidate)
                   (if (cl-concurrent-kit:promise-p candidate)
                       (cl-concurrent-kit:promise-then
                        candidate
                        #'settle
                        (lambda (condition)
                          (cl-concurrent-kit:deliver-error
                           flattened
                           condition)))
                       (cl-concurrent-kit:deliver flattened candidate))))
          (handler-case (settle value)
            (error (condition)
              (cl-concurrent-kit:deliver-error flattened condition))))
        flattened)))

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
                           (continuation #'%identity-continuation)
                           control timeout)
  "Run PIPELINE with INPUT. PARALLEL delegates sibling execution to DFK.

Without CONTROL or TIMEOUT, synchronous stages return a value and asynchronous
stage results return a promise. Controlled runs return a promise: successful
runs resolve to the original pipeline value; cancellation and timeout resolve
to RESULT records with :CANCELLED and :TIMED-OUT statuses. TIMEOUT is a
CL-DATE-KIT:DURATION, stored on the run control and visible to handlers via
CURRENT-PIPELINE-RUN-CONTROL. Cancellation is cooperative: a running blocking
handler or native I/O operation may continue until it checks the control or
its transport timeout expires. Later handlers and the terminal continuation
are skipped after cancellation."
  (check-type pipeline cps-pipeline)
  (check-type continuation function)
  (when (and (null control) (null timeout))
    (multiple-value-bind (value pipeline-context)
        (cl-dataflow-kit:run-pipeline-with-context
         (cps-pipeline-dataflow-pipeline pipeline)
         :input input
         :context context
         :parallel parallel)
      (return-from run-cps-pipeline
        (values
         (%map-async value
                     (lambda (resolved-value)
                       (funcall continuation resolved-value pipeline-context)))))))
  (let* ((control (or control (make-pipeline-run-control :timeout timeout)))
         (timeout (or timeout (pipeline-run-control-timeout control))))
    (when timeout
      (check-type timeout cl-date-kit:duration)
      (setf (pipeline-run-control-timeout control) timeout))
    (let* ((dataflow-pipeline
             (%build-dataflow-pipeline
              (cps-pipeline-nodes pipeline)
              (cps-pipeline-edges pipeline)
              (cps-pipeline-graph-p pipeline)
              control))
           (operation
             (%flatten-promise
              (cl-concurrent-kit:future
                (multiple-value-bind (value pipeline-context)
                    (cl-dataflow-kit:run-pipeline-with-context
                     dataflow-pipeline
                     :input input
                     :context context
                     :parallel parallel)
                  (%map-async
                   value
                   (lambda (resolved-value)
                     (if (pipeline-run-cancelled-p control)
                         :pipeline-run-cancelled
                         (let ((*current-pipeline-run-control* control))
                           (funcall continuation resolved-value pipeline-context)))))))))
           (settled-operation
             (cl-concurrent-kit:promise-then
              operation
              (lambda (value) (list :success value))
              (lambda (condition) (list :failure condition))))
           (deadline
             (if timeout
                 (cl-concurrent-kit:promise-timeout settled-operation timeout)
                 settled-operation))
           (race
             (cl-concurrent-kit:promise-race
              (append (%pipeline-run-control-signals control)
                      (list deadline)))))
      (values
       (cl-concurrent-kit:promise-then
        race
        (lambda (outcome)
          (cond
            ((eq outcome :pipeline-run-cancelled)
             (make-result :status :cancelled :value input))
            ((eq (first outcome) :failure)
             (error (second outcome)))
            ((pipeline-run-cancelled-p control)
             (make-result :status :cancelled :value input))
            (t
             (second outcome))))
        (lambda (condition)
          (if (typep condition 'cl-concurrent-kit:operation-timed-out)
              (progn
                (cancel-pipeline-run control)
                (make-result :status :timed-out :value input))
              (error condition))))
       control))))
(defvar *current-pipeline-run-control* nil)
(defstruct (pipeline-run-control
             (:constructor %make-pipeline-run-control (timeout parent)))
  (lock (cl-concurrent-kit:make-lock :name "nrecon pipeline run control"))
  (cancelled-p nil)
  (cancel-signal (cl-concurrent-kit:make-promise))
  timeout
  parent)
(defun make-pipeline-run-control (&key timeout)
  "Create a one-run cancellation token. TIMEOUT must be a CL-DATE-KIT:DURATION."
  (when timeout
    (check-type timeout cl-date-kit:duration))
  (%make-pipeline-run-control timeout nil))
(defun pipeline-run-cancelled-p (control)
  "Return true when CONTROL or one of its parent controls has been cancelled."
  (check-type control pipeline-run-control)
  (or (cl-concurrent-kit:with-lock-held
        ((pipeline-run-control-lock control))
        (pipeline-run-control-cancelled-p control))
      (and (pipeline-run-control-parent control)
           (pipeline-run-cancelled-p
            (pipeline-run-control-parent control)))))
(defun cancel-pipeline-run (control)
  "Cancel CONTROL once. Running handlers stop at their next cooperative boundary."
  (check-type control pipeline-run-control)
  (let ((notify nil))
    (cl-concurrent-kit:with-lock-held
      ((pipeline-run-control-lock control))
      (unless (pipeline-run-control-cancelled-p control)
        (setf (pipeline-run-control-cancelled-p control) t
              notify t)))
    (when notify
      (cl-concurrent-kit:deliver
       (pipeline-run-control-cancel-signal control)
       :pipeline-run-cancelled))
    notify))
(defun current-pipeline-run-control ()
  "Return the control bound while the current stage handler is invoked."
  *current-pipeline-run-control*)
(defun %pipeline-run-control-signals (control)
  (loop for current = control then (pipeline-run-control-parent current)
        while current
        collect (pipeline-run-control-cancel-signal current)))
(defun %controlled-node-handler (handler control)
  (lambda (input context)
    (%map-async
     input
     (lambda (resolved-input)
       (if (and control (pipeline-run-cancelled-p control))
           :pipeline-run-cancelled
           (let ((*current-pipeline-run-control* control))
             (funcall handler resolved-input context)))))))
(defun %build-dataflow-pipeline (nodes edges graph-p &optional control)
  (let ((wrapped-nodes
          (loop for node in nodes
                collect
                (let ((handler (cl-dataflow-kit:node-handler node)))
                  (cl-dataflow-kit:make-node
                   (cl-dataflow-kit:node-name node)
                   :inputs (cl-dataflow-kit:node-inputs node)
                   :outputs (cl-dataflow-kit:node-outputs node)
                   :metadata (cl-dataflow-kit:node-metadata node)
                   :handler (%controlled-node-handler handler control))))))
    (if graph-p
        (let ((graph (cl-dataflow-kit:make-graph)))
          (dolist (node wrapped-nodes)
            (cl-dataflow-kit:add-node graph node))
          (dolist (edge edges)
            (cl-dataflow-kit:add-edge
             graph
             (cl-dataflow-kit:edge-from edge)
             (cl-dataflow-kit:edge-to edge)
             :from-port (cl-dataflow-kit:edge-from-port edge)
             :to-port (cl-dataflow-kit:edge-to-port edge)))
          (cl-dataflow-kit:make-pipeline :graph graph))
        (cl-dataflow-kit:make-pipeline :stages wrapped-nodes))))
(defun run-cps-pipeline-batch
    (pipeline inputs
     &key context (max-in-flight 4) (buffer-size 1) probe-timeout
       parallel (continuation #'%identity-continuation) control)
  "Run INPUTS through PIPELINE with bounded channel backpressure.

Return two values: a promise resolving to an ordered list of RESULT records,
and the shared run control for external cancellation. MAX-IN-FLIGHT bounds
active probes; BUFFER-SIZE configures the source and mapped channels. Each
probe gets a child control, so PROBE-TIMEOUT marks only that probe :TIMED-OUT
and siblings continue. Cancelling the shared control marks active and queued
probes :CANCELLED and skips later handlers. Successful probes are
:COMPLETED records whose VALUE is the pipeline result. A running blocking
handler or native I/O cannot be interrupted until it reaches a cooperative
cancellation check or its transport-native timeout."
  (check-type pipeline cps-pipeline)
  (check-type inputs sequence)
  (check-type max-in-flight (integer 1 *))
  (check-type buffer-size (integer 0 *))
  (check-type continuation function)
  (when probe-timeout
    (check-type probe-timeout cl-date-kit:duration))
  (let ((control (or control (make-pipeline-run-control))))
    (check-type control pipeline-run-control)
    (multiple-value-bind (source source-completion)
        (cl-concurrent-kit:channel-from-sequence
         inputs :buffer-size buffer-size)
      (multiple-value-bind (mapped map-completion)
          (cl-concurrent-kit:channel-map-concurrent
           max-in-flight
           (lambda (input)
             (if (pipeline-run-cancelled-p control)
                 (make-result :status :cancelled :value input)
                 (let* ((local-control
                          (%make-pipeline-run-control probe-timeout control))
                        (outcome
                          (cl-concurrent-kit:await
                           (run-cps-pipeline
                            pipeline input
                            :context context
                            :parallel parallel
                            :continuation continuation
                            :control local-control))))
                   (if (and (result-p outcome)
                            (member (result-status outcome)
                                    '(:cancelled :timed-out)
                                    :test #'eq))
                       outcome
                       (make-result
                        :job-id (and (typep input 'job) (job-id input))
                        :status :completed
                        :value outcome)))))
           source :buffer-size buffer-size)
        (let* ((collected (cl-concurrent-kit:channel-collect mapped))
               (completion
                 (cl-concurrent-kit:promise-all
                  (list source-completion map-completion collected))))
          (values
           (cl-concurrent-kit:promise-then
            completion
            (lambda (values) (third values)))
           control))))))
