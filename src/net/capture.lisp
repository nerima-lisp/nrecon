(in-package #:nrecon.net)

(defparameter *default-capture-timeout* 5.0)

(defun %validate-capture-timeout (timeout)
  (check-type timeout (real 0 *))
  (when (zerop timeout)
    (error "Capture timeout must be greater than zero."))
  timeout)

(defun %capture-deadline (timeout)
  (+ (get-internal-real-time)
     (* timeout internal-time-units-per-second)))

(defun %capture-expired-p (deadline)
  (>= (get-internal-real-time) deadline))

(defun %capture-result (packets status)
  (list :packets (nreverse packets) :status status))

(defun %capture-offline (path deadline)
  (let ((packets nil))
    (cl-pcap-kit:with-offline-capture (capture path)
      (loop
        (when (%capture-expired-p deadline)
          (return-from %capture-offline (%capture-result packets :timeout)))
        (multiple-value-bind (packet status) (cl-pcap-kit:capture-next capture)
          (case status
            (:packet (push (cl-pcap-kit:packet-bytes packet) packets))
            (:timeout nil)
            (:eof (return-from %capture-offline
                    (%capture-result packets :eof)))))))))

(defun %capture-live (device promiscuous-p deadline)
  (let ((packets nil))
    (cl-pcap-kit:with-live-capture (capture device
                                  :promiscuous-p promiscuous-p
                                  :timeout-ms 100)
      (loop
        (when (%capture-expired-p deadline)
          (return-from %capture-live (%capture-result packets :timeout)))
        (multiple-value-bind (packet status) (cl-pcap-kit:capture-next capture)
          (case status
            (:packet (push (cl-pcap-kit:packet-bytes packet) packets))
            (:timeout nil)
            (:eof (return-from %capture-live
                    (%capture-result packets :eof)))))))))

(defun %capture-request (request &key timeout)
  (%validate-capture-timeout timeout)
  (let ((deadline (%capture-deadline timeout)))
    (case (getf request :source-kind)
      (:offline (%capture-offline (getf request :path) deadline))
      (:live (%capture-live (getf request :device)
                            (getf request :promiscuous-p)
                            deadline))
      (otherwise (error "Unknown passive capture source: ~S." request)))))

(defun capture-packets (&key offline-file device (timeout *default-capture-timeout*)
                          (promiscuous-p nil))
  (%validate-capture-timeout timeout)
  (check-type promiscuous-p boolean)
  (when (and offline-file device)
    (error "Specify only one of :OFFLINE-FILE and :DEVICE."))
  (unless (or offline-file device)
    (error "Specify either :OFFLINE-FILE or :DEVICE for passive capture."))
  (let* ((request
           (if offline-file
               (progn
                 (check-type offline-file (or string pathname))
                 (list :source-kind :offline :path offline-file))
               (progn
                 (check-type device string)
                 (list :source-kind :live :device device
                       :promiscuous-p promiscuous-p))))
         (boundary
           (cl-boundary-kit:make-network-boundary
            :request-fn #'%capture-request))
         (result
           (cl-boundary-kit:network-boundary-request
            boundary request :timeout timeout)))
    (values (getf result :packets) (getf result :status))))

(defun discover-network (&key offline-file device
                           (timeout *default-capture-timeout*)
                           (promiscuous-p nil))
  (multiple-value-bind (packets status)
      (capture-packets :offline-file offline-file
                       :device device
                       :timeout timeout
                       :promiscuous-p promiscuous-p)
    (values (discover-hosts packets) packets status)))

(defun %module-option (options name)
  (cond
    ((hash-table-p options)
     (let ((keyword (intern (string-upcase name) :keyword)))
       (or (gethash name options)
           (gethash keyword options))))
    ((listp options)
     (getf options (intern (string-upcase name) :keyword)))
    (t nil)))

(defun run-net (input context)
  (declare (ignore context))
  (let* ((options (if (typep input 'nrecon.core:job)
                      (nrecon.core:job-options input)
                      input))
         (offline-file (%module-option options "offline-file"))
         (device (%module-option options "device"))
         (timeout (or (%module-option options "timeout")
                      *default-capture-timeout*))
         (promiscuous-p (%module-option options "promiscuous-p")))
    (discover-network :offline-file offline-file
                      :device device
                      :timeout timeout
                      :promiscuous-p promiscuous-p)))

(nrecon.core:define-module net
  :capabilities (:passive-capture)
  :options (offline-file device timeout promiscuous-p)
  :run run-net)
