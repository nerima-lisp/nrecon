(in-package #:nrecon.attack)

(define-condition attack-authorization-denied (error)
  ((action :initarg :action :reader attack-authorization-denied-action)
   (reason :initarg :reason :reader attack-authorization-denied-reason))
  (:report (lambda (condition stream)
             (format stream "Authorization denied for ~A: ~A."
                     (%action-name
                      (attack-authorization-denied-action condition))
                     (attack-authorization-denied-reason condition)))))

(define-condition attack-audit-failure (error) ()
  (:report "Attack audit callback rejected the outbound packet attempt."))

(defun %action-name (action)
  (etypecase action
    (string (string-downcase action))
    (symbol (string-downcase (symbol-name action)))))

(defun %effective-policy (policy)
  (or policy (make-authorization-policy :actions nil :allowlist nil)))

(defun %decision (policy action target)
  (check-type target authorization-target)
  (authorize-action (%effective-policy policy) action target))

(defun %deadline (timeout)
  (check-type timeout (real 0 *))
  (when (zerop timeout)
    (error "Attack timeout must be greater than zero."))
  (+ (get-internal-real-time)
     (* timeout internal-time-units-per-second)))

(defun %remaining-timeout (deadline)
  (let ((remaining (- deadline (get-internal-real-time))))
    (when (<= remaining 0)
      (error "Attack request deadline expired before packet injection."))
    (/ remaining internal-time-units-per-second)))

(defun %audit-record (action target decision packet)
  (list :event :outbound-packet-attempt
        :action (%action-name action)
        :target (nrecon.core:authorization-target-host target)
        :authorized (authorization-decision-allowed-p decision)
        :reason (authorization-decision-reason decision)
        :packet-length (length packet)))

(defun %send-at-boundary (sender packet timeout)
  (let ((boundary
          (cl-boundary-kit:make-network-boundary
           :request-fn
           (lambda (request &key timeout)
             (funcall (getf request :sender)
                      (getf request :packet)
                      timeout)))))
    (cl-boundary-kit:network-boundary-request
     boundary (list :sender sender :packet packet) :timeout timeout)))

(defun authorize-and-send (policy action target audit-fn packet sender
                           &key (timeout 1.0) deadline)
  "Authorize, audit, then inject one packet through the network boundary.
AUDIT-FN receives metadata only and must return non-NIL on success. SENDER
accepts an octet vector and a timeout in seconds."
  (%check-octets packet)
  (check-type audit-fn function)
  (check-type sender function)
  (let* ((effective-deadline (or deadline (%deadline timeout)))
         (decision (%decision policy action target))
         (record (%audit-record action target decision packet)))
  (unless (funcall audit-fn record)
      (error 'attack-audit-failure))
    (unless (authorization-decision-allowed-p decision)
      (error 'attack-authorization-denied
             :action action
             :reason (authorization-decision-reason decision)))
    (%send-at-boundary sender packet (%remaining-timeout effective-deadline))))

(defun %pcap-open-at-boundary (interface timeout)
  (let ((boundary
          (cl-boundary-kit:make-network-boundary
           :request-fn
           (lambda (request &key timeout)
             (declare (ignore timeout))
             (cl-pcap-kit:injector-open-live
              (getf request :interface)
              :timeout-ms (getf request :timeout-ms))))))
    (cl-boundary-kit:network-boundary-request
     boundary
     (list :interface interface
           :timeout-ms (max 1 (ceiling (* timeout 1000))))
     :timeout timeout)))

(defun %pcap-close-at-boundary (injector timeout)
  (let ((boundary
          (cl-boundary-kit:make-network-boundary
           :request-fn
           (lambda (request &key timeout)
             (declare (ignore timeout))
             (cl-pcap-kit:close-injector (getf request :injector))))))
    (cl-boundary-kit:network-boundary-request
     boundary (list :injector injector) :timeout timeout)))

(defun %preflight-authorization (policy action target)
  (let ((decision (%decision policy action target)))
    (unless (authorization-decision-allowed-p decision)
      (error 'attack-authorization-denied
             :action action
             :reason (authorization-decision-reason decision)))
    decision))

(defun %send-packet (packet action target policy audit-fn
                     &key sender interface (timeout 1.0) deadline)
  (unless audit-fn
    (error "An audit callback is required before active packet injection."))
  (if sender
      (authorize-and-send policy action target audit-fn packet sender
                          :timeout timeout :deadline deadline)
      (progn
        (unless interface
          (error "An interface or an injected sender is required for active packet injection."))
        (%preflight-authorization policy action target)
        (let ((injector (%pcap-open-at-boundary interface timeout)))
          (unwind-protect
               (authorize-and-send
                policy action target audit-fn packet
                (lambda (bytes send-timeout)
                  (cl-pcap-kit:injector-send injector bytes
                                             :timeout send-timeout))
                :timeout timeout :deadline deadline)
            (%pcap-close-at-boundary injector timeout))))))
