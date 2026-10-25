(in-package #:nrecon.attack)

(define-condition attack-authorization-denied (error)
  ((action :initarg :action :reader attack-authorization-denied-action)
   (reason :initarg :reason :reader attack-authorization-denied-reason))
  (:report (lambda (condition stream)
             (let ((action (attack-authorization-denied-action condition))
                   (reason (attack-authorization-denied-reason condition)))
               (format stream "Authorization denied for ~A: ~A."
                       (%audit-safe-string
                        (if (or (stringp action) (symbolp action))
                            (%action-name action)
                            action)
                        64)
                       (%audit-safe-string reason 64))))))

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
(defun %audit-safe-string (value limit)
  (check-type limit (integer 1 *))
  (let ((text (typecase value
                (string value)
                (symbol (symbol-name value))
                (t "<non-string>"))))
    (with-output-to-string (stream)
      (let ((written 0))
        (loop for index below (min (length text) (min (* limit 4) 4096))
              while (< written limit)
              for character = (char text index)
              for code = (char-code character)
              unless (or (<= code 31)
                         (<= 127 code 159)
                         (= code #x2028)
                         (= code #x2029))
                do (write-char character stream)
                   (incf written))))))
(defun %ipv4-allowlist-entry-matches-p (entry address-octets)
  (when (and (stringp entry)
             (typep address-octets '(vector (unsigned-byte 8)))
             (= (length address-octets) 4))
    (let ((slash (position #\/ entry)))
      (if slash
          (let* ((prefix-text (subseq entry (1+ slash)))
                 (valid-prefix-text
                   (and (<= 1 (length prefix-text) 2)
                        (every (lambda (character)
                                 (char<= #\0 character #\9))
                               prefix-text)
                        (or (= (length prefix-text) 1)
                            (char/= (char prefix-text 0) #\0))))
                 (prefix (and valid-prefix-text
                              (parse-integer prefix-text)))
                 (network (%ipv4-literal-octets
                           (subseq entry 0 slash))))
            (and network prefix
                 (<= 0 prefix 32)
                 (loop for index below 4
                       for bits = (- prefix (* index 8))
                       for mask = (cond ((>= bits 8) #xff)
                                        ((<= bits 0) 0)
                                        (t (logand #xff (ash #xff (- 8 bits)))))
                       always (= (logand (aref network index) mask)
                                 (logand (aref address-octets index) mask)))))
          (let ((literal (%ipv4-literal-octets entry)))
            (and literal (equalp literal address-octets)))))))
(defun %trusted-lab-destination-p (policy address-octets)
  "The configured IPv4 exact entries and CIDRs prove lab scope; caller flags do not."
  (some (lambda (entry)
          (%ipv4-allowlist-entry-matches-p entry address-octets))
        (nrecon.core:authorization-policy-allowlist
         (%effective-policy policy))))

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
        :action (%audit-safe-string (%action-name action) 64)
        :target (%audit-safe-string
                 (nrecon.core:authorization-target-host target) 256)
        :authorized (authorization-decision-allowed-p decision)
        :reason (%audit-safe-string
                 (authorization-decision-reason decision) 64)
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
     boundary (list :sender sender :packet (copy-seq packet)) :timeout timeout)))

(defun authorize-and-send (policy action target audit-fn packet sender
                           &key (timeout 1.0) deadline)
  "Authorize the packet snapshot, persist its decision, then inject those same bytes.
TARGET is a strict expected-destination assertion. It does not supply authorization
or lab status. AUDIT-FN must return :PERSISTED only after durable persistence.
SENDER accepts packet bytes and a timeout in seconds. SENDER is a trusted injection
primitive that must transmit exactly the byte sequence it receives. Never provide
an attacker-controlled value as SENDER."
  (check-type target authorization-target)
  (check-type sender function)
  (let* ((packet-snapshot (copy-seq (%check-octets packet)))
         (effective-deadline (or deadline (%deadline timeout))))
    (multiple-value-bind (actual-host actual-octets)
        (%attack-packet-destination-address packet-snapshot)
      (unless (equalp (nrecon.core:authorization-target-host target) actual-host)
        (error 'attack-authorization-denied
               :action action
               :reason "Expected destination does not match packet destination."))
      (let ((packet-target
              (make-authorization-target
               :host actual-host
               :lab-p (%trusted-lab-destination-p policy actual-octets))))
        (%authorize-and-audit policy action packet-target audit-fn packet-snapshot)
        (%send-at-boundary sender packet-snapshot
                           (%remaining-timeout effective-deadline))))))

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

(defun %authorize-and-audit (policy action target audit-fn packet)
  (%check-octets packet)
  (let* ((decision (%decision policy action target))
         (record (%audit-record action target decision packet)))
    (check-type audit-fn function)
    (unless (handler-case (eq (funcall audit-fn record) :persisted)
              (error () nil))
      (error 'attack-audit-failure))
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
        (authorize-and-send
         policy action target audit-fn packet
         (lambda (bytes send-timeout)
           (let ((injector
                   (%pcap-open-at-boundary interface send-timeout)))
             (unwind-protect
                  (cl-pcap-kit:injector-send injector bytes
                                             :timeout send-timeout)
               (%pcap-close-at-boundary injector timeout))))
         :timeout timeout :deadline deadline))))
