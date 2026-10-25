(defpackage #:nrecon/attack-test
  (:use #:cl #:nrecon.attack)
  (:shadowing-import-from #:cl-weave #:describe)
  (:import-from #:cl-weave #:expect #:it)
  (:export #:run-tests))

(in-package #:nrecon/attack-test)

(defun %test-policy (action host)
  (nrecon.core:make-authorization-policy
   :actions (list action)
   :allowlist (list host)
   :lab-only-p t))

(defun %test-target (host)
  (nrecon.core:make-authorization-target :host host :lab-p t))

(defun %test-packet ()
  (make-array 3 :element-type '(unsigned-byte 8)
                :initial-contents '(1 2 3)))

(defun %deny-result (thunk)
  (handler-case
      (progn (funcall thunk) :sent)
    (attack-authorization-denied () :denied)
    (attack-audit-failure () :denied)))

(describe "nrecon attack frame generation"
  (it "builds an ARP reply with the requested Ethernet and ARP addresses"
    (let* ((packet
             (build-arp-reply
              :source-mac "02:00:00:00:00:11"
              :source-ip "192.0.2.1"
              :target-mac "02:00:00:00:00:22"
              :target-ip "192.0.2.10"))
           (frame (nrecon.net:decode-frame packet))
           (arp (getf frame :arp)))
      (expect (length packet) :to-be 42)
      (expect (getf (getf frame :ethernet) :destination-mac)
              :to-equal "02:00:00:00:00:22")
      (expect (getf arp :operation) :to-be 2)
      (expect (getf arp :sender-hardware-address)
              :to-equal "02:00:00:00:00:11")
      (expect (getf arp :sender-protocol-address) :to-equal "192.0.2.1")
      (expect (getf arp :target-protocol-address) :to-equal "192.0.2.10")))
  (it "builds a decodable DNS A response with IPv4 checksum"
    (let* ((packet
             (build-dns-response-frame
              :source-mac "02:00:00:00:00:53"
              :source-ip "192.0.2.53"
              :target-mac "02:00:00:00:00:10"
              :target-ip "192.0.2.10"
              :query-name "resolver.example.test"
              :identifier #x1234
              :destination-port 49152
              :answer-ip "198.51.100.7"))
           (frame (nrecon.net:decode-frame packet))
           (dns (getf frame :dns)))
      (expect (getf (getf frame :udp) :source-port) :to-be 53)
      (expect (getf (getf frame :udp) :destination-port) :to-be 49152)
      (expect (getf dns :identifier) :to-be #x1234)
      (expect (getf (first (getf dns :questions)) :name)
              :to-equal "resolver.example.test")
      (expect (getf (first (getf dns :answers)) :data)
              :to-equal "198.51.100.7")
      (expect (nrecon.attack::%internet-checksum (subseq packet 14 34))
              :to-be 0)))
  (it "rewrites only Ethernet addresses on a relayed frame"
    (let* ((packet
             (build-arp-reply
              :source-mac "02:00:00:00:00:11"
              :source-ip "192.0.2.1"
              :target-mac "02:00:00:00:00:22"
              :target-ip "192.0.2.10"))
           (rewritten
             (rewrite-l2-frame packet "02:00:00:00:00:99"
                               "02:00:00:00:00:33")))
      (expect (equalp (subseq rewritten 12) (subseq packet 12)) :to-be t)
      (expect (getf (getf (nrecon.net:decode-frame rewritten) :ethernet)
                    :source-mac)
              :to-equal "02:00:00:00:00:99")
      (expect (getf (getf (nrecon.net:decode-frame rewritten) :ethernet)
                    :destination-mac)
              :to-equal "02:00:00:00:00:33"))))

(describe "nrecon attack authorization and audit gate"
  (it "audits and rejects an action without a policy before invoking the sender"
    (let ((events nil)
          (packet (%test-packet)))
      (expect
       (%deny-result
        (lambda ()
          (authorize-and-send
           nil :arp-spoof (%test-target "192.0.2.10")
           (lambda (record)
             (push (list :audit record) events)
             t)
           packet
           (lambda (bytes timeout)
             (declare (ignore bytes timeout))
             (push :send events)))))
       :to-be :denied)
      (expect (mapcar (lambda (event) (if (consp event) :audit event))
                      (nreverse events))
              :to-equal '(:audit))
      (expect (find :packet-bytes (second (first events))) :to-be nil)))
  (it "rejects a target outside the allowlist before invoking the sender"
    (let ((sent nil)
          (audited nil))
      (expect
       (%deny-result
        (lambda ()
          (authorize-and-send
           (%test-policy :arp-spoof "192.0.2.0/24")
           :arp-spoof (%test-target "198.51.100.10")
           (lambda (record) (declare (ignore record)) (setf audited t))
           (%test-packet)
           (lambda (bytes timeout)
             (declare (ignore bytes timeout))
             (setf sent t)))))
       :to-be :denied)
      (expect audited :to-be t)
      (expect sent :to-be nil)))
  (it "does not send when the audit callback fails"
    (let ((sent nil))
      (expect
       (%deny-result
        (lambda ()
          (authorize-and-send
           (%test-policy :arp-spoof "192.0.2.10")
           :arp-spoof (%test-target "192.0.2.10")
           (lambda (record) (declare (ignore record)) nil)
           (%test-packet)
           (lambda (bytes timeout)
             (declare (ignore bytes timeout))
             (setf sent t)))))
       :to-be :denied)
      (expect sent :to-be nil)))
  (it "calls the audit callback immediately before an authorized send"
    (let ((events nil)
          (packet (%test-packet)))
      (expect
       (authorize-and-send
        (%test-policy :arp-spoof "192.0.2.10")
        :arp-spoof (%test-target "192.0.2.10")
        (lambda (record)
          (expect (getf record :action) :to-equal "arp-spoof")
          (expect (getf record :packet-length) :to-be 3)
          (push :audit events)
          t)
        packet
        (lambda (bytes timeout)
          (declare (ignore timeout))
          (push :send events)
          (length bytes)))
       :to-be 3)
      (expect (nreverse events) :to-equal '(:audit :send))))
  (it "relays one captured frame through the same per-send gate"
    (let* ((frame
             (build-arp-reply
              :source-mac "02:00:00:00:00:11"
              :source-ip "192.0.2.1"
              :target-mac "02:00:00:00:00:22"
              :target-ip "192.0.2.10"))
           (events nil)
           (sent nil)
           (relay-mac "02:00:00:00:00:99")
           (result
             (run-mitm-relay
              frame
              :source-mac "02:00:00:00:00:11"
              :destination-mac "02:00:00:00:00:22"
              :interface-mac relay-mac
              :target-host "192.0.2.10"
              :target-lab-p t
              :authorization-policy (%test-policy :mitm-proxy "192.0.2.10")
              :audit-fn (lambda (record)
                          (push :audit events)
                          (expect (getf record :action) :to-equal "mitm-proxy")
                          t)
              :sender (lambda (bytes timeout)
                        (declare (ignore timeout))
                        (push (copy-seq bytes) sent)
                        (push :send events)
                        (length bytes))))
           (relayed (first sent)))
      (expect result :to-be 42)
      (expect (length sent) :to-be 1)
      (expect (equalp (subseq relayed 0 6) (subseq frame 0 6)) :to-be t)
      (expect (equalp (subseq relayed 6 12)
                      (nrecon.attack::%mac-octets relay-mac))
              :to-be t)
      (expect (equalp (subseq relayed 12) (subseq frame 12)) :to-be t)
      (expect (nreverse events) :to-equal '(:audit :send))))
  (it "renders an authorized dry-run JSON plan without invoking its sender"
    (let* ((sent nil)
           (policy (%test-policy :arp-spoof "192.0.2.10"))
           (plan
             (run-attack
              '(:action :arp-spoof
                :source-mac "02:00:00:00:00:11"
                :spoofed-ip "192.0.2.1"
                :target-mac "02:00:00:00:00:22"
                :target-ip "192.0.2.10"
                :dry-run t)
              (list :authorization-policy policy
                    :target-lab-p t
                    :sender (lambda (bytes timeout)
                              (declare (ignore bytes timeout))
                              (setf sent t)))))
           (module (nrecon.core:find-module "attack")))
      (expect (stringp plan) :to-be t)
      (expect (not (null (search "\"dry_run\":true" plan))) :to-be t)
      (expect (not (null (search "\"authorized\":true" plan))) :to-be t)
      (expect sent :to-be nil)
      (expect (nrecon.core:module-name module) :to-equal "attack")))
  (it "escapes JSON strings in dry-run plans"
    (let ((plan
            (render-attack-plan
             :arp-spoof
             (nrecon.core:make-authorization-target
              :host "host.\"quoted" :lab-p t)
             nil 42)))
      (expect (not (null (search "host.\\\"quoted" plan))) :to-be t))))

(defun run-tests ()
  (let* ((plan (cl-weave:list-tests :reporter :sexp
                                    :stream (make-broadcast-stream)))
         (selected-count (length plan)))
    (unless (plusp selected-count)
      (error "The nrecon attack test suite selected no tests."))
    (format t "~&Selected ~D nrecon attack tests.~%" selected-count)
    (let* ((events (cl-weave:run nil :reporter :spec :stream *standard-output*))
           (normalized (cl-weave::normalize-run-results events))
           (passed-count (count :pass normalized
                                :key #'cl-weave::test-event-status)))
      (format t "Passed ~D of ~D selected nrecon attack tests.~%"
              passed-count selected-count)
      (unless (and (= selected-count (length normalized))
                   (= selected-count passed-count))
        (error "The nrecon attack test suite passed ~D of ~D selected tests."
               passed-count selected-count))
      passed-count)))
