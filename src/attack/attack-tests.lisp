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

(defun %test-packet (&optional (target-ip "192.0.2.10"))
  (build-arp-reply
   :source-mac "02:00:00:00:00:11"
   :source-ip "192.0.2.1"
   :target-mac "02:00:00:00:00:22"
   :target-ip target-ip))

(defun %deny-result (thunk)
  (handler-case
      (progn (funcall thunk) :sent)
    (attack-authorization-denied () :denied)
    (attack-audit-failure () :denied)))
(defun %error-result (thunk)
  (handler-case
      (progn (funcall thunk) :accepted)
    (error () :rejected)))

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
  (it "records a denied decision before returning and never invokes the sender"
    (let ((events nil)
          (packet (%test-packet)))
      (expect
       (%deny-result
        (lambda ()
          (authorize-and-send
           nil :arp-spoof (%test-target "192.0.2.10")
           (lambda (record)
             (push (list :audit record) events)
             :persisted)
           packet
           (lambda (bytes timeout)
             (declare (ignore bytes timeout))
             (push :send events)))))
       :to-be :denied)
      (expect (mapcar (lambda (event) (if (consp event) :audit event))
                      (nreverse events))
              :to-equal (list :audit))
      (expect (getf (second (first events)) :authorized) :to-be nil)
      (expect (getf (second (first events)) :packet-length) :to-be 42)))
  (it "rejects a target outside the allowlist before invoking the sender"
    (let ((sent nil)
          (audited nil))
      (expect
       (%deny-result
        (lambda ()
          (authorize-and-send
           (%test-policy :arp-spoof "192.0.2.0/24")
           :arp-spoof (%test-target "198.51.100.10")
           (lambda (record)
             (declare (ignore record))
             (setf audited t)
             :persisted)
           (%test-packet "198.51.100.10")
           (lambda (bytes timeout)
             (declare (ignore bytes timeout))
             (setf sent t)))))
       :to-be :denied)
      (expect audited :to-be t)
      (expect sent :to-be nil)))
  (it "requires an explicit durable audit acknowledgment before sending"
    (let ((sent nil)
          (audit-count 0))
      (dolist (acknowledgment (list :failed t))
        (expect
         (%deny-result
          (lambda ()
            (authorize-and-send
             (%test-policy :arp-spoof "192.0.2.10")
             :arp-spoof (%test-target "192.0.2.10")
             (lambda (record)
               (declare (ignore record))
               (incf audit-count)
               acknowledgment)
             (%test-packet)
             (lambda (bytes timeout)
               (declare (ignore bytes timeout))
               (setf sent t)))))
         :to-be :denied))
      (expect audit-count :to-be 2)
      (expect sent :to-be nil)))
  (it "audits an allowed decision before invoking the sender"
    (let ((events nil)
          (packet (%test-packet)))
      (expect
       (authorize-and-send
        (%test-policy :arp-spoof "192.0.2.10")
        :arp-spoof (%test-target "192.0.2.10")
        (lambda (record)
          (expect (getf record :action) :to-equal "arp-spoof")
          (expect (getf record :authorized) :to-be t)
          (expect (getf record :packet-length) :to-be 42)
          (push :audit events)
          :persisted)
        packet
        (lambda (bytes timeout)
          (declare (ignore timeout))
          (push :send events)
          (length bytes)))
       :to-be 42)
      (expect (nreverse events) :to-equal (list :audit :send))))
  (it "removes controls and bounds user values before passing audit metadata"
    (let* ((control-prefix
             (coerce (list #\a #\Newline #\b #\Tab #\c #\Return #\d
                           (code-char 27))
                     'string))
           (host (concatenate 'string control-prefix
                              (make-string 300 :initial-element #\x)))
           (expected-host (concatenate 'string "abcd"
                                       (make-string 252 :initial-element #\x)))
           (action (concatenate 'string "arp" (string (code-char 10)) "-spoof"))
           (record nil)
           (sent nil))
      (expect
       (%deny-result
        (lambda ()
          (authorize-and-send
           (%test-policy :arp-spoof "192.0.2.10")
           action (%test-target "192.0.2.10")
           (lambda (audit-record)
             (setf record audit-record)
             :persisted)
           (%test-packet)
           (lambda (bytes timeout)
             (declare (ignore bytes timeout))
             (setf sent t)))))
       :to-be :denied)
      (expect (getf record :action) :to-equal "arp-spoof")
      (expect (getf record :target) :to-equal "192.0.2.10")
      (expect (getf record :authorized) :to-be nil)
      (expect (<= (length (getf record :reason)) 64) :to-be t)
      (expect sent :to-be nil)
      (expect (nrecon.attack::%audit-safe-string host 256)
              :to-equal expected-host)
      (expect (length (nrecon.attack::%audit-safe-string host 256))
              :to-be 256)))
  (it "rejects a relay target that differs from the rewritten frame destination"
    (let* ((frame
             (build-dns-response-frame
              :source-mac "02:00:00:00:00:11"
              :source-ip "192.0.2.53"
              :target-mac "02:00:00:00:00:22"
              :target-ip "192.0.2.10"
              :query-name "resolver.example.test"
              :answer-ip "198.51.100.7"))
           (audited nil)
           (sent nil))
      (expect
       (%error-result
        (lambda ()
          (run-mitm-relay
           frame
           :source-mac "02:00:00:00:00:11"
           :destination-mac "02:00:00:00:00:22"
           :interface-mac "02:00:00:00:00:99"
           :target-host "198.51.100.10"
           :authorization-policy (%test-policy :mitm-proxy "198.51.100.10")
           :audit-fn (lambda (record)
                       (declare (ignore record))
                       (setf audited t)
                       :persisted)
           :sender (lambda (bytes timeout)
                     (declare (ignore bytes timeout))
                     (setf sent t)))))
       :to-be :rejected)
      (expect audited :to-be nil)
      (expect sent :to-be nil)))
  (it "rejects unsupported and malformed relay frames before audit or send"
    (let* ((frame
             (build-dns-response-frame
              :source-mac "02:00:00:00:00:11"
              :source-ip "192.0.2.53"
              :target-mac "02:00:00:00:00:22"
              :target-ip "192.0.2.10"
              :query-name "resolver.example.test"
              :answer-ip "198.51.100.7"))
           (unsupported (copy-seq frame))
           (truncated (subseq frame 0 20))
           (fragmented (copy-seq frame))
           (unsupported-transport (copy-seq frame))
           (audited 0)
           (sent 0))
      (setf (aref unsupported 12) #x86
            (aref unsupported 13) #xdd
            (aref fragmented 20) #x20
            (aref fragmented 21) #x00
            (aref unsupported-transport 23) 1)
      (dolist (bad-frame (list unsupported truncated fragmented
                                unsupported-transport))
        (expect
         (%error-result
          (lambda ()
            (run-mitm-relay
             bad-frame
             :source-mac "02:00:00:00:00:11"
             :destination-mac "02:00:00:00:00:22"
             :interface-mac "02:00:00:00:00:99"
             :target-host "192.0.2.10"
             :authorization-policy (%test-policy :mitm-proxy "192.0.2.10")
             :audit-fn (lambda (record)
                         (declare (ignore record))
                         (incf audited)
                         :persisted)
             :sender (lambda (bytes timeout)
                       (declare (ignore bytes timeout))
                       (incf sent)))))
         :to-be :rejected))
      (expect audited :to-be 0)
      (expect sent :to-be 0)))
  (it "uses configured IPv4 exact entries and CIDRs as lab-scope proof"
    (let ((destination (nrecon.attack::%ipv4-literal-octets "192.0.2.10")))
      (expect (nrecon.attack::%trusted-lab-destination-p
               (%test-policy :arp-spoof "192.0.2.10") destination)
              :to-be t)
      (expect (nrecon.attack::%trusted-lab-destination-p
               (%test-policy :arp-spoof "192.0.2.0/24") destination)
              :to-be t)
      (expect (nrecon.attack::%trusted-lab-destination-p
               (%test-policy :arp-spoof "192.0.3.0/24") destination)
              :to-be nil)
      (expect (nrecon.attack::%trusted-lab-destination-p
               (%test-policy :arp-spoof "resolver.example.test") destination)
              :to-be nil)))
  (it "ignores a spoofed context lab flag for an out-of-scope target"
    (let ((record nil)
          (sent nil))
      (expect
       (%deny-result
        (lambda ()
          (run-attack
           (list :action :arp-spoof
                 :source-mac "02:00:00:00:00:11"
                 :spoofed-ip "192.0.2.1"
                 :target-mac "02:00:00:00:00:22"
                 :target-ip "198.51.100.10")
           (list :authorization-policy
                 (%test-policy :arp-spoof "192.0.2.0/24")
                 :target-lab-p t
                 :audit-fn (lambda (audit-record)
                             (setf record audit-record)
                             :persisted)
                 :sender (lambda (bytes timeout)
                           (declare (ignore bytes timeout))
                           (setf sent t))))))
       :to-be :denied)
      (expect (getf record :authorized) :to-be nil)
      (expect sent :to-be nil)))
  (it "ignores a spoofed MITM lab flag for the actual frame destination"
  (let* ((frame
           (build-dns-response-frame
            :source-mac "02:00:00:00:00:11"
            :source-ip "192.0.2.53"
            :target-mac "02:00:00:00:00:22"
            :target-ip "198.51.100.10"
            :query-name "resolver.example.test"
            :answer-ip "198.51.100.7"))
         (record nil)
         (sent nil))
    (expect
     (%deny-result
      (lambda ()
        (run-mitm-relay
         frame
         :source-mac "02:00:00:00:00:11"
         :destination-mac "02:00:00:00:00:22"
         :interface-mac "02:00:00:00:00:99"
         :target-host "198.51.100.10"
         :target-lab-p t
         :authorization-policy (%test-policy :mitm-proxy "192.0.2.0/24")
         :audit-fn (lambda (audit-record)
                     (setf record audit-record)
                     :persisted)
         :sender (lambda (bytes timeout)
                   (declare (ignore bytes timeout))
                   (setf sent t)))))
     :to-be :denied)
    (expect (getf record :authorized) :to-be nil)
    (expect sent :to-be nil)))
  (it "relays an allowed IPv4 UDP frame through only the injected sender"
    (let* ((frame
             (build-dns-response-frame
              :source-mac "02:00:00:00:00:11"
              :source-ip "192.0.2.53"
              :target-mac "02:00:00:00:00:22"
              :target-ip "192.0.2.10"
              :query-name "resolver.example.test"
              :answer-ip "198.51.100.7"))
           (events nil)
           (sent nil)
           (relay-mac "02:00:00:00:00:99")
           (record nil)
           (result
             (run-mitm-relay
              frame
              :source-mac "02:00:00:00:00:11"
              :destination-mac "02:00:00:00:00:22"
              :interface-mac relay-mac
              :target-host "192.0.2.10"
              :target-lab-p nil
              :authorization-policy (%test-policy :mitm-proxy "192.0.2.0/24")
              :audit-fn (lambda (audit-record)
                          (setf record audit-record)
                          (push :audit events)
                          :persisted)
              :sender (lambda (bytes timeout)
                        (declare (ignore timeout))
                        (push (copy-seq bytes) sent)
                        (push :send events)
                        (length bytes))))
           (relayed (first sent)))
      (expect result :to-be (length frame))
      (expect (length sent) :to-be 1)
      (expect (getf record :target) :to-equal "192.0.2.10")
      (expect (getf record :authorized) :to-be t)
      (expect (equalp (subseq relayed 0 6) (subseq frame 0 6)) :to-be t)
      (expect (equalp (subseq relayed 6 12)
                      (nrecon.attack::%mac-octets relay-mac))
              :to-be t)
      (expect (equalp (subseq relayed 12) (subseq frame 12)) :to-be t)
      (expect (nreverse events) :to-equal (list :audit :send))))
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
                    :target-lab-p nil
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
      (expect (not (null (search "host.\\\"quoted" plan))) :to-be t)))
  (it "rejects an allowlisted expected target when the packet encodes another destination"
    (let* ((policy (%test-policy :arp-spoof "192.0.2.10"))
           (packet (%test-packet "198.51.100.10"))
           (audited nil)
           (sent nil))
      (multiple-value-bind (actual-host actual-octets)
          (nrecon.attack::%attack-packet-destination-address packet)
        (declare (ignore actual-octets))
        (expect actual-host :to-equal "198.51.100.10"))
      (expect (nrecon.core:authorization-policy-allowlist policy)
              :to-equal (list "192.0.2.10"))
      (expect
       (%deny-result
        (lambda ()
          (authorize-and-send
           policy :arp-spoof (%test-target "192.0.2.10")
           (lambda (record)
             (declare (ignore record))
             (setf audited t)
             :persisted)
           packet
           (lambda (bytes timeout)
             (declare (ignore bytes timeout))
             (setf sent t)))))
       :to-be :denied)
      (expect audited :to-be nil)
      (expect sent :to-be nil)))
  (it "derives lab authorization from the packet despite a false caller lab flag"
    (let* ((policy (%test-policy :arp-spoof "192.0.2.10"))
           (packet (%test-packet))
           (target (nrecon.core:make-authorization-target
                    :host "192.0.2.10" :lab-p nil))
           (record nil)
           (sent nil)
           (sent-destination nil)
           (events nil)
           (result
             (authorize-and-send
              policy :arp-spoof target
              (lambda (audit-record)
                (setf record audit-record)
                (push :audit events)
                :persisted)
              packet
              (lambda (bytes timeout)
                (declare (ignore timeout))
                (setf sent (copy-seq bytes))
                (multiple-value-bind (actual-host actual-octets)
                    (nrecon.attack::%attack-packet-destination-address bytes)
                  (declare (ignore actual-octets))
                  (setf sent-destination actual-host))
                (push :send events)
                (length bytes)))))
      (expect (nrecon.core:authorization-policy-allowlist policy)
              :to-equal (list "192.0.2.10"))
      (expect result :to-be 42)
      (expect (equalp sent packet) :to-be t)
      (expect sent-destination :to-equal "192.0.2.10")
      (expect (getf record :target) :to-equal "192.0.2.10")
      (expect (getf record :authorized) :to-be t)
      (expect (nreverse events) :to-equal (list :audit :send))))
  (it "sends the authorized packet snapshot after audit mutates shared options"
    (let* ((options (make-hash-table))
           (policy (%test-policy :arp-spoof "192.0.2.10"))
           (expected-packet
             (build-arp-reply
              :source-mac "02:00:00:00:00:11"
              :source-ip "192.0.2.1"
              :target-mac "02:00:00:00:00:22"
              :target-ip "192.0.2.10"))
           (mutated nil)
           (record nil)
           (sent nil)
           (sent-destination nil)
           (result nil))
      (setf (gethash :action options) :arp-spoof
            (gethash :source-mac options) "02:00:00:00:00:11"
            (gethash :spoofed-ip options) "192.0.2.1"
            (gethash :target-mac options) "02:00:00:00:00:22"
            (gethash :target-ip options) "192.0.2.10")
      (setf result
            (run-attack
             options
             (list :authorization-policy policy
                   :target-lab-p nil
                   :audit-fn
                   (lambda (audit-record)
                     (setf record audit-record
                           (gethash :target-ip options) "198.51.100.10"
                           mutated t)
                     :persisted)
                   :sender
                   (lambda (bytes timeout)
                     (declare (ignore timeout))
                     (setf sent (copy-seq bytes))
                     (multiple-value-bind (actual-host actual-octets)
                         (nrecon.attack::%attack-packet-destination-address bytes)
                       (declare (ignore actual-octets))
                       (setf sent-destination actual-host))
                     (length bytes)))))
      (expect (gethash :target-ip options) :to-equal "198.51.100.10")
      (expect mutated :to-be t)
      (expect (nrecon.core:authorization-policy-allowlist policy)
              :to-equal (list "192.0.2.10"))
      (expect result :to-be 42)
      (expect (equalp sent expected-packet) :to-be t)
      (expect sent-destination :to-equal "192.0.2.10")
      (expect (getf record :target) :to-equal "192.0.2.10")
      (expect (getf record :authorized) :to-be t)))
  (it "does not expose the authorized snapshot to a mutating sender"
    (let* ((authorized-snapshot (%test-packet))
           (expected-packet (copy-seq authorized-snapshot))
           (sender-buffer nil)
           (sender-input nil)
           (record nil)
           (public-sender-buffer nil)
           (public-sender-input nil))
      (nrecon.attack::%send-at-boundary
       (lambda (bytes timeout)
         (declare (ignore timeout))
         (setf sender-buffer bytes
               sender-input (copy-seq bytes)
               (aref bytes 38) 198
               (aref bytes 39) 51
               (aref bytes 40) 100
               (aref bytes 41) 10)
         (length bytes))
       authorized-snapshot 1.0)
      (expect (eq sender-buffer authorized-snapshot) :to-be nil)
      (expect (equalp sender-input expected-packet) :to-be t)
      (expect (equalp authorized-snapshot expected-packet) :to-be t)
      (multiple-value-bind (snapshot-host snapshot-octets)
          (nrecon.attack::%attack-packet-destination-address authorized-snapshot)
        (declare (ignore snapshot-octets))
        (expect snapshot-host :to-equal "192.0.2.10"))
      (multiple-value-bind (sender-host sender-octets)
          (nrecon.attack::%attack-packet-destination-address sender-buffer)
        (declare (ignore sender-octets))
        (expect sender-host :to-equal "198.51.100.10"))
      (expect
       (authorize-and-send
        (%test-policy :arp-spoof "192.0.2.10")
        :arp-spoof (%test-target "192.0.2.10")
        (lambda (audit-record)
          (setf record audit-record)
          :persisted)
        (%test-packet)
        (lambda (bytes timeout)
          (declare (ignore timeout))
          (setf public-sender-buffer bytes
                public-sender-input (copy-seq bytes)
                (aref bytes 38) 198
                (aref bytes 39) 51
                (aref bytes 40) 100
                (aref bytes 41) 10)
          (length bytes)))
       :to-be 42)
      (expect (equalp public-sender-input expected-packet) :to-be t)
      (multiple-value-bind (input-host input-octets)
          (nrecon.attack::%attack-packet-destination-address public-sender-input)
        (declare (ignore input-octets))
        (expect input-host :to-equal "192.0.2.10"))
      (expect (getf record :target) :to-equal "192.0.2.10")
      (expect (getf record :authorized) :to-be t)
      (multiple-value-bind (public-sender-host public-sender-octets)
          (nrecon.attack::%attack-packet-destination-address public-sender-buffer)
        (declare (ignore public-sender-octets))
        (expect public-sender-host :to-equal "198.51.100.10")))))

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
