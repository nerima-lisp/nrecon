(defpackage #:nrecon/net-test
  (:use #:cl #:nrecon.net)
  (:shadowing-import-from #:cl-weave #:describe)
  (:import-from #:cl-weave #:expect #:it)
  (:export #:run-tests))

(in-package #:nrecon/net-test)

(defun %fixture-pcap-result (path)
  (let ((boundary
          (cl-boundary-kit:make-network-boundary
           :request-fn
           (lambda (request &key timeout)
             (check-type timeout (real 0 *))
             (let ((deadline (+ (get-internal-real-time)
                                (* timeout internal-time-units-per-second)))
                   (packets nil)
                   (status nil))
               (cl-pcap-kit:with-offline-capture (capture (getf request :path))
                 (loop
                   (when (>= (get-internal-real-time) deadline)
                     (setf status :timeout)
                     (return))
                   (multiple-value-bind (packet packet-status)
                       (cl-pcap-kit:capture-next capture)
                     (case packet-status
                       (:packet
                        (push (cl-pcap-kit:packet-bytes packet) packets))
                       (:timeout nil)
                       (:eof
                        (setf status :eof)
                        (return))))))
               (list :packets (nreverse packets) :status status))))))
    (cl-boundary-kit:network-boundary-request
     boundary (list :path path) :timeout 2.0)))
(defun %discovery-fixture-path ()
  (asdf:system-relative-pathname :nrecon/net "src/net/fixtures/discovery.pcap"))
(describe "nrecon net offline protocol dissection"
  (it "reads the fixed capture with offline libpcap and decodes ARP and DNS fields"
    (let* ((capture (%fixture-pcap-result (%discovery-fixture-path)))
           (packets (getf capture :packets))
           (arp (getf (decode-frame (first packets)) :arp))
           (query (getf (decode-frame (third packets)) :dns))
           (answer (getf (decode-frame (fourth packets)) :dns))
           (question (first (getf query :questions)))
           (record (first (getf answer :answers))))
      (expect (getf capture :status) :to-be :eof)
      (expect (length packets) :to-be 4)
      (expect (getf arp :hardware-type) :to-be 1)
      (expect (getf arp :operation) :to-be 1)
      (expect (getf arp :sender-hardware-address)
              :to-equal "02:00:00:00:00:01")
      (expect (getf arp :sender-protocol-address) :to-equal "192.0.2.10")
      (expect (getf question :name) :to-equal "resolver.example.test")
      (expect (getf question :type) :to-be 1)
      (expect (getf answer :identifier) :to-be #x1234)
      (expect (getf record :name) :to-equal "resolver.example.test")
      (expect (getf record :data) :to-equal "198.51.100.7")))
  (it "reconstructs observed IPv4 hosts through the capture boundary"
    (multiple-value-bind (packets status)
        (capture-packets :offline-file (%discovery-fixture-path) :timeout 2.0)
      (let* ((hosts (discover-hosts packets))
             (answer-host
               (find "198.51.100.7" hosts
                     :key (lambda (host)
                            (first (network-host-ip-addresses host)))
                     :test #'string=)))
        (expect status :to-be :eof)
        (expect (discovered-ip-addresses hosts)
                :to-equal
                '("192.0.2.1" "192.0.2.10" "192.0.2.53" "198.51.100.7"))
        (progn
  (expect (and answer-host (network-host-names answer-host))
          :to-equal (quote ("resolver.example.test")))
  (let* ((same-mac-frame (copy-seq (first packets))))
    (setf (aref same-mac-frame 31) 11)
    (let* ((merged-hosts (discover-hosts (cons same-mac-frame packets)))
           (same-mac-host
             (find-if (lambda (host)
                        (member "02:00:00:00:00:01"
                                (network-host-mac-addresses host)
                                :test (function string=)))
                      merged-hosts)))
      (expect (length merged-hosts) :to-be 4)
      (expect (and same-mac-host
                   (sort (copy-list (network-host-ip-addresses same-mac-host))
                         (function string<)))
              :to-equal (quote ("192.0.2.10" "192.0.2.11"))))))))))
(defun run-tests ()
  (let* ((plan (cl-weave:list-tests
                :reporter :sexp
                :stream (make-broadcast-stream)))
         (selected-count (length plan)))
    (unless (plusp selected-count)
      (error "The nrecon net test suite selected no tests."))
    (format t "~&Selected ~D nrecon net tests.~%" selected-count)
    (let* ((events (cl-weave:run nil :reporter :spec :stream *standard-output*))
           (normalized (cl-weave::normalize-run-results events))
           (passed-count (count :pass normalized
                                :key #'cl-weave::test-event-status)))
      (format t "Passed ~D of ~D selected nrecon net tests.~%"
              passed-count selected-count)
      (unless (and (= selected-count (length normalized))
                   (= selected-count passed-count))
        (error "The nrecon net test suite passed ~D of ~D selected tests."
               passed-count selected-count))
      passed-count)))