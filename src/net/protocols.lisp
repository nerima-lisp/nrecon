(in-package #:nrecon.net)

(define-dissector ethernet
  ((destination-mac :mac)
   (source-mac :mac)
   (ether-type :u16)))

(define-dissector arp
  ((hardware-type :u16)
   (protocol-type :u16)
   (hardware-length :u8)
   (protocol-length :u8)
   (operation :u16)
   (sender-hardware-address :mac)
   (sender-protocol-address :ipv4)
   (target-hardware-address :mac)
   (target-protocol-address :ipv4)))

(define-dissector ipv4
  ((version-ihl :u8)
   (service-type :u8)
   (total-length :u16)
   (identification :u16)
   (flags-fragment-offset :u16)
   (ttl :u8)
   (protocol :u8)
   (header-checksum :u16)
   (source-address :ipv4)
   (destination-address :ipv4)))

(define-dissector udp
  ((source-port :u16)
   (destination-port :u16)
   (length :u16)
   (checksum :u16)))

(define-dissector dns-header
  ((identifier :u16)
   (flags :u16)
   (question-count :u16)
   (answer-count :u16)
   (authority-count :u16)
   (additional-count :u16)))

(define-dissector dns-question-tail
  ((type :u16)
   (class :u16)))

(define-dissector dns-record-header
  ((type :u16)
   (class :u16)
   (ttl :u32)
   (data-length :u16)))

(defun %decode-dns-name (bytes offset end)
  (let ((position offset)
        (consumed-end nil)
        (wire-length 1)
        (labels nil)
        (visited (make-hash-table)))
    (loop
      (%require-bytes bytes position end 1)
      (let ((label-length (aref bytes position)))
        (cond
          ((zerop label-length)
           (return-from %decode-dns-name
             (values (format nil "~{~A~^.~}" (nreverse labels))
                     (or consumed-end (1+ position)))))
          ((= (logand label-length #xc0) #xc0)
           (%require-bytes bytes position end 2)
           (let ((target (logior (ash (logand label-length #x3f) 8)
                                 (aref bytes (1+ position)))))
             (when (or (>= target end) (gethash target visited))
               (error 'malformed-packet
                      :offset position :required 2 :available (- end position)))
             (setf (gethash target visited) t
                   consumed-end (or consumed-end (+ position 2))
                   position target)))
          ((/= (logand label-length #xc0) 0)
           (error 'malformed-packet
                  :offset position :required 1 :available (- end position)))
          (t
           (incf position)
           (%require-bytes bytes position end label-length)
           (incf wire-length (1+ label-length))
           (when (> wire-length 255)
             (error 'malformed-packet
                    :offset offset :required wire-length :available (- end offset)))
           (push (map 'string #'code-char
                      (subseq bytes position (+ position label-length)))
                 labels)
           (incf position label-length)))))))

(defun %decode-dns-question (bytes offset end)
  (multiple-value-bind (name name-end) (%decode-dns-name bytes offset end)
    (multiple-value-bind (tail next)
        (dissect-dns-question-tail bytes :offset name-end :end end)
      (values (list :name name :type (getf tail :type) :class (getf tail :class))
              next))))

(defun %decode-dns-record (bytes offset end)
  (multiple-value-bind (name name-end) (%decode-dns-name bytes offset end)
    (multiple-value-bind (header data-offset)
        (dissect-dns-record-header bytes :offset name-end :end end)
      (let* ((data-end (+ data-offset (getf header :data-length)))
             (type (getf header :type)))
        (%require-bytes bytes data-offset end (getf header :data-length))
        (let ((data
                (cond
                  ((and (= type 1) (= (getf header :data-length) 4))
                   (nth-value 0
                     (%decode-ipv4-address bytes data-offset data-end)))
                  ((member type '(5 12))
                   (multiple-value-bind (decoded-name name-end)
                       (%decode-dns-name bytes data-offset end)
                     (unless (<= name-end data-end)
                       (error 'malformed-packet
                              :offset data-offset
                              :required (- name-end data-offset)
                              :available (getf header :data-length)))
                     decoded-name))
                  (t (subseq bytes data-offset data-end)))))
          (values (list :name name
                        :type type
                        :class (getf header :class)
                        :ttl (getf header :ttl)
                        :data data)
                  data-end))))))

(defun %decode-dns-section (bytes offset end count decoder)
  (let ((position offset)
        (records nil))
    (dotimes (index count)
      (declare (ignore index))
      (multiple-value-bind (record next) (funcall decoder bytes position end)
        (push record records)
        (setf position next)))
    (values (nreverse records) position)))

(defun dissect-dns (bytes &key (offset 0) (end (length bytes)))
  (%check-dissector-input bytes offset end)
  (let* ((message (subseq bytes offset end))
         (message-end (length message)))
    (multiple-value-bind (header position)
        (dissect-dns-header message :offset 0 :end message-end)
      (let ((questions nil)
            (answers nil)
            (authorities nil)
            (additionals nil))
        (multiple-value-setq (questions position)
          (%decode-dns-section message position message-end
                               (getf header :question-count)
                               (function %decode-dns-question)))
        (multiple-value-setq (answers position)
          (%decode-dns-section message position message-end
                               (getf header :answer-count)
                               (function %decode-dns-record)))
        (multiple-value-setq (authorities position)
          (%decode-dns-section message position message-end
                               (getf header :authority-count)
                               (function %decode-dns-record)))
        (multiple-value-setq (additionals position)
          (%decode-dns-section message position message-end
                               (getf header :additional-count)
                               (function %decode-dns-record)))
        (values (append header
                        (list :questions questions
                              :answers answers
                              :authorities authorities
                              :additionals additionals))
                (+ offset position))))))

(defun decode-frame (bytes)
  (%check-dissector-input bytes 0 (length bytes))
  (multiple-value-bind (ethernet payload-offset) (dissect-ethernet bytes)
    (let ((frame (list :ethernet ethernet :arp nil :ipv4 nil :udp nil :dns nil)))
      (case (getf ethernet :ether-type)
        (#x0806
         (handler-case
             (multiple-value-bind (arp next) (dissect-arp bytes :offset payload-offset)
               (declare (ignore next))
               (when (and (= (getf arp :hardware-type) 1)
                          (= (getf arp :protocol-type) #x0800)
                          (= (getf arp :hardware-length) 6)
                          (= (getf arp :protocol-length) 4))
                 (setf (getf frame :arp) arp)))
           (malformed-packet () nil)))
        (#x0800
         (%decode-ipv4-frame frame bytes payload-offset)))
      frame)))

(defun %decode-ipv4-frame (frame bytes offset)
  (handler-case
      (multiple-value-bind (ipv4 fixed-header-end)
          (dissect-ipv4 bytes :offset offset)
        (let* ((version-ihl (getf ipv4 :version-ihl))
               (version (ldb (byte 4 4) version-ihl))
               (header-length (* 4 (ldb (byte 4 0) version-ihl)))
               (total-length (getf ipv4 :total-length))
               (ip-end (+ offset total-length)))
          (unless (and (= version 4)
                       (>= header-length 20)
                       (>= total-length header-length)
                       (<= ip-end (length bytes)))
            (error 'malformed-packet
                   :offset offset
                   :required (max header-length total-length)
                   :available (- (length bytes) offset)))
          (setf (getf frame :ipv4) ipv4)
          (when (and (= (getf ipv4 :protocol) 17)
                     (zerop (logand (getf ipv4 :flags-fragment-offset) #x1fff)))
            (%decode-udp-frame frame bytes (+ offset header-length) ip-end))))
    (malformed-packet () nil)))

(defun %decode-udp-frame (frame bytes offset end)
  (handler-case
      (multiple-value-bind (udp payload-offset)
          (dissect-udp bytes :offset offset :end end)
        (let ((udp-end (+ offset (getf udp :length))))
          (unless (and (>= (getf udp :length) 8) (<= udp-end end))
            (error 'malformed-packet
                   :offset offset
                   :required (getf udp :length)
                   :available (- end offset)))
          (setf (getf frame :udp) udp)
          (when (and (> (getf udp :length) 8)
                     (or (= (getf udp :source-port) 53)
                         (= (getf udp :destination-port) 53)))
            (handler-case
                (setf (getf frame :dns)
                      (dissect-dns bytes :offset payload-offset :end udp-end))
              (malformed-packet () nil)))))
    (malformed-packet () nil)))
