(in-package #:nrecon.net)

(defun %usable-ipv4-address-p (address)
  (when (and (stringp address)
             (not (member address '("0.0.0.0" "255.255.255.255")
                           :test #'string=)))
    (let ((separator (position #\. address)))
      (and separator
           (< (parse-integer address :end separator) 224)))))

(defun %usable-mac-address-p (address)
  (when (and (stringp address) (= (length address) 17))
    (let ((first-octet (parse-integer address :end 2 :radix 16)))
      (and (zerop (logand first-octet 1))
           (not (string= address "00:00:00:00:00:00"))))))

(defun %observe-host (index ip-address mac-address name protocol)
  (let* ((ip-address (and (%usable-ipv4-address-p ip-address) ip-address))
         (mac-address (and (%usable-mac-address-p mac-address) mac-address))
         (ip-key (and ip-address (list :ip ip-address)))
         (mac-key (and mac-address (list :mac mac-address))))
    (labels ((merge-host-record (host other)
               (dolist (address (network-host-ip-addresses other))
                 (pushnew address (network-host-ip-addresses host) :test (function string=)))
               (dolist (address (network-host-mac-addresses other))
                 (pushnew address (network-host-mac-addresses host) :test (function string=)))
               (dolist (host-name (network-host-names other))
                 (pushnew host-name (network-host-names host) :test (function string=)))
               (dolist (observed-protocol (network-host-protocols other))
                 (pushnew observed-protocol (network-host-protocols host) :test (function eq))))
             (repoint-host-keys (old host)
               (let ((keys nil))
                 (maphash (lambda (key value)
                            (when (eq value old)
                              (push key keys)))
                          index)
                 (dolist (key keys)
                   (setf (gethash key index) host)))))
      (when (or ip-key mac-key)
        (let* ((ip-host (and ip-key (gethash ip-key index)))
               (mac-host (and mac-key (gethash mac-key index)))
               (host (or ip-host mac-host)))
          (when (and ip-host mac-host (not (eq ip-host mac-host)))
            (merge-host-record host mac-host)
            (repoint-host-keys mac-host host))
          (unless host
            (setf host (%make-network-host)))
          (when ip-key
            (setf (gethash ip-key index) host
                  (network-host-ip-addresses host)
                  (adjoin ip-address (network-host-ip-addresses host)
                          :test (function string=))))
          (when mac-key
            (setf (gethash mac-key index) host
                  (network-host-mac-addresses host)
                  (adjoin mac-address (network-host-mac-addresses host)
                          :test (function string=))))
          (when (and name ip-address)
            (pushnew name (network-host-names host) :test (function string=)))
          (when protocol
            (pushnew protocol (network-host-protocols host) :test (function eq)))
          host)))))

(defun %observe-frame (index frame)
  (let* ((ethernet (getf frame :ethernet))
         (source-mac (getf ethernet :source-mac))
         (destination-mac (getf ethernet :destination-mac))
         (arp (getf frame :arp))
         (ipv4 (getf frame :ipv4)))
    (cond
      (arp
       (%observe-host index
                      (getf arp :sender-protocol-address)
                      (getf arp :sender-hardware-address)
                      nil :arp)
       (%observe-host index
                      (getf arp :target-protocol-address)
                      (getf arp :target-hardware-address)
                      nil :arp))
      (ipv4
       (%observe-host index (getf ipv4 :source-address) source-mac nil :ipv4)
       (%observe-host index (getf ipv4 :destination-address)
                      destination-mac nil :ipv4)
       (dolist (answer (getf (getf frame :dns) :answers))
         (when (= (getf answer :type) 1)
           (%observe-host index (getf answer :data) nil
                          (getf answer :name) :dns))))
      (t
       (%observe-host index nil source-mac nil :ethernet)
       (%observe-host index nil destination-mac nil :ethernet)))))

(defun discover-hosts (packets)
  (check-type packets list)
  (let ((index (make-hash-table :test #'equal)))
    (dolist (bytes packets)
      (check-type bytes (vector (unsigned-byte 8)))
      (handler-case
          (%observe-frame index (decode-frame bytes))
        (malformed-packet () nil)))
    (sort (remove-duplicates (loop for host being the hash-values of index
                                   collect host)
                             :test #'eq)
          #'string<
          :key (lambda (host)
                 (or (first (network-host-ip-addresses host))
                     (first (network-host-mac-addresses host)))))))

(defun discovered-ip-addresses (hosts)
  (sort (remove-duplicates
         (loop for host in hosts
               append (copy-list (network-host-ip-addresses host)))
         :test #'string=)
        #'string<))
