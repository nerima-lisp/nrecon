(in-package #:nrecon.net)

(define-condition malformed-packet (error)
  ((offset :initarg :offset :reader malformed-packet-offset)
   (required :initarg :required :reader malformed-packet-required)
   (available :initarg :available :reader malformed-packet-available))
  (:report (lambda (condition stream)
             (format stream
                     "Malformed packet at byte ~D: requires ~D bytes, ~D available."
                     (malformed-packet-offset condition)
                     (malformed-packet-required condition)
                     (malformed-packet-available condition)))))

(defun %check-dissector-input (bytes offset end)
  (unless (typep bytes '(vector (unsigned-byte 8)))
    (error "Packet bytes must be an octet vector, got ~S." (type-of bytes)))
  (check-type offset (integer 0 *))
  (check-type end (integer 0 *))
  (unless (<= offset end (length bytes))
    (error "Packet byte range ~D..~D is outside a ~D-byte vector."
           offset end (length bytes)))
  bytes)

(defun %require-bytes (bytes offset end count)
  (unless (<= count (- end offset))
    (error 'malformed-packet
           :offset offset
           :required count
           :available (max 0 (- end offset))))
  offset)

(defun %decode-unsigned (bytes offset end width)
  (%require-bytes bytes offset end width)
  (values (loop with value = 0
                for index from offset below (+ offset width)
                do (setf value (logior (ash value 8) (aref bytes index)))
                finally (return value))
          (+ offset width)))

(defun %decode-mac-address (bytes offset end)
  (%require-bytes bytes offset end 6)
  (values (with-output-to-string (stream)
            (loop for index from offset below (+ offset 6)
                  do (when (> index offset)
                       (write-char #\: stream))
                     (format stream "~(~2,'0X~)" (aref bytes index))))
          (+ offset 6)))

(defun %decode-ipv4-address (bytes offset end)
  (%require-bytes bytes offset end 4)
  (values (format nil "~D.~D.~D.~D"
                  (aref bytes offset)
                  (aref bytes (+ offset 1))
                  (aref bytes (+ offset 2))
                  (aref bytes (+ offset 3)))
          (+ offset 4)))

(defun %decode-field (bytes offset end type)
  (case type
    (:u8 (%decode-unsigned bytes offset end 1))
    (:u16 (%decode-unsigned bytes offset end 2))
    (:u32 (%decode-unsigned bytes offset end 4))
    (:mac (%decode-mac-address bytes offset end))
    (:ipv4 (%decode-ipv4-address bytes offset end))
    (otherwise (error "Unsupported dissector field type: ~S." type))))

(defmacro define-dissector (name fields)
  (unless (symbolp name)
    (error "Dissector names must be symbols, got ~S." name))
  (unless (and (listp fields)
               (every (lambda (field)
                        (and (listp field)
                             (= (length field) 2)
                             (symbolp (first field))
                             (member (second field)
                                     '(:u8 :u16 :u32 :mac :ipv4)
                                     :test #'eq)))
                      fields))
    (error "Dissector fields must be (name :u8|:u16|:u32|:mac|:ipv4) forms."))
  (let* ((field-names (mapcar #'first fields))
         (function-name
           (intern (concatenate 'string "DISSECT-" (symbol-name name))
                   (symbol-package name))))
    (unless (= (length field-names)
               (length (remove-duplicates field-names :test #'eq)))
      (error "Dissector field names must be unique."))
    `(defun ,function-name (bytes &key (offset 0) (end (length bytes)))
       (%check-dissector-input bytes offset end)
       (let ((position offset)
             ,@(mapcar (lambda (field) `(,field nil)) field-names))
         ,@(mapcar
            (lambda (field)
              `(multiple-value-bind (value next-position)
                   (%decode-field bytes position end ',(second field))
                 (setf ,(first field) value
                       position next-position)))
            fields)
         (values (list
                  ,@(mapcan (lambda (field)
                              (list (intern (symbol-name (first field)) :keyword)
                                    (first field)))
                            fields))
                 position)))))
