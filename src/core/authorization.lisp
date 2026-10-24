(in-package #:nrecon.core)

(defstruct (authorization-policy
            (:constructor %make-authorization-policy (&key actions allowlist lab-only-p)))
  actions
  allowlist
  (lab-only-p t))

(defun make-authorization-policy (&key actions allowlist (lab-only-p t))
  (%make-authorization-policy :actions (copy-tree actions)
                              :allowlist (copy-tree allowlist)
                              :lab-only-p (not (null lab-only-p))))

(defstruct (authorization-target
            (:constructor %make-authorization-target (&key host lab-p)))
  host
  lab-p)

(defun make-authorization-target (&key host (lab-p nil))
  (%make-authorization-target :host (if (stringp host) (copy-seq host) host)
                              :lab-p (not (null lab-p))))

(defstruct (authorization-decision
            (:constructor %make-authorization-decision (&key allowed-p reason action)))
  allowed-p
  reason
  action)

(defun %split-on-character (string separator)
  (loop with start = 0
        for end = (position separator string :start start)
        collect (subseq string start end)
        while end
        do (setf start (1+ end))))

(defun %ascii-digit-p (character)
  (<= 48 (char-code character) 57))

(defun %parse-decimal (string)
  (when (and (plusp (length string))
             (every #'%ascii-digit-p string))
    (parse-integer string :radix 10 :junk-allowed nil)))

(defun %parse-ipv4 (host)
  (when (stringp host)
    (let ((parts (%split-on-character host (code-char 46))))
      (when (and (= (length parts) 4)
                 (every (lambda (part)
                          (let ((octet (%parse-decimal part)))
                            (and octet (<= 0 octet 255))))
                        parts))
        (loop with address = 0
              for part in parts
              for shift in '(24 16 8 0)
              do (setf address
                       (logior address
                               (ash (%parse-decimal part) shift)))
              finally (return address))))))

(defun %ipv4-mask (prefix)
  (logand #xffffffff (ash #xffffffff (- 32 prefix))))

(defun %parse-ipv4-cidr (entry)
  (when (stringp entry)
    (let ((parts (%split-on-character entry (code-char 47))))
      (when (= (length parts) 2)
        (let ((address (%parse-ipv4 (first parts)))
              (prefix (%parse-decimal (second parts))))
          (when (and address prefix (<= 0 prefix 32))
            (let ((mask (%ipv4-mask prefix)))
              (values (logand address mask) mask t))))))))

(defun %normalize-host (host)
  (when (stringp host)
    (let ((normalized (string-downcase host)))
      (if (and (plusp (length normalized))
               (char= (char normalized (1- (length normalized)))
                      (code-char 46)))
          (subseq normalized 0 (1- (length normalized)))
          normalized))))

(defun %valid-domain-label-p (label)
  (and (<= 1 (length label) 63)
       (not (char= (char label 0) (code-char 45)))
       (not (char= (char label (1- (length label))) (code-char 45)))
       (every (lambda (character)
                (let ((code (char-code character)))
                  (or (<= 48 code 57)
                      (<= 97 code 122)
                      (= code 45))))
              label)))

(defun %valid-domain-p (host)
  (and host
       (<= 1 (length host) 253)
       (not (%parse-ipv4 host))
       (every #'%valid-domain-label-p
              (%split-on-character host (code-char 46)))))

(defun %domain-allows-host-p (domain host)
  (let ((domain-length (length domain))
        (host-length (length host)))
    (or (string= domain host)
        (and (> host-length domain-length)
             (let ((suffix-start (- host-length domain-length)))
               (and (char= (char host (1- suffix-start)) (code-char 46))
                    (string= domain host
                             :start2 suffix-start
                             :end2 host-length)))))))

(defun %allowlist-entry-matches-p (entry host)
  (multiple-value-bind (network mask cidr-p)
      (%parse-ipv4-cidr entry)
    (cond
      (cidr-p
       (let ((address (%parse-ipv4 host)))
         (and address (= (logand address mask) network))))
      ((and (stringp entry) (find (code-char 47) entry))
       nil)
      (t
       (let* ((normalized-entry (%normalize-host entry))
              (normalized-host (%normalize-host host))
              (entry-ip (%parse-ipv4 normalized-entry))
              (host-ip (%parse-ipv4 normalized-host)))
         (cond
           ((and entry-ip host-ip) (= entry-ip host-ip))
           ((or entry-ip host-ip) nil)
           ((and (%valid-domain-p normalized-entry)
                 (%valid-domain-p normalized-host))
            (%domain-allows-host-p normalized-entry normalized-host))
           (t nil)))))))

(defun %action-name (action)
  (etypecase action
    (string (string-downcase action))
    (symbol (string-downcase (symbol-name action)))))

(defun %authorization-result (allowed-p reason action)
  (%make-authorization-decision :allowed-p allowed-p
                                :reason reason
                                :action action))

(defun authorize-action (policy action target)
  (check-type policy authorization-policy)
  (unless (or (symbolp action) (stringp action))
    (error "Authorization action must be a symbol or string, got ~S." action))
  (cond
    ((null (authorization-policy-allowlist policy))
     (%authorization-result nil :empty-allowlist action))
    ((not (member (%action-name action)
                  (authorization-policy-actions policy)
                  :test (lambda (name allowed)
                          (and (or (symbolp allowed) (stringp allowed))
                               (string= name (%action-name allowed))))))
     (%authorization-result nil :action-out-of-scope action))
    ((not (authorization-target-p target))
     (%authorization-result nil :target-required action))
    ((not (or (%parse-ipv4 (authorization-target-host target))
              (%valid-domain-p (%normalize-host
                                (authorization-target-host target)))))
     (%authorization-result nil :invalid-target action))
    ((and (authorization-policy-lab-only-p policy)
          (not (authorization-target-lab-p target)))
     (%authorization-result nil :target-not-lab action))
    ((not (some (lambda (entry)
                  (%allowlist-entry-matches-p
                   entry
                   (authorization-target-host target)))
                (authorization-policy-allowlist policy)))
     (%authorization-result nil :target-not-allowlisted action))
    (t (%authorization-result t :allowed action))))
