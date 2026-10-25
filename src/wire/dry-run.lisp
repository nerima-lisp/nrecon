(in-package #:nrecon.wire)

(defun %action-name (action)
  (etypecase action
    (string (string-downcase action))
    (symbol (string-downcase (symbol-name action)))))

(defun %authorization-json (decision)
  (let ((object (make-hash-table :test #'equal)))
    (setf (gethash "action" object)
          (%action-name (authorization-decision-action decision))
          (gethash "allowed" object)
          (if (authorization-decision-allowed-p decision)
              t
              json-kit:+json-false+)
          (gethash "reason" object)
          (%json-value (authorization-decision-reason decision)))
    object))

(defun plan-job (module-name job
                 &key authorization-policy (target-lab-p nil))
  (check-type job job)
  (when authorization-policy
    (check-type authorization-policy authorization-policy))
  (let* ((module (find-module module-name))
         (policy (or authorization-policy
                     (make-authorization-policy :actions nil :allowlist nil)))
         (target (make-authorization-target :host (job-target job)
                                            :lab-p target-lab-p)))
    (unless module
      (error "No nrecon module is registered as ~A." module-name))
    (let* ((capabilities (module-capabilities module))
           (decisions (mapcar (lambda (action)
                                (authorize-action policy action target))
                              capabilities))
           (authorized (and (consp capabilities)
                            (every #'authorization-decision-allowed-p
                                   decisions)))
           (plan (make-hash-table :test #'equal)))
      (setf (gethash "actions" plan)
            (coerce (mapcar #'%authorization-json decisions) 'vector)
            (gethash "authorized" plan)
            (if authorized t json-kit:+json-false+)
            (gethash "dry_run" plan) t
            (gethash "job_id" plan) (%json-value (job-id job))
            (gethash "module" plan) (module-name module)
            (gethash "target" plan) (%json-value (job-target job)))
      plan)))

(defun render-plan (module-name job
                    &key authorization-policy (target-lab-p nil))
  (json-kit:stringify
   (plan-job module-name job
             :authorization-policy authorization-policy
             :target-lab-p target-lab-p)
   :sort-keys t))
