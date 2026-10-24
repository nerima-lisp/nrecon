(in-package #:nrecon.core)

(defstruct (module (:constructor %make-module (&key name capabilities options run)))
  name
  capabilities
  options
  run)

(defun %module-key (name)
  (etypecase name
    (string (string-downcase name))
    (symbol (string-downcase (symbol-name name)))))

(defun make-module (&key name capabilities options run)
  (unless (and (or (symbolp name) (stringp name))
               (plusp (length (%module-key name))))
    (error "Module name must be a non-empty symbol or string."))
  (check-type run function)
  (%make-module :name (%module-key name)
                :capabilities (copy-tree capabilities)
                :options (copy-tree options)
                :run run))

(defvar *module-registry* (make-hash-table :test #'equal))

(defun %register-module (module)
  (setf (gethash (module-name module) *module-registry*) module))

(defmacro define-module (name &key capabilities options run)
  (unless (symbolp name)
    (error "DEFINE-MODULE names must be symbols, got ~S." name))
  (unless (symbolp run)
    (error "DEFINE-MODULE requires :RUN to name a function, got ~S." run))
  `(eval-when (:load-toplevel :execute)
     (%register-module
      (make-module :name ',name
                   :capabilities ',capabilities
                   :options ',options
                   :run #',run)))
)

(defun find-module (name)
  (gethash (%module-key name) *module-registry*))

(defun list-modules ()
  (sort (loop for module being the hash-values of *module-registry*
              collect module)
        #'string<
        :key #'module-name))
