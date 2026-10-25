(defpackage #:nrecon.attack
  (:use #:cl)
  (:import-from #:nrecon.core
   #:authorization-decision-allowed-p
   #:authorization-decision-reason
   #:authorization-target
   #:authorize-action
   #:define-module
   #:make-authorization-policy
   #:make-authorization-target
   #:job
   #:job-options)
  (:export
   #:build-arp-reply
   #:build-dns-response-frame
   #:rewrite-l2-frame
   #:attack-authorization-denied
   #:attack-audit-failure
   #:authorize-and-send
   #:run-mitm-relay
   #:render-attack-plan
   #:run-attack))

(in-package #:nrecon.attack)
