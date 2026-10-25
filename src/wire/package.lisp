(defpackage #:nrecon.wire
  (:use #:cl)
  (:import-from #:nrecon.core
   #:authorization-decision-action
   #:authorization-decision-allowed-p
   #:authorization-decision-reason
   #:authorization-policy
   #:authorize-action
   #:find-module
   #:job
   #:job-id
   #:job-options
   #:job-target
   #:list-modules
   #:make-authorization-policy
   #:make-authorization-target
   #:make-job
   #:make-result
   #:module-capabilities
   #:module-name
   #:module-options
   #:module-run
   #:result
   #:result-job-id
   #:result-metadata
   #:result-status
   #:result-value)
  (:export
   #:*mcp-timeout*
   #:describe-manifest
   #:handle-mcp-request
   #:plan-job
   #:render-plan
   #:render-results
   #:write-results))
