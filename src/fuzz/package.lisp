(defpackage #:nrecon.fuzz
            (:use #:cl)
            (:import-from #:nrecon.core #:define-module)
            (:export #:request-template
                     #:make-request-template
                     #:request-template-method
                     #:request-template-uri
                     #:request-template-host
                     #:request-template-headers
                     #:request-template-body
                     #:request-template-lab-p
                     #:fuzz-request
                     #:fuzz-request-method
                     #:fuzz-request-uri
                     #:fuzz-request-host
                     #:fuzz-request-headers
                     #:fuzz-request-body
                     #:fuzz-request-word-values
                     #:fuzz-request-depth
                     #:fuzz-response
                     #:fuzz-response-status
                     #:fuzz-response-headers
                     #:fuzz-response-body
                     #:fuzz-response-size
                     #:fuzz-response-words
                     #:fuzz-response-lines
                     #:fuzz-result
                     #:fuzz-result-request
                     #:fuzz-result-response
                     #:fuzz-result-depth
                     #:fuzz-result-matched-p
                     #:read-wordlist-file
                     #:read-wordlist-stream
                     #:wordlist-from-generator
                     #:define-matcher
                     #:define-filter
                     #:run-fuzz))
