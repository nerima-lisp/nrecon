(in-package #:nrecon.fuzz)

(defstruct
    (request-template
     (:constructor %make-request-template
                   (&key method uri host headers body lab-p)))
  method
  uri
  host
  headers
  body
  lab-p)

(defstruct
    (fuzz-request
     (:constructor %make-fuzz-request
                   (&key method uri host headers body word-values depth)))
  method
  uri
  host
  headers
  body
  word-values
  depth)

(defstruct
    (fuzz-response
     (:constructor %make-fuzz-response
                   (&key status headers body size words lines)))
  status
  headers
  body
  size
  words
  lines)

(defstruct
    (fuzz-result
     (:constructor %make-fuzz-result (&key request response depth matched-p)))
  request
  response
  depth
  matched-p)
