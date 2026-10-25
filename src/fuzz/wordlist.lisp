(in-package #:nrecon.fuzz)

(defun read-wordlist-file (pathname &optional
                                    (filesystem
                                     (cl-boundary-kit:make-filesystem)))
  (check-type pathname (or pathname string))
  (with-input-from-string
      (stream
       (cl-boundary-kit:filesystem-read-file filesystem
                                             pathname
                                             :external-format
                                             :utf-8))
    (read-wordlist-stream stream)))

(defun read-wordlist-stream (stream)
  (check-type stream (satisfies input-stream-p))
  (loop for word = (read-line stream nil nil)
        while word
        collect (if (and (plusp (length word))
                         (char= (char word (1- (length word))) #\Return))
                    (subseq word 0 (1- (length word)))
                    word)))

(defun wordlist-from-generator (generator)
  (check-type generator function)
  (loop with words = nil
        do (multiple-value-bind (word present-p) (funcall generator)
             (unless present-p
               (return (nreverse words)))
             (check-type word string)
             (push (copy-seq word) words))))
