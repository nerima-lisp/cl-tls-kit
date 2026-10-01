(in-package #:cl-tls-kit/test)

(defun run-tests ()
  (unless (and (run-basic-tests)
               (run-record-tests)
               (run-handshake-tests)
               (run-client-tests))
    (error "cl-tls-kit tests failed."))
  t)
