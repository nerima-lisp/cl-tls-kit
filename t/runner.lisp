(in-package #:cl-tls-kit/test)

(defun run-tests ()
  (unless (cl-tls-kit/test::run-basic-tests) (error "cl-tls-kit tests failed."))
  t)
