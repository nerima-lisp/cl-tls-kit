(in-package #:cl-tls-kit/test)

(defun run-tests ()
  (let ((passed 0))
    (when (find-package '#:crypto-kit)
      (unless (eq (run-key-schedule-tests) t)
        (error "cl-tls-kit key schedule tests did not pass."))
      (incf passed))
    (dolist (test '(run-basic-tests
                    run-record-tests
                    run-handshake-tests
                    run-client-tests
                    run-client-driver-tests
                    run-verification-tests
                    run-quic-boundary-tests))
      (unless (funcall test)
        (error "cl-tls-kit test group failed: ~A" test))
      (incf passed))
    (let ((rfc8448-result (run-rfc8448-tests)))
      (when (eq rfc8448-result t)
        (incf passed))
      (format t "cl-tls-kit tests: ~D groups passed; RFC 8448 result: ~A~%"
              passed rfc8448-result))
    (unless (plusp passed)
      (error "cl-tls-kit tests ran zero groups."))
    t))
