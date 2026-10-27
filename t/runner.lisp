(in-package #:cl-tls-kit/test)

(defun run-tests ()
  (let ((passed 0))
    (when (find-package (quote #:crypto-kit))
      (unless (eq (run-key-schedule-tests) t)
        (error "cl-tls-kit key schedule tests did not pass."))
      (incf passed))
    (dolist (test '(run-basic-tests run-test-support-tests
                    run-path-building-tests
                    run-trust-store-tests
                    run-record-tests
                    run-handshake-tests
                    run-client-tests
                    run-client-driver-tests
                    run-client-resumption-tests
                    run-client-resumption-security-tests
                    run-server-driver-tests
                    run-server-driver-close-tests
                    run-verification-tests
                    run-quic-boundary-tests
                    run-openssl-e2e-tests
                    run-server-openssl-e2e-tests
                    run-openssl-chain-tests
                    run-pss-signature-tests
                    run-pss-parameters-tests))
      (let ((result (funcall test)))
        (unless (member result (quote (t :skipped)))
          (error "cl-tls-kit test group failed: ~A" test))
        (when (eq result t)
          (incf passed))))
    (let ((client-result (run-rfc8448-tests)))
      (when (eq client-result t)
        (incf passed))
      (let ((server-result (run-rfc8448-server-trace-tests)))
        (when (eq server-result t)
          (incf passed))
        (format t "cl-tls-kit tests: ~D groups passed; RFC 8448 client: ~A; RFC 8448 server trace: ~A~%"
                passed client-result server-result)))
    (unless (plusp passed)
      (error "cl-tls-kit tests ran zero groups."))
    t))
