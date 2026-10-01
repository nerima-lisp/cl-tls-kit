(in-package #:cl-tls-kit/test)

(defun check (condition message)
  (unless condition (error "Test failed: ~A" message)))

(defun run-basic-tests ()
  (let* ((integer (make-der-integer 127))
         (sequence (make-der-sequence integer (make-der-null)))
         (encoded (der-encode sequence))
         (decoded (der-decode encoded))
         (pem (pem-encode (make-pem-block :label "TEST" :der encoded))))
    (check (equalp encoded #(48 5 2 1 127 5 0)) "DER sequence")
    (check (= (der-integer-value (first (der-node-children decoded))) 127) "INTEGER round trip")
    (check (equalp (pem-block-der (first (pem-decode pem))) encoded) "PEM round trip")
    (check (handler-case (progn (der-decode #(2 2 0 1)) nil)
      (der-error () t)
      (condition () nil)) "reject non-minimal INTEGER")
    (check (hostname-match-p "www.example.test"
                             '((:dns "*.example.test")))
           "left-most wildcard")
    (check (not (hostname-match-p "deep.www.example.test"
                                  '((:dns "*.example.test"))))
           "wildcard must match one label")
    (check (not (hostname-match-p "example.test" nil))
           "CN fallback is disabled")
    (let ((now (get-universal-time)))
      (check (handler-case
                 (progn
                   (verify-certificate-chain
                    (list (list :not-before 0 :not-after (1- now)
                                :self-signed t)))
                   nil)
               (certificate-expired () t)
               (condition () nil))
             "expired certificate condition")
      (check (handler-case
                 (progn
                   (verify-certificate-chain
                    (list (list :not-before 0 :not-after (1+ now)
                                :self-signed t)))
                   nil)
               (self-signed-certificate () t)
               (condition () nil))
             "self-signed condition"))
    t))
