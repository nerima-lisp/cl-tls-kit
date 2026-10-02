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
    (let ((oid (make-der-oid '(2 999 3 128))))
      (check (equal '(2 999 3 128) (der-oid-value oid)) "multi-octet OID round trip"))
    (check (handler-case (progn (pem-decode "-----BEGIN TEST-----\n///=\n-----END TEST-----") nil)
             (pem-error () t)
             (condition () nil)) "reject non-zero Base64 pad bits")
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
    (dolist (tail '(#(68 79 87 78 71 82 68 0)
                    #(68 79 87 78 71 82 68 1)))
      (let ((random (concatenate '(vector (unsigned-byte 8))
                                 #(0 0 0 0 0 0 0 0) tail)))
        (check (handler-case
                   (progn
                     (tls-client-check-server-random
                      (make-tls-client) random :version :tls-1.3)
                     nil)
                 (tls12-downgrade-sentinel (condition)
                   (eq (cl-tls-kit::tls12-downgrade-version condition)
                       :tls-1.3))
                 (condition () nil))
               "TLS 1.3 rejects TLS 1.2/1.1 downgrade sentinel")))
    (check (hostname-match-p "WWW.EXAMPLE.TEST."
                             '((:dns "www.example.test")))
           "DNS trailing dot is normalized")
    (check (handler-case
               (progn (cl-tls-kit.x509::%read-der #(48)) nil)
             (cl-tls-kit.x509:x509-error () t))
           "truncated X.509 DER has a domain error")
    (let ((utc (cl-tls-kit.x509::make-der
                :tag #x17 :content (map 'vector #'char-code "991231235959Z"))))
      (check (= (cl-tls-kit.x509::%time utc)
                (encode-universal-time 59 59 23 31 12 1999 0))
             "UTCTime uses the RFC 5280 1950-2049 window"))
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
