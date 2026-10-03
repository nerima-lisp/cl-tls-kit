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
    (check (hostname-match-p "127.0.0.1"
                             (list (list :ip #(127 0 0 1))))
           "IPv4 hostname matches an IP SAN")
    (check (hostname-match-p "2001:db8::1"
                             (list (list :ip
                                         #(32 1 13 184 0 0 0 0 0 0 0 0 0 0 0 1))))
           "IPv6 hostname matches an IP SAN")
    (check (not (hostname-match-p "127.0.0.1"
                                  '((:dns "127.0.0.1"))))
           "IP hostnames do not match DNS SANs")
    (check (handler-case
               (progn (cl-tls-kit.x509::%read-der #(48)) nil)
             (cl-tls-kit.x509:x509-error () t))
           "truncated X.509 DER has a domain error")
    (check (handler-case
               (progn (cl-tls-kit.x509::%read-der #(48 129 127)) nil)
             (cl-tls-kit.x509:x509-error () t))
           "non-minimal DER length is rejected")
    (check (handler-case
               (progn (cl-tls-kit.x509::%read-der #(48 131 16 0 1)) nil)
             (cl-tls-kit.x509:x509-error () t))
           "oversized DER length is rejected")
    (check (handler-case
               (let ((bytes #(5 0)))
                 (dotimes (i 40)
                   (setf bytes (concatenate '(vector (unsigned-byte 8))
                                            (vector 48 (length bytes)) bytes)))
                 (multiple-value-bind (root ignored)
                     (cl-tls-kit.x509::%read-der bytes)
                   (declare (ignore ignored))
                   (cl-tls-kit.x509::%children root))
                 nil)
             (cl-tls-kit.x509:x509-error () t))
           "DER nesting depth is bounded")
    (check (handler-case
               (progn (cl-tls-kit.x509::%read-der #(31 1 0)) nil)
             (cl-tls-kit.x509:x509-error () t))
           "unsupported high-tag DER is rejected")
    (check (handler-case
               (progn (cl-tls-kit.x509::%pem-octets
                       "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----") nil)
             (cl-tls-kit.x509:x509-error () t))
           "invalid PEM base64 is rejected")
    (check (handler-case
               (progn (verify-certificate-chain (make-list 17)) nil)
             (invalid-certificate-chain () t))
           "certificate chain count is bounded")
    (check (handler-case
               (progn
                 (verify-certificate-chain
                  (list (list :tbs-certificate
                              (make-array (1+ (* 4 1024 1024))
                                          :element-type '(unsigned-byte 8)))))
                 nil)
             (invalid-certificate-chain () t))
           "certificate chain byte size is bounded")
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
    (let ((now (get-universal-time)))
      (let* ((leaf (list :issuer "intermediate" :subject "leaf"
                       :not-before 0 :not-after (1+ now)
                       :signature-algorithm :rsa-pkcs1-sha256))
           (intermediate (list :issuer "root" :subject "intermediate"
                               :not-before 0 :not-after (1+ now)
                               :signature-algorithm :rsa-pkcs1-sha256
                               :basic-constraints '(:ca t)))
           (root (list :subject "root" :not-before 0 :not-after (1+ now)
                       :self-signed t
                       :basic-constraints '(:ca t :path-length 0)))
             (chain (list leaf intermediate root)))
        (check (handler-case
                 (progn
                   (verify-certificate-chain
                    chain :trust-anchors (list root)
                    :verify-signature (lambda (&rest arguments)
                                        (declare (ignore arguments)) t))
                   nil)
               (path-length-exceeded () t)
               (condition () nil))
               "pathLen counts subordinate CA certificates")
        (setf (getf (getf root :basic-constraints) :path-length) 1)
        (check (verify-certificate-chain
                chain :trust-anchors (list root)
                :verify-signature (lambda (&rest arguments)
                                    (declare (ignore arguments)) t))
               "pathLen permits the configured subordinate CA depth")))
    (let* ((leaf (list :issuer "root" :subject "leaf"
                       :not-before 0 :not-after (1+ (get-universal-time))
                       :signature-algorithm :rsa-pkcs1-sha256
                       :subject-alternative-names '((:dns "outside.example"))))
           (root (list :subject "root" :self-signed t
                       :not-before 0 :not-after (1+ (get-universal-time))
                       :basic-constraints '(:ca t)
                       :name-constraints
                       '(:permitted-subtrees ((:dns "allowed.example")))))
           (chain (list leaf root)))
      (check (handler-case
                 (progn
                   (verify-certificate-chain
                    chain :trust-anchors (list root)
                    :verify-signature (lambda (&rest arguments)
                                        (declare (ignore arguments)) t))
                   nil)
               (invalid-certificate-chain () t)
               (condition () nil))
             "ancestor name constraints reject an invalid leaf")
      (setf (getf leaf :subject-alternative-names)
            '((:dns "allowed.example")))
      (check (verify-certificate-chain
              chain :trust-anchors (list root)
              :verify-signature (lambda (&rest arguments)
                                  (declare (ignore arguments)) t))
             "ancestor name constraints permit a valid leaf"))
    (let* ((leaf (list :issuer "root" :subject "leaf"
                       :not-before 0 :not-after (1+ (get-universal-time))
                       :subject-alternative-names '((:uri "https://outside.example"))))
           (root (list :subject "root" :self-signed t
                       :not-before 0 :not-after (1+ (get-universal-time))
                       :basic-constraints '(:ca t)
                       :name-constraints '(:critical t
                                           :permitted-subtrees ((:dns "allowed.example")))))
           (chain (list leaf root)))
      (check (handler-case
                 (progn
                   (verify-certificate-chain
                    chain :trust-anchors (list root)
                    :verify-signature (lambda (&rest arguments)
                                        (declare (ignore arguments)) t))
                   nil)
               (invalid-certificate-chain () t))
             "critical name constraints reject unsupported SAN types"))
    (let* ((now (get-universal-time))
           (leaf (cl-tls-kit.x509::make-x509-certificate
                  :issuer "root" :subject "leaf"
                  :not-before 0 :not-after (1+ now)
                  :signature-algorithm :rsa-pkcs1-sha256
                  :tbs-signature-algorithm :ecdsa-p256-sha256
                  :tbs-certificate #(1) :signature #(2)))
           (root (list :subject "root" :self-signed t
                       :not-before 0 :not-after (1+ now)
                       :basic-constraints '(:ca t))))
      (check (handler-case
                 (progn
                   (verify-certificate-chain
                    (list leaf root) :trust-anchors (list root)
                    :verify-signature (lambda (&rest arguments)
                                        (declare (ignore arguments)) t))
                   nil)
               (bad-signature () t))
             "TBSCertificate signature algorithm must match outer algorithm"))
    (let* ((leaf (list :issuer "root" :subject "leaf"
                       :not-before 0 :not-after (1+ (get-universal-time))
                       :signature-algorithm :rsa-pkcs1-sha256
                       :key-usage '(:key-encipherment)
                       :subject-alternative-names '((:dns "example.test"))))
           (root (list :subject "root" :self-signed t
                       :not-before 0 :not-after (1+ (get-universal-time))
                       :basic-constraints '(:ca t)))
           (chain (list leaf root)))
      (check (handler-case
                 (progn
                   (verify-certificate-chain
                    chain :hostname "example.test" :trust-anchors (list root)
                    :verify-signature (lambda (&rest arguments)
                                        (declare (ignore arguments)) t))
                   nil)
               (invalid-key-usage () t)
               (condition () nil))
             "leaf key usage requires digitalSignature for TLS server authentication"))
    t))
