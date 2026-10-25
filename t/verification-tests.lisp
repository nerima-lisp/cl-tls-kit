(in-package #:cl-tls-kit/test)

(unless (fboundp 'check)
  (defun check (condition message)
    (unless condition (error "Verification test failed: ~A" message))))

(defun run-verification-tests ()
  (let* ((random (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (hello (make-tls13-client-hello #x0303 random #() #( #x1301)
                                         (list (make-tls-extension 13 #(0 4 #x08 #x04 #x04 #x03)))))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xaa))
         (signature #(1 2 3))
         (calls nil))
    (check (= (length (cl-tls-kit::tls13-client-hello-signature-algorithms hello)) 2)
           "signature_algorithms is decoded")
    (check (equalp (cl-tls-kit::tls13-certificate-verify-signature-input :server hash)
                   (concatenate '(vector (unsigned-byte 8))
                                (make-array 64 :element-type '(unsigned-byte 8)
                                            :initial-element #x20)
                                #(84 76 83 32 49 46 51 44 32 115 101 114 118 101 114
                                  32 67 101 114 116 105 102 105 99 97 116 101 86 101
                                  114 105 102 121)
                                #(0)
                                hash))
           "CertificateVerify input is RFC 8446 context plus transcript hash")
    (let ((signed-input (cl-tls-kit::tls13-certificate-verify-signature-input :server hash)))
      (check (= (aref signed-input (+ 64 (length "TLS 1.3, server CertificateVerify"))) 0)
             "CertificateVerify input includes the zero separator"))
    (check (handler-case
               (progn (cl-tls-kit::tls13-validate-certificate-verify-algorithm hello #x0807) nil)
             (cl-tls-kit::tls13-signature-scheme-not-offered () t))
           "unoffered scheme has a reason-specific condition")
    (unless (find-package '#:crypto-kit)
      (check (handler-case
                 (progn (cl-tls-kit::tls13-verify-certificate-verify
                         hello :server :key #x0804 signature hash nil)
                        nil)
               (cl-tls-kit::tls13-verification-provider-error (condition)
                 (eq (cl-tls-kit::tls13-verification-error-reason condition)
                     :missing-verify-signature)))
             "missing provider is rejected at the boundary"))
    (check (handler-case
               (progn (cl-tls-kit::tls13-verify-certificate-verify
                       hello :server :key #x0804 #() hash nil)
                      nil)
             (cl-tls-kit::tls13-invalid-verification-input () t))
           "empty CertificateVerify signature is rejected before provider use")
    (check (cl-tls-kit::tls13-verify-certificate-verify
            hello :server :key #x0804 signature hash
            (lambda (key scheme input received)
              (push (list key scheme input received) calls)
              t))
           "provider boundary accepts a valid mock result")
    (check (= (length calls) 1) "provider is called once")
    (check (equalp (third (first calls))
                   (cl-tls-kit::tls13-certificate-verify-signature-input :server hash))
           "provider receives the exact CertificateVerify input")
    (check (cl-tls-kit::tls13-verify-finished #(1 2 3) #(1 2 3))
           "matching Finished data succeeds")
    (check (handler-case (progn (cl-tls-kit::tls13-verify-finished #(1 2 3) #(1 2 4)) nil)
             (cl-tls-kit::tls13-finished-mismatch () t))
           "mismatching Finished data has a reason-specific condition")
    (unless (find-package '#:crypto-kit)
      (error "ECDSA CertificateVerify tests require cl-crypto-kit"))
    (let* ((crypto-package (find-package "CRYPTO-KIT"))
           (make-ec-public-key (symbol-function (find-symbol "MAKE-EC-PUBLIC-KEY"
                                                              crypto-package)))
           (public-key
             (funcall make-ec-public-key
                      :p256
                      #(4
                        #xc4 #x53 #x48 #x3b #x62 #x5a #xc5 #x6a
                        #x78 #xcd #xbf #x36 #x8b #x30 #xff #x4a
                        #xbb #xc3 #xfa #xf2 #x4e #x5b #x09 #x5e
                        #x3b #xfe #x54 #x31 #x9f #x53 #x52 #x31
                        #x3a #xe0 #x3a #x65 #xb4 #x15 #x3b #x05
                        #x42 #xd4 #x55 #x75 #xac #xe4 #xe2 #x73
                        #xe6 #x70 #x89 #x4f #xfb #x50 #x9c #x61
                        #x1b #x91 #x37 #xa7 #x5a #x6e #x58 #x4f)))
           (real-signature
             #( #x30 #x46 #x02 #x21 #x00 #x8d #xf2 #x29 #xc8 #x1e #xce #xb0
                #x6a #x4d #x2f #x2e #x87 #x38 #xb2 #x8f #x9d #xd3 #x50 #x27
                #xb8 #x02 #xdb #x3d #x47 #x0a #x68 #x31 #xbb #x3c #xa2 #xcc
                #x21 #x02 #x21 #x00 #xff #xd7 #x5b #xe0 #x12 #xc4 #x47 #x32
                #xb0 #x88 #x18 #x99 #x68 #x89 #x3e #x5d #x33 #x00 #x16 #x7a
                #x82 #x52 #xb7 #x91 #xaf #xcd #xeb #xb7 #x07 #xce #x6b #xfd))
           (provider (cl-tls-kit:make-cl-crypto-kit-provider)))
      (check (cl-tls-kit::tls13-verify-certificate-verify
              hello :server public-key #x0403 real-signature hash provider)
             "real cl-crypto-kit provider accepts ECDSA P-256 CertificateVerify")
      (let ((tampered (copy-seq real-signature)))
        (setf (aref tampered (1- (length tampered)))
              (logxor (aref tampered (1- (length tampered))) 1))
        (check (handler-case
                   (progn (cl-tls-kit::tls13-verify-certificate-verify
                           hello :server public-key #x0403 tampered hash provider)
                          nil)
                 (cl-tls-kit::tls13-bad-signature () t))
               "real cl-crypto-kit provider rejects a tampered ECDSA signature")))
    (let* ((pss-parameters
             (cl-tls-kit.x509::make-der
              :tag #x30
              :content #( #xa0 #x0d #x30 #x0b #x06 #x09 #x60 #x86 #x48 #x01 #x65
                          #x03 #x04 #x02 #x02
                          #xa1 #x1a #x30 #x18 #x06 #x09 #x2a #x86 #x48 #x86 #xf7
                          #x0d #x01 #x01 #x08
                          #x30 #x0b #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03 #x04
                          #x02 #x02
                          #xa2 #x03 #x02 #x01 #x30
                          #xa3 #x03 #x02 #x01 #x01)
              :raw nil))
           (parsed (cl-tls-kit.x509::%pss-parameters pss-parameters)))
      (check (equal parsed
                    '(:hash :sha384 :mgf-hash :sha384 :salt-length 48
                      :trailer-field 1))
             "X.509 parses matching RSA-PSS hash and MGF parameters"))
    (let* ((algorithm "1.2.840.113549.1.1.10")
           (parameters '(:hash :sha384 :mgf-hash :sha384
                         :salt-length 48 :trailer-field 1))
           (certificate
             (cl-tls-kit.x509::make-x509-certificate
              :signature-algorithm algorithm
              :signature-parameters parameters
              :tbs-signature-algorithm algorithm
              :tbs-signature-parameters parameters)))
      (check (eq (cl-tls-kit::%signature-scheme certificate)
                 :rsa-pss-rsae-sha384)
             "RSA-PSS certificate verification selects the parsed digest scheme")
      (check (cl-tls-kit::%same-signature-algorithm-p certificate)
             "matching outer and TBSCertificate RSA-PSS parameters are accepted")
      (setf (cl-tls-kit.x509::x509-certificate-tbs-signature-parameters certificate)
            '(:hash :sha256 :mgf-hash :sha256 :salt-length 32 :trailer-field 1))
      (check (not (cl-tls-kit::%same-signature-algorithm-p certificate))
             "different outer and TBSCertificate RSA-PSS parameters are rejected"))
    (check (handler-case
               (progn
                 (cl-tls-kit::%signature-scheme
                  '(:signature-algorithm "1.2.840.113549.1.1.10"
                    :signature-parameters
                    (:hash :sha256 :mgf-hash :sha256 :salt-length 20
                     :trailer-field 1)))
                 nil)
             (bad-signature () t))
           "RSA-PSS rejects a salt length that differs from the digest length")
    (check (cl-tls-kit::%constraint-match-p
            (list :ip #(192 0 2 0 255 255 255 0))
            (list :ip #(192 0 2 17)))
           "IP name constraints accept an address followed by its mask")
    (check (not (cl-tls-kit::%constraint-match-p
                 (list :ip #(192 0 2 0))
                 (list :ip #(192 0 2 17))))
           "IP name constraints reject a mask with no address half")
    (flet ((certificate (subject issuer &key ca path-length self-signed)
               (append
                (list :subject subject :issuer issuer
                      :signature-algorithm :rsa-pkcs1-sha256
                      :tbs-certificate #() :signature #())
                (when ca
                  (list :basic-constraints
                        (append (list :ca t)
                                (when path-length
                                  (list :path-length path-length)))))
                (when self-signed (list :self-signed t))))
             (verify-chain (chain root)
               (cl-tls-kit::%verify-ordered-certificate-chain
                chain :trust-anchors (list root)
                :verify-signature
                (lambda (&rest arguments)
                  (declare (ignore arguments))
                  t))))
        (let* ((leaf (certificate "leaf" "root"))
               (self-issued (certificate "root" "root" :ca t))
               (self-issued-root (certificate "root" "root" :ca t
                                              :path-length 0 :self-signed t))
               (normal-leaf (certificate "leaf" "intermediate"))
               (normal-intermediate (certificate "intermediate" "root" :ca t))
               (normal-root (certificate "root" "root" :ca t
                                         :path-length 0 :self-signed t)))
          (check (verify-chain (list leaf self-issued self-issued-root)
                               self-issued-root)
                 "pathLen zero excludes a self-issued subordinate CA")
          (check (handler-case
                     (progn
                       (verify-chain (list normal-leaf normal-intermediate normal-root)
                                     normal-root)
                       nil)
                   (path-length-exceeded () t))
                 "pathLen zero rejects a non-self-issued subordinate CA")))
      t))
