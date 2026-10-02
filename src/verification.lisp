(in-package #:cl-tls-kit)

;;; TLS 1.3 CertificateVerify and Finished verification.  This file keeps the
;;; cryptographic operation behind a deliberately small provider boundary.

(define-condition tls13-verification-error (error)
  ((reason :initarg :reason :reader tls13-verification-error-reason)
   (message :initarg :message :reader tls13-verification-error-message))
  (:report (lambda (condition stream)
             (format stream "TLS 1.3 verification error (~A): ~A"
                     (tls13-verification-error-reason condition)
                     (tls13-verification-error-message condition)))))
(define-condition tls13-invalid-verification-input (tls13-verification-error) ())
(define-condition tls13-signature-scheme-error (tls13-verification-error) ())
(define-condition tls13-signature-scheme-not-offered (tls13-signature-scheme-error) ())
(define-condition tls13-signature-algorithm-mismatch (tls13-signature-scheme-error) ())
(define-condition tls13-verification-provider-error (tls13-verification-error) ())
(define-condition tls13-bad-signature (tls13-verification-error) ())
(define-condition tls13-finished-mismatch (tls13-verification-error) ())

(defparameter *tls13-signature-scheme-names*
  '((#x0403 . :ecdsa-secp256r1-sha256)
    (#x0503 . :ecdsa-secp384r1-sha384)
    (#x0603 . :ecdsa-secp521r1-sha512)
    (#x0804 . :rsa-pss-rsae-sha256)
    (#x0805 . :rsa-pss-rsae-sha384)
    (#x0806 . :rsa-pss-rsae-sha512)
    (#x0807 . :ed25519)
    (#x0808 . :ed448)
    (#x0809 . :rsa-pss-pss-sha256)
    (#x080a . :rsa-pss-pss-sha384)
    (#x080b . :rsa-pss-pss-sha512)))

(defun %tls13-verification-octets (value name)
  (unless (and (vectorp value)
               (every (lambda (octet) (typep octet '(unsigned-byte 8))) value))
    (error 'tls13-invalid-verification-input
           :reason :invalid-input
           :message (format nil "~A must be an octet vector" name)))
  value)

(defun %tls13-verification-fail (type reason format-control &rest arguments)
  (error type :reason reason :message (apply #'format nil format-control arguments)))

(defun tls13-signature-scheme-name (scheme)
  "Return the keyword name of a TLS 1.3 signature scheme, or NIL."
  (cdr (assoc scheme *tls13-signature-scheme-names*)))

(defun tls13-client-hello-signature-algorithms (client-hello)
  "Decode the signature_algorithms extension (type 13) from CLIENT-HELLO.
Return the offered uint16 scheme identifiers in wire order."
  (let ((extension (find 13 (tls13-client-hello-extensions client-hello)
                         :key #'tls-extension-type)))
    (unless extension
      (%tls13-verification-fail 'tls13-signature-scheme-not-offered
                                :missing-signature-algorithms
                                "ClientHello has no signature_algorithms extension"))
    (let ((data (%tls13-verification-octets (tls-extension-data extension)
                                           "signature_algorithms extension")))
      (when (< (length data) 2)
        (%tls13-verification-fail 'tls13-invalid-verification-input
                                  :malformed-signature-algorithms
                                  "signature_algorithms extension is truncated"))
      (let ((length (logior (ash (aref data 0) 8) (aref data 1))))
        (unless (and (plusp length) (= length (- (length data) 2)) (evenp length))
          (%tls13-verification-fail 'tls13-invalid-verification-input
                                    :malformed-signature-algorithms
                                    "signature_algorithms vector has invalid length"))
        (loop for position from 2 below (length data) by 2
              collect (logior (ash (aref data position) 8)
                              (aref data (1+ position))))))))

(defun tls13-signature-scheme-offered-p (client-hello scheme)
  (member scheme (tls13-client-hello-signature-algorithms client-hello) :test #'=))

(defun tls13-validate-certificate-verify-algorithm (client-hello scheme)
  "Ensure the CertificateVerify scheme was offered by ClientHello."
  (unless (tls13-signature-scheme-name scheme)
    (%tls13-verification-fail 'tls13-signature-algorithm-mismatch
                              :unsupported-signature-scheme
                              "unsupported CertificateVerify signature scheme #x~4,'0X"
                              scheme))
  (unless (tls13-signature-scheme-offered-p client-hello scheme)
    (%tls13-verification-fail 'tls13-signature-scheme-not-offered
                              :signature-scheme-not-offered
                              "CertificateVerify scheme #x~4,'0X was not offered"
                              scheme))
  scheme)

(defun tls13-certificate-verify-signature-input (role transcript-hash)
  "Construct the RFC 8446 CertificateVerify input, including the separator."
  (%tls13-verification-octets transcript-hash "transcript hash")
  (unless (member role '(:client :server))
    (%tls13-verification-fail 'tls13-invalid-verification-input :invalid-role
                              "CertificateVerify role must be :CLIENT or :SERVER"))
  (concatenate '(vector (unsigned-byte 8))
               (make-array 64 :element-type '(unsigned-byte 8) :initial-element #x20)
               (map '(vector (unsigned-byte 8)) #'char-code
                    (tls13-certificate-verify-context role))
               #(0)
               transcript-hash))

(defun tls13-constant-time-equal-p (left right)
  "Compare equal-length octet vectors without an early mismatch exit."
  (%tls13-verification-octets left "left value")
  (%tls13-verification-octets right "right value")
  (let ((difference (logxor (length left) (length right)))
        (limit (max (length left) (length right))))
    (dotimes (index limit)
      (let ((left-octet (if (< index (length left)) (aref left index) 0))
            (right-octet (if (< index (length right)) (aref right index) 0)))
        (setf difference (logior difference (logxor left-octet right-octet)))))
    (zerop difference)))

(defun tls13-verify-finished (expected actual)
  "Verify Finished verify_data using a constant-time comparison."
  (unless (tls13-constant-time-equal-p expected actual)
    (%tls13-verification-fail 'tls13-finished-mismatch :finished-mismatch
                              "Finished verify_data does not match"))
  t)

(defun %tls13-verify-signature-provider (provider)
  (cond ((functionp provider) provider)
        ((and (listp provider) (functionp (getf provider :verify-signature)))
         (getf provider :verify-signature))
        ((%crypto-verify-function))
        (t (%tls13-verification-fail 'tls13-verification-provider-error
                                     :missing-verify-signature
                                     "provider has no verify-signature operation"))))

(defun %tls13-certificate-public-key (public-key)
  "Convert a parsed X.509 public key when CL-CRYPTO-KIT is available."
  (if (not (typep public-key 'cl-tls-kit.x509:x509-public-key))
      public-key
      (let* ((package (or (find-package "CRYPTO-KIT")
                          (find-package "CL-CRYPTO-KIT")))
             (constructor-name
               (case (cl-tls-kit.x509:x509-public-key-type public-key)
                 (:rsa "MAKE-RSA-PUBLIC-KEY")
                 (:ec "MAKE-EC-PUBLIC-KEY")
                 (:ed25519 "MAKE-ED25519-PUBLIC-KEY")))
             (constructor (and package (find-symbol constructor-name package))))
        (unless (and constructor (fboundp constructor))
          (%tls13-verification-fail 'tls13-verification-provider-error
                                    :missing-public-key-constructor
                                    "crypto provider cannot construct the certificate public key"))
        (case (cl-tls-kit.x509:x509-public-key-type public-key)
          (:rsa (funcall constructor
                         (cl-tls-kit.x509:x509-rsa-public-key-modulus public-key)
                         (cl-tls-kit.x509:x509-rsa-public-key-exponent public-key)))
          (:ec (funcall constructor
                        (cond ((string= (cl-tls-kit.x509:x509-ec-public-key-curve public-key)
                                       "1.3.132.0.34") :p384)
                              ((string= (cl-tls-kit.x509:x509-ec-public-key-curve public-key)
                                        "1.2.840.10045.3.1.7") :p256)
                              (t (%tls13-verification-fail
                                  'tls13-verification-provider-error
                                  :unsupported-public-key
                                  "unsupported EC certificate curve")))
                        (cl-tls-kit.x509:x509-ec-public-key-point public-key)))
          (:ed25519 (funcall constructor
                             (cl-tls-kit.x509:x509-ed25519-public-key-point public-key)))))))

(defun %tls13-crypto-scheme (scheme)
  (or (cdr (assoc scheme *tls13-signature-scheme-names*))
      (%tls13-verification-fail 'tls13-signature-algorithm-mismatch
                                :unsupported-signature-scheme
                                "unsupported CertificateVerify signature scheme #x~4,'0X"
                                scheme)))

(defun tls13-verify-certificate-verify
    (client-hello role public-key scheme signature transcript-hash provider)
  "Verify a TLS 1.3 CertificateVerify message.

The provider is called as (SCHEME PUBLIC-KEY INPUT SIGNATURE), or defaults to
the loaded crypto provider, and must return true for a valid signature."
  (%tls13-verification-octets signature "CertificateVerify signature")
  (when (zerop (length signature))
    (%tls13-verification-fail 'tls13-invalid-verification-input :invalid-input
                              "CertificateVerify signature cannot be empty"))
  (%tls13-verification-octets transcript-hash "transcript hash")
  (unless (member role '(:client :server))
    (%tls13-verification-fail 'tls13-invalid-verification-input :invalid-role
                              "CertificateVerify role must be :CLIENT or :SERVER"))
  (tls13-validate-certificate-verify-algorithm client-hello scheme)
  (let* ((input (tls13-certificate-verify-signature-input role transcript-hash))
         (verify-signature (%tls13-verify-signature-provider provider))
         (result (handler-case
                     (funcall verify-signature (%tls13-crypto-scheme scheme)
                              (%tls13-certificate-public-key public-key) input signature)
                   (tls13-verification-error (condition) (error condition))
                   (error (condition)
                     (%tls13-verification-fail 'tls13-verification-provider-error
                                               :provider-failure
                                               "verify-signature failed: ~A"
                                               condition)))))
    (unless (typep result 'boolean)
      (%tls13-verification-fail 'tls13-verification-provider-error
                                :invalid-provider-result
                                "verify-signature must return a boolean"))
    (unless result
      (%tls13-verification-fail 'tls13-bad-signature :bad-signature
                                "CertificateVerify signature is invalid"))
    t))
