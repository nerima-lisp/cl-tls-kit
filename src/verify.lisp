(in-package #:cl-tls-kit)

(export '(expired certificate-expired hostname-mismatch certificate-hostname-mismatch
          untrusted-root self-signed self-signed-certificate not-a-ca path-length-exceeded bad-signature
          invalid-key-usage invalid-extended-key-usage verify-certificate
          verify-certificate-chain))

(define-condition certificate-verification-error (error)
  ((certificate :initarg :certificate :reader verification-error-certificate)))
(define-condition expired (certificate-verification-error) ())
(define-condition certificate-expired (expired) ())
(define-condition certificate-hostname-mismatch (hostname-mismatch certificate-verification-error) ())
(define-condition untrusted-root (certificate-verification-error) ())
(define-condition self-signed (certificate-verification-error) ())
(define-condition self-signed-certificate (self-signed) ())
(define-condition not-a-ca (certificate-verification-error) ())
(define-condition path-length-exceeded (certificate-verification-error) ())
(define-condition bad-signature (certificate-verification-error) ())
(define-condition invalid-key-usage (certificate-verification-error) ())
(define-condition invalid-extended-key-usage (certificate-verification-error) ())

(defun %field (object key &optional default)
  (cond ((hash-table-p object) (gethash key object default))
        ((and (listp object)
              (or (null object) (keywordp (first object))))
         (getf object key default))
        ((listp object) (or (cdr (assoc key object)) default))
        (t default)))

(defun %time-ok-p (certificate now)
  (let ((not-before (%field certificate :not-before 0))
        (not-after (%field certificate :not-after most-positive-fixnum)))
    (and (<= not-before now) (<= now not-after))))

(defun %token (value)
  (coerce (remove-if (lambda (character) (find character "-_ "))
                     (string-downcase (string value))) 'string))

(defun %has-p (value item)
  (some (lambda (x) (string= (%token x) (%token item))) value))

(defun %verify-signature (certificate issuer)
  (let ((package (find-package "CL-CRYPTO-KIT"))
        (algorithm (%field certificate :signature-algorithm)))
    (unless package (error "cl-crypto-kit is required to verify signatures"))
    (let ((symbol (find-symbol "VERIFY-SIGNATURE" package)))
      (unless (and symbol (fboundp symbol)) (error "cl-crypto-kit:verify-signature is unavailable"))
      ;; cl-crypto-kit contract: (scheme public-key message signature).
      (unless (funcall symbol algorithm
                       (%field issuer :public-key)
                       (%field certificate :tbs-certificate)
                       (%field certificate :signature))
        (error 'bad-signature :certificate certificate)))))

(defun %check-certificate (certificate issuer depth now)
  (unless (%time-ok-p certificate now)
    (error 'certificate-expired :certificate certificate))
  (when issuer (%verify-signature certificate issuer))
  (when issuer
    (unless (%field issuer :ca nil)
      (error 'not-a-ca :certificate issuer))
    (let ((usage (%field issuer :key-usage nil)))
      (when (and usage (not (%has-p usage "key-cert-sign")))
        (error 'invalid-key-usage :certificate issuer)))
    (let ((limit (%field issuer :path-length nil)))
      (when (and limit (> depth limit))
        (error 'path-length-exceeded :certificate issuer)))))

(defun verify-certificate-chain (chain &key hostname trust-anchors
                                           (now (get-universal-time)))
  "Verify CHAIN leaf-first.  Certificates are plists or hash tables with
the fields used below.  TRUST-ANCHORS contains the trusted root certificates.
The leaf requires serverAuth EKU when EKU is present; hostname matching uses
SAN only."
  (unless chain (error 'untrusted-root :certificate nil))
  (loop for certificate in chain
        for issuer in (append (rest chain) '(nil))
        for index from 0
        do (%check-certificate certificate issuer (max 0 (- index 1)) now))
  (let* ((leaf (first chain))
         (root (car (last chain)))
         (anchors trust-anchors))
    (unless anchors
      (if (%field root :self-signed nil)
          (error 'self-signed-certificate :certificate root)
          (error 'untrusted-root :certificate root)))
    (unless (member root anchors :test #'equalp)
      (error 'untrusted-root :certificate root))
    (when (and (%field root :self-signed nil)
               (not (member root anchors :test #'equalp)))
      (error 'self-signed-certificate :certificate root))
    (let ((eku (%field leaf :extended-key-usage nil)))
      (when (and eku (not (%has-p eku "server-auth")))
        (error 'invalid-extended-key-usage :certificate leaf)))
    (when hostname
      (unless (hostname-match-p hostname (%field leaf :subject-alternative-names nil))
        (error 'certificate-hostname-mismatch :certificate leaf)))
    t))

(defun verify-certificate (chain &rest keys)
  (apply #'verify-certificate-chain chain keys))
