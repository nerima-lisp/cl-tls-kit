(in-package #:cl-tls-kit)

(export '(expired certificate-expired hostname-mismatch certificate-hostname-mismatch
          untrusted-root self-signed self-signed-certificate not-a-ca path-length-exceeded
          bad-signature invalid-key-usage invalid-extended-key-usage
          invalid-certificate-chain certificate-signature-provider-unavailable
          verify-certificate verify-certificate-chain))

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
(define-condition invalid-certificate-chain (certificate-verification-error) ())
(define-condition certificate-signature-provider-unavailable (certificate-verification-error) ())

(defun %field (object key &optional default)
  (cond ((hash-table-p object) (gethash key object default))
        ((and (listp object) (or (null object) (keywordp (first object)))) (getf object key default))
        ((listp object) (or (cdr (assoc key object)) default))
        ((typep object 'cl-tls-kit.x509:x509-certificate)
         (case key
           (:not-before (cl-tls-kit.x509:x509-certificate-not-before object))
           (:not-after (cl-tls-kit.x509:x509-certificate-not-after object))
           (:issuer (cl-tls-kit.x509:x509-certificate-issuer object))
           (:subject (cl-tls-kit.x509:x509-certificate-subject object))
           (:public-key (cl-tls-kit.x509:x509-certificate-public-key object))
           (:signature-algorithm (cl-tls-kit.x509:x509-certificate-signature-algorithm object))
           (:tbs-certificate (cl-tls-kit.x509::x509-certificate-tbs-certificate object))
           (:signature (cl-tls-kit.x509::x509-certificate-signature object))
           (:basic-constraints (cl-tls-kit.x509:x509-certificate-basic-constraints object))
           (:key-usage (cl-tls-kit.x509:x509-certificate-key-usage object))
           (:extended-key-usage (cl-tls-kit.x509:x509-certificate-extended-key-usage object))
           (:subject-alternative-names (cl-tls-kit.x509:x509-certificate-subject-alternative-name object))
           (:subject-alternative-name (cl-tls-kit.x509:x509-certificate-subject-alternative-name object))
           (otherwise default)))
        (t default)))

(defun %time-ok-p (certificate now)
  (let ((not-before (%field certificate :not-before 0))
        (not-after (%field certificate :not-after most-positive-fixnum)))
    (and (<= not-before now) (<= now not-after))))

(defun %has-p (value item)
  (some (lambda (x)
          (or (string-equal (string x) (string item))
              (and (string-equal (string item) "server-auth")
                   (string= (string x) "1.3.6.1.5.5.7.3.1")))) value))

(defun %same-name-p (left right)
  (or (equalp left right)
      (and (listp left) (listp right)
           (string= (cl-tls-kit.x509:x509-name-string left)
                    (cl-tls-kit.x509:x509-name-string right)))))

(defun %crypto-verify-function ()
  (dolist (package-name '("CL-CRYPTO-KIT" "CRYPTO-KIT"))
    (let* ((package (find-package package-name))
           (symbol (and package (find-symbol "VERIFY-SIGNATURE" package))))
      (when (and symbol (fboundp symbol)) (return-from %crypto-verify-function symbol))))
  nil)

(defun %verify-signature (certificate issuer verify-signature)
  (let ((function (or verify-signature (%crypto-verify-function))))
    (unless (and function (fboundp function))
      (error 'certificate-signature-provider-unavailable :certificate certificate))
    (unless (handler-case
                (funcall function (%field certificate :signature-algorithm)
                         (%field issuer :public-key) (%field certificate :tbs-certificate)
                         (%field certificate :signature))
              (error () nil))
      (error 'bad-signature :certificate certificate))))

(defun %basic-constraint (certificate key &optional default)
  (let ((constraints (%field certificate :basic-constraints nil)))
    (if (and constraints (listp constraints)) (getf constraints key default) default)))

(defun %check-certificate (certificate issuer ca-depth now verify-signature)
  (unless (%time-ok-p certificate now) (error 'certificate-expired :certificate certificate))
  (when issuer
    (unless (%same-name-p (%field certificate :issuer nil) (%field issuer :subject nil))
      (error 'invalid-certificate-chain :certificate certificate))
    (%verify-signature certificate issuer verify-signature)
    (unless (eq t (%basic-constraint issuer :ca nil)) (error 'not-a-ca :certificate issuer))
    (let ((usage (%field issuer :key-usage nil)))
      (when (and usage (not (%has-p usage :key-cert-sign)))
        (error 'invalid-key-usage :certificate issuer)))
    (let ((limit (%basic-constraint issuer :path-length nil)))
      (when (and limit (> ca-depth limit)) (error 'path-length-exceeded :certificate issuer)))))

(defun verify-certificate-chain (chain &key hostname trust-anchors
                                           (now (get-universal-time)) verify-signature)
  "Verify a leaf-first CHAIN. VERIFY-SIGNATURE takes algorithm, public key,
TBS bytes, and signature bytes, and defaults to a loaded crypto provider."
  (unless chain (error 'untrusted-root :certificate nil))
  (loop for certificate in chain
        for issuer in (append (rest chain) '(nil))
        for index from 0
        do (%check-certificate certificate issuer
                               (count-if (lambda (item) (%field item :basic-constraints nil))
                                         (nthcdr (1+ index) chain))
                               now verify-signature))
  (let* ((leaf (first chain)) (root (car (last chain))))
    (unless (and trust-anchors (member root trust-anchors :test #'equalp))
      (if (%field root :self-signed nil)
          (error 'self-signed-certificate :certificate root)
          (error 'untrusted-root :certificate root)))
    (let ((eku (%field leaf :extended-key-usage nil)))
      (when (and eku (not (%has-p eku :server-auth)))
        (error 'invalid-extended-key-usage :certificate leaf)))
    (when hostname
      (unless (hostname-match-p hostname (%field leaf :subject-alternative-names nil))
        (error 'certificate-hostname-mismatch :certificate leaf)))
    t))

(defun verify-certificate (chain &rest keys)
  (apply #'verify-certificate-chain chain keys))
