(in-package #:cl-tls-kit)

(export (quote (default-trust-store-path load-trust-store load-trust-store-pem
                trust-store-error trust-store-error-message *default-ca-paths*)))

(defparameter *default-ca-paths*
  '("/etc/ssl/cert.pem" "/etc/ssl/certs/ca-certificates.crt"
    "/etc/pki/tls/certs/ca-bundle.crt" "/etc/ssl/ca-bundle.pem"
    "/etc/ssl/certs"))

(defun %getenv (name)
  (let* ((uiop (find-package "UIOP"))
         (uiop-getenv (and uiop (find-symbol "GETENV" uiop))))
    (cond ((and uiop-getenv (fboundp uiop-getenv))
           (funcall uiop-getenv name))
          ((find-package "SB-EXT")
           (funcall (find-symbol "GETENV" "SB-EXT") name))
          (t nil))))

(defun %first-existing-path (paths)
  (find-if (lambda (path)
             (and path (probe-file path)
                  (not (uiop:directory-pathname-p (pathname path)))))
           paths))

(defun %read-trust-store-file (path)
  (with-open-file (input path :direction :input
                         :element-type (quote (unsigned-byte 8)))
    (with-output-to-string (output)
      (let ((buffer (make-array 8192 :element-type (quote (unsigned-byte 8))))
            (total 0))
        (loop for count = (read-sequence buffer input)
              do (incf total count)
                 (when (> total (* 16 1024 1024))
                   (error "CA trust store exceeds the 16 MiB limit"))
                 (dotimes (index count)
                   (let ((octet (aref buffer index)))
                     (when (> octet 127)
                       (error "CA trust store contains non-ASCII data"))
                     (write-char (code-char octet) output)))
              while (= count (length buffer)))))))

(defun default-trust-store-path (&optional (environment #'%getenv))
  "Choose SSL_CERT_FILE, then NIX_SSL_CERT_FILE, then a platform default.
The ENVIRONMENT argument is injectable for deterministic tests."
  (or (funcall environment "SSL_CERT_FILE")
      (funcall environment "NIX_SSL_CERT_FILE")
      (%first-existing-path *default-ca-paths*)))

(defun load-trust-store (&key ca-file (environment #'%getenv)
                              (loader nil loader-supplied-p))
  "Load CA-FILE, or the conventional environment/default CA file.
LOADER receives the selected pathname.  A caller may supply a PEM/DER loader
from its crypto dependency; this module intentionally does not parse PEM."
  (let ((path (or ca-file (default-trust-store-path environment))))
    (unless path
      (error "No CA trust store found (set SSL_CERT_FILE or NIX_SSL_CERT_FILE)."))
    (when loader-supplied-p
      (return-from load-trust-store (funcall loader path)))
    path))

(define-condition trust-store-error (error)
  ((message :initarg :message :reader trust-store-error-message))
  (:report (lambda (condition stream)
             (format stream "Trust store error: ~A"
                     (trust-store-error-message condition)))))
(defun %load-trust-store-pem (&key ca-file
                                  (environment (function %getenv))
                                  (command-runner
                                    (lambda (argv)
                                      (multiple-value-bind (output error-output exit-code)
                                          (uiop:run-program argv :output :string
                                                            :error-output :string
                                                            :ignore-error-status t)
                                        (values output error-output exit-code))))
                                  (platform :other)
                                  (file-reader (function %read-trust-store-file)))
  (labels ((fail (control &rest arguments)
             (error (quote trust-store-error) :message
                    (apply (function format) nil control arguments)))
           (validate-pem (pem source)
             (unless (stringp pem)
               (fail "~A did not return PEM text" source))
             (when (> (length pem) (* 16 1024 1024))
               (fail "~A exceeds the 16 MiB trust-store limit" source))
             (unless (every (lambda (character) (<= (char-code character) 127)) pem)
               (fail "~A contains non-ASCII data" source))
             (let ((block-count 0))
               (loop with cursor = 0
                     for begin = (search "-----BEGIN " pem :start2 cursor)
                     while begin
                     do (incf block-count)
                        (when (> block-count 512)
                          (fail "~A contains too many PEM blocks" source))
                        (setf cursor (+ begin (length "-----BEGIN "))))
               (handler-case
                   (let ((certificate-count 0)
                         (blocks (pem-decode pem))
                         (cursor 0))
                     (unless (= block-count (length blocks))
                       (fail "~A contains malformed PEM data" source))
                     (dolist (block blocks)
                       (unless (string= (pem-block-label block) "CERTIFICATE")
                         (fail "~A contains a non-certificate PEM block" source))
                       (when (>= certificate-count 512)
                         (fail "~A contains too many certificates" source))
                       (let* ((begin-marker "-----BEGIN CERTIFICATE-----")
                              (end-marker "-----END CERTIFICATE-----")
                              (begin (search begin-marker pem :start2 cursor)))
                         (unless begin
                           (fail "~A contains malformed PEM data" source))
                         (unless (every (lambda (character)
                                          (let ((code (char-code character)))
                                            (or (= code 32) (= code 9) (= code 13) (= code 10))))
                                        (subseq pem cursor begin))
                           (fail "~A contains data outside PEM blocks" source))
                         (let* ((body-start (+ begin (length begin-marker)))
                                (end (search end-marker pem :start2 body-start)))
                           (unless end
                             (fail "~A contains malformed PEM data" source))
                           (setf cursor (+ end (length end-marker)))))
                       (incf certificate-count))
                     (unless (every (lambda (character)
                                      (let ((code (char-code character)))
                                        (or (= code 32) (= code 9) (= code 13) (= code 10))))
                                    (subseq pem cursor))
                       (fail "~A contains data outside PEM blocks" source))
                     (unless (plusp certificate-count)
                       (fail "~A contains no certificates" source))
                     pem)
                 (trust-store-error (condition) (error condition))
                 (error (condition)
                   (fail "Invalid certificate PEM in ~A: ~A" source condition)))))
           (read-pem-file (path)
             (handler-case
                 (validate-pem (funcall file-reader path) "configured CA file")
               (trust-store-error (condition) (error condition))
               (error (condition)
                 (fail "Could not read configured CA file ~A: ~A" path condition))))
           (system-roots-pem ()
             (handler-case
                 (multiple-value-bind (output error-output exit-code)
                     (funcall command-runner
                              (list "/usr/bin/security" "find-certificate" "-a" "-p"
                                    "/System/Library/Keychains/SystemRootCertificates.keychain"))
                   (declare (ignore error-output))
                   (unless (eql exit-code 0)
                     (fail "System Roots Keychain export failed with exit status ~A"
                           exit-code))
                   (validate-pem output "macOS System Roots Keychain"))
               (trust-store-error (condition) (error condition))
               (error (condition)
                 (fail "Could not export System Roots Keychain certificates: ~A"
                       condition)))))
    (let ((path (or ca-file
                    (funcall environment "SSL_CERT_FILE")
                    (funcall environment "NIX_SSL_CERT_FILE"))))
      (cond (path (read-pem-file path))
            ((eq platform :macos) (system-roots-pem))
            (t (let ((default-path (%first-existing-path *default-ca-paths*)))
                 (if default-path
                     (read-pem-file default-path)
                     (fail "No CA trust store found (set SSL_CERT_FILE or NIX_SSL_CERT_FILE)."))))))))
(defun load-trust-store-pem (&key ca-file (environment (function %getenv)))
  (%load-trust-store-pem
   :ca-file ca-file
   :environment environment
   :platform (if (or (member :darwin *features*)
                     (member :macos *features*)
                     (search "Darwin" (software-type) :test (function char-equal)))
                 :macos
                 :other)))
