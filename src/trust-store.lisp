(in-package #:cl-tls-kit)

(export '(default-trust-store-path load-trust-store *default-ca-paths*))

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
