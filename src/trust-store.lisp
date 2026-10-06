(in-package #:cl-tls-kit)

(export '(default-trust-store-path load-trust-store load-trust-anchors
          *default-ca-paths*))

(defparameter +max-trust-store-bytes+ (* 16 1024 1024))

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

(defun %read-trust-store-octets (source)
  (cond
    ((typep source '(vector (unsigned-byte 8)))
     (when (> (length source) +max-trust-store-bytes+)
       (error 'pem-error :message "CA trust store is too large"))
     source)
    ((or (stringp source) (pathnamep source))
     (let ((path (pathname source)))
       (unless (and (probe-file path)
                    (not (uiop:directory-pathname-p path)))
         (error 'pem-error :message "CA trust store path does not name a file"))
       (with-open-file (stream path :direction :input
                                    :element-type '(unsigned-byte 8))
         (let ((size (file-length stream)))
           (unless (and (integerp size) (<= 0 size) (<= size +max-trust-store-bytes+))
             (error 'pem-error :message "CA trust store is too large"))
           (let ((octets (make-array size :element-type '(unsigned-byte 8))))
             (unless (= (read-sequence octets stream) size)
               (error 'pem-error :message "CA trust store ended before its declared size"))
             octets)))))
    (t
     (error 'type-error :datum source
            :expected-type '(or string pathname (vector (unsigned-byte 8)))))))

(defun %trust-store-text (octets)
  (map 'string
       (lambda (octet)
         (if (< octet #x80)
             (code-char octet)
             (error 'pem-error :message "CA trust store is not ASCII PEM")))
       octets))

(defun load-trust-anchors (source)
  "Return X.509 trust anchors from a PEM bundle supplied as bytes or a path.
SOURCE must be a byte vector containing PEM text, or a pathname/string naming
a PEM file. Every CERTIFICATE block is parsed and malformed blocks are
rejected instead of being ignored."
  (let* ((text (%trust-store-text (%read-trust-store-octets source)))
         (blocks (pem-decode text))
         (certificate-blocks
           (remove-if-not (lambda (block)
                            (string= (pem-block-label block) "CERTIFICATE"))
                          blocks)))
    (unless certificate-blocks
      (error 'invalid-certificate-chain :certificate nil))
    (mapcar (lambda (block)
              (cl-tls-kit.x509:parse-certificate-der (pem-block-der block)))
            certificate-blocks)))
