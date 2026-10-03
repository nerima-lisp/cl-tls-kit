(in-package #:cl-tls-kit/test)

(defparameter *openssl-e2e-port* 45100)

(defun %openssl-e2e-call (name)
  (let* ((package (find-package "CRYPTO-KIT"))
         (symbol (and package (find-symbol name package))))
    (unless (and symbol (fboundp symbol))
      (error "CL-CRYPTO-KIT:~A is unavailable" name))
    (symbol-function symbol)))

(defun %openssl-e2e-key-exchange ()
  (let ((random (%openssl-e2e-call "RANDOM-OCTETS"))
        (x25519 (%openssl-e2e-call "X25519"))
        (p256-generate (%openssl-e2e-call "P256-GENERATE-KEYPAIR"))
        (p256-ecdh (%openssl-e2e-call "P256-ECDH")))
    (list :random random
          :generate
          (lambda (group)
            (if (= group #x001d)
                (let ((private (funcall random 32)))
                  (let ((base (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 0)))
                    (setf (aref base 0) 9)
                    (values private (nth-value 0 (funcall x25519 private base)))))
                (funcall p256-generate)))
          :shared-secret
          (lambda (group private public)
            (if (= group #x001d)
                (multiple-value-bind (secret all-zero)
                    (funcall x25519 private public)
                  (when all-zero (error "X25519 produced an all-zero secret"))
                  secret)
                (funcall p256-ecdh private public))))))

(defun %openssl-e2e-run (program arguments)
  (multiple-value-bind (output error-output exit-code)
      (uiop:run-program (cons program arguments)
                        :output :string :error-output :string
                        :ignore-error-status t)
    (declare (ignore error-output))
    (values output exit-code)))

(defun %openssl-e2e-certificate (openssl path key-name common-name days &key ca)
  (multiple-value-bind (output exit-code)
      (%openssl-e2e-run
       openssl
       (list "req" "-x509" "-newkey" "rsa:2048" "-nodes"
             "-days" (princ-to-string days) "-subj"
             (format nil "/CN=~A" common-name)
             "-addext" (format nil "subjectAltName=DNS:~A" common-name)
             "-addext" (if ca
                            "basicConstraints=critical,CA:TRUE"
                            "basicConstraints=critical,CA:FALSE")
             "-addext" (if ca
                            "keyUsage=critical,keyCertSign,digitalSignature"
                            "keyUsage=critical,digitalSignature")
             "-addext" "extendedKeyUsage=serverAuth"
             "-keyout" key-name "-out" path))
    (declare (ignore output))
    (unless (zerop exit-code)
      (error "OpenSSL certificate generation failed"))))

(defun %openssl-e2e-start (openssl port certificate key suite groups)
  (uiop:launch-program
   (list openssl "s_server" "-accept" (princ-to-string port)
         "-cert" certificate "-key" key "-tls1_3"
         "-ciphersuites" suite "-groups" groups "-alpn" "http/1.1"
         "-no_ticket" "-www" "-quiet")
   :output *standard-output* :error-output *error-output*
   :wait nil))

(defun %openssl-e2e-pem-certificate (path)
  (cl-tls-kit.x509:parse-certificate-der
   (cl-tls-kit:pem-block-der
    (first (cl-tls-kit:pem-decode (uiop:read-file-string path))))))

(defun %openssl-e2e-driver (host port provider suite groups &key trust-anchors now)
  (cl-tls-kit:make-tls13-client-driver-over-tcp
   host port
   :provider provider
   :key-exchange (%openssl-e2e-key-exchange)
   :on-send nil
   :alpn '("http/1.1")
   :cipher-suites (vector suite)
   :supported-groups groups
   :hostname "localhost"
   :trust-anchors trust-anchors
   :now (or now (get-universal-time))))

(defun %openssl-e2e-http-request ()
  (map 'vector #'char-code
       (format nil "GET / HTTP/1.0~C~CHost: localhost~C~CConnection: close~C~C~C~C"
               #\Return #\Linefeed #\Return #\Linefeed
               #\Return #\Linefeed #\Return #\Linefeed)))

(defun %openssl-e2e-read-application (driver)
  (loop repeat 16
        for plaintext = (cl-tls-kit:tls13-client-driver-read-record driver)
        when plaintext return (cl-tls-kit:tls-plaintext-fragment plaintext)
        finally (error "OpenSSL did not return application data")))

(defun %openssl-e2e-with-server
    (openssl suite groups certificate key function)
  (let* ((port (prog1 *openssl-e2e-port* (incf *openssl-e2e-port*)))
         (server nil))
    (unwind-protect
         (progn
           (setf server (%openssl-e2e-start openssl port certificate key suite groups))
           (sleep 1)
           (funcall function port))
      (when server
        (ignore-errors (uiop:terminate-process server))
        (ignore-errors (uiop:wait-process server))))))

(defun %openssl-e2e-expect-verification
    (openssl provider certificate key trust-anchor now expected)
  (%openssl-e2e-with-server
   openssl "TLS_AES_128_GCM_SHA256" "X25519" certificate key
   (lambda (port)
     (let ((driver (%openssl-e2e-driver "127.0.0.1" port provider #x1301
                                        '(#x001d) :trust-anchors
                                        (list trust-anchor) :now now))
           (condition nil))
       (unwind-protect
            (handler-case
                (cl-tls-kit:tls13-client-driver-connect driver)
              (cl-tls-kit:tls13-client-driver-error (error)
                (let ((reason (cl-tls-kit:tls13-client-driver-error-reason error)))
                  (setf condition (getf (cdr reason) :condition)))))
         (cl-tls-kit:tls13-client-driver-close driver))
       (check (typep condition expected)
              "OpenSSL certificate failure has the expected condition")))))

(defun run-openssl-e2e-tests ()
  (unless (find-package "CRYPTO-KIT")
    (error "OpenSSL E2E requires cl-crypto-kit in the canonical test process"))
  (let* ((openssl (or (uiop:getenv "OPENSSL") "openssl"))
         (directory (merge-pathnames "cl-tls-kit-openssl-e2e/"
                                     (uiop:temporary-directory)))
         (certificate (namestring (merge-pathnames "server.crt" directory)))
         (key (namestring (merge-pathnames "server.key" directory)))
         (wrong-certificate (namestring (merge-pathnames "wrong.crt" directory)))
         (wrong-key (namestring (merge-pathnames "wrong.key" directory)))
         (other-certificate (namestring (merge-pathnames "other.crt" directory)))
         (other-key (namestring (merge-pathnames "other.key" directory)))
         (anchor-certificate (namestring (merge-pathnames "anchor.crt" directory)))
         (anchor-key (namestring (merge-pathnames "anchor.key" directory)))
         (provider (cl-tls-kit:make-cl-crypto-kit-provider))
         (selected 0)
         (assertions 0))
    (ensure-directories-exist directory)
    (unwind-protect
         (progn
           (%openssl-e2e-certificate openssl certificate key "localhost" 1)
           (dolist (suite '(#x1301 #x1302 #x1303))
             (dolist (group '((#x001d) (#x0017)))
               (incf selected)
               (%openssl-e2e-with-server
                openssl
                (case suite
                  (#x1301 "TLS_AES_128_GCM_SHA256")
                  (#x1302 "TLS_AES_256_GCM_SHA384")
                  (#x1303 "TLS_CHACHA20_POLY1305_SHA256"))
                (if (= (first group) #x001d) "X25519" "P-256")
                certificate key
                (lambda (port)
                  (let ((driver (%openssl-e2e-driver "127.0.0.1" port provider
                                                     suite group :trust-anchors
                                                     (list (%openssl-e2e-pem-certificate certificate)))))
                    (unwind-protect
                         (progn
                           (cl-tls-kit:tls13-client-driver-connect driver)
                           (incf assertions)
                           (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                                      :connected)
                                  "cl-tls-kit completes an OpenSSL TLS 1.3 handshake")
                           (incf assertions)
                           (check (string= (cl-tls-kit:tls13-client-driver-negotiated-alpn driver)
                                           "http/1.1")
                                  "OpenSSL negotiates the requested ALPN")
                           (cl-tls-kit:tls13-client-driver-key-update driver 0)
                           (cl-tls-kit:tls13-client-driver-write
                            driver (%openssl-e2e-http-request))
                           (incf assertions)
                           (let ((response (%openssl-e2e-read-application driver)))
                             (check (search "HTTP/1.0" (map 'string #'code-char response))
                                    "OpenSSL accepts application data after KeyUpdate")))
                      (cl-tls-kit:tls13-client-driver-close driver)))))))
           (incf selected)
           (%openssl-e2e-with-server
            openssl "TLS_AES_128_GCM_SHA256" "P-256" certificate key
            (lambda (port)
              (let ((driver (%openssl-e2e-driver "127.0.0.1" port provider #x1301
                                                 '(#x001d #x0017) :trust-anchors
                                                 (list (%openssl-e2e-pem-certificate certificate)))))
                (unwind-protect
                     (progn
                       (cl-tls-kit:tls13-client-driver-connect driver)
                       (incf assertions)
                       (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                                  :connected)
                              "cl-tls-kit completes an OpenSSL HelloRetryRequest"))
                       (incf assertions)
                       (check (string= (cl-tls-kit:tls13-client-driver-negotiated-alpn driver)
                                       "http/1.1")
                              "OpenSSL negotiates ALPN after HelloRetryRequest")
                       (cl-tls-kit:tls13-client-driver-write
                        driver (%openssl-e2e-http-request))
                       (incf assertions)
                       (check (search "HTTP/1.0"
                                      (map 'string #'code-char
                                           (%openssl-e2e-read-application driver)))
                              "OpenSSL accepts application data after HelloRetryRequest")
                  (cl-tls-kit:tls13-client-driver-close driver)
                  (incf assertions)
                  (check (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
                         "cl-tls-kit sends close_notify")))))
           (%openssl-e2e-certificate openssl wrong-certificate wrong-key "wrong.local" 1)
           (%openssl-e2e-certificate openssl other-certificate other-key "other.local" 1)
           (%openssl-e2e-certificate openssl anchor-certificate anchor-key "localhost" 1 :ca t)
           (incf selected)
           (%openssl-e2e-with-server
            openssl "TLS_AES_128_GCM_SHA256" "X25519" anchor-certificate anchor-key
            (lambda (port)
              (let ((driver (%openssl-e2e-driver
                             "127.0.0.1" port provider #x1301 '(#x001d)
                             :trust-anchors
                             (list (%openssl-e2e-pem-certificate anchor-certificate)))))
                (unwind-protect
                     (progn
                       (cl-tls-kit:tls13-client-driver-connect driver)
                       (incf assertions)
                       (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                                  :connected)
                              "TLS 1.3 accepts a self-signed CA trust anchor with localhost SAN"))
                  (cl-tls-kit:tls13-client-driver-close driver)))))
           (let ((anchor (%openssl-e2e-pem-certificate certificate))
                 (future (+ (get-universal-time) (* 3 86400))))
             (incf selected)
             (%openssl-e2e-expect-verification
              openssl provider certificate key anchor future
              'cl-tls-kit:certificate-expired)
             (incf assertions)
             (incf selected)
             (%openssl-e2e-expect-verification
              openssl provider wrong-certificate wrong-key
              (%openssl-e2e-pem-certificate wrong-certificate)
              (get-universal-time) 'cl-tls-kit:certificate-hostname-mismatch)
             (incf assertions)
             (incf selected)
             (%openssl-e2e-expect-verification
              openssl provider other-certificate other-key anchor
              (get-universal-time) 'cl-tls-kit:untrusted-root)
             (incf assertions))
           (check (plusp selected) "OpenSSL E2E selected at least one case")
           (check (plusp assertions) "OpenSSL E2E executed at least one assertion")
           (format t "OpenSSL E2E: selected test count: ~D; assertions: ~D~%"
                   selected assertions)
           t)
      (ignore-errors (delete-file certificate))
      (ignore-errors (delete-file key))
      (ignore-errors (delete-file wrong-certificate))
      (ignore-errors (delete-file wrong-key))
      (ignore-errors (delete-file other-certificate))
      (ignore-errors (delete-file other-key))
      (ignore-errors (delete-file anchor-certificate))
      (ignore-errors (delete-file anchor-key)))))
