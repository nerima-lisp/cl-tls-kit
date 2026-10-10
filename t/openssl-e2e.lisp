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

(defun %openssl-e2e-temp-directory ()
  (multiple-value-bind (output exit-code)
      (%openssl-e2e-run
       "mktemp"
       (list "-d" (namestring
                   (merge-pathnames "cl-tls-kit-openssl-e2e.XXXXXXXX"
                                    (uiop:temporary-directory)))))
    (unless (zerop exit-code)
      (error "OpenSSL E2E temporary directory creation failed"))
    (uiop:ensure-directory-pathname
     (string-trim '(#\Space #\Newline #\Return) output))))

(defun %openssl-e2e-cleanup-directory (directory files)
  (let ((failures nil))
    (dolist (file files)
      (handler-case
          (when (probe-file file) (delete-file file))
        (error (condition) (push condition failures))))
    (handler-case
        (uiop:delete-empty-directory directory)
      (error (condition) (push condition failures)))
    (nreverse failures)))

(defun %openssl-e2e-certificate (openssl path key-name common-name days
                                  &key ca (key-type :rsa))
  (multiple-value-bind (output exit-code)
      (%openssl-e2e-run
       openssl
       (append (list "req" "-x509")
               (if (eq key-type :ecdsa)
                   (list "-newkey" "ec" "-pkeyopt" "ec_paramgen_curve:P-256")
                   (list "-newkey" "rsa:2048"))
               (list "-nodes"
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
             "-keyout" key-name "-out" path)))
    (declare (ignore output))
    (unless (zerop exit-code)
      (error "OpenSSL certificate generation failed"))))

(defun %openssl-e2e-start (openssl port certificate key suite groups &key chain)
  (uiop:launch-program
   (append (list openssl "s_server" "-accept" (princ-to-string port)
                 "-cert" certificate "-key" key "-tls1_3"
                 "-ciphersuites" suite "-groups" groups "-alpn" "http/1.1"
                 "-no_ticket" "-www" "-quiet")
           (when chain (list "-cert_chain" chain)))
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
    (openssl suite groups certificate key function &key chain)
  (let* ((port (prog1 *openssl-e2e-port* (incf *openssl-e2e-port*)))
         (server nil))
    (unwind-protect
         (progn
           (setf server (%openssl-e2e-start openssl port certificate key suite groups
                                          :chain chain))
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
         (provider (cl-tls-kit:make-cl-crypto-kit-provider))
         (directory (%openssl-e2e-temp-directory))
         (certificate (namestring (merge-pathnames "server.crt" directory)))
         (key (namestring (merge-pathnames "server.key" directory)))
         (wrong-certificate (namestring (merge-pathnames "wrong.crt" directory)))
         (wrong-key (namestring (merge-pathnames "wrong.key" directory)))
         (other-certificate (namestring (merge-pathnames "other.crt" directory)))
         (other-key (namestring (merge-pathnames "other.key" directory)))
         (anchor-certificate (namestring (merge-pathnames "anchor.crt" directory)))
         (anchor-key (namestring (merge-pathnames "anchor.key" directory)))
         (ecdsa-certificate (namestring (merge-pathnames "ecdsa.crt" directory)))
         (ecdsa-key (namestring (merge-pathnames "ecdsa.key" directory)))
         (files (list certificate key wrong-certificate wrong-key
                      other-certificate other-key anchor-certificate anchor-key
                      ecdsa-certificate ecdsa-key))
         (body-failure nil)
         (cleanup-failures nil)
         (selected 0)
         (assertions 0))
    (unwind-protect
         (handler-case
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
                              "cl-tls-kit completes an OpenSSL HelloRetryRequest")
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
                              "OpenSSL accepts application data after HelloRetryRequest"))
                  (cl-tls-kit:tls13-client-driver-close driver)
                  (incf assertions)
                  (check (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
                         "cl-tls-kit sends close_notify")))))
           (%openssl-e2e-certificate openssl wrong-certificate wrong-key "wrong.local" 1)
           (%openssl-e2e-certificate openssl other-certificate other-key "other.local" 1)
           (%openssl-e2e-certificate openssl anchor-certificate anchor-key "localhost" 1 :ca t)
           (%openssl-e2e-certificate openssl ecdsa-certificate ecdsa-key "localhost" 1
                                     :key-type :ecdsa)
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
           (incf selected)
           (%openssl-e2e-with-server
            openssl "TLS_AES_128_GCM_SHA256" "X25519" ecdsa-certificate ecdsa-key
            (lambda (port)
              (let ((driver (%openssl-e2e-driver
                             "127.0.0.1" port provider #x1301 '(#x001d)
                             :trust-anchors
                             (list (%openssl-e2e-pem-certificate ecdsa-certificate)))))
                (unwind-protect
                     (progn
                       (cl-tls-kit:tls13-client-driver-connect driver)
                       (incf assertions)
                       (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                                  :connected)
                              "TLS 1.3 completes with an ECDSA P-256 certificate")
                       (cl-tls-kit:tls13-client-driver-write
                        driver (%openssl-e2e-http-request))
                       (incf assertions)
                       (check (search "HTTP/1.0"
                                      (map 'string #'code-char
                                           (%openssl-e2e-read-application driver)))
                              "OpenSSL accepts application data after ECDSA CertificateVerify"))
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
           (multiple-value-bind (chain-selected chain-assertions)
               (run-openssl-chain-tests openssl provider)
             (incf selected chain-selected)
             (incf assertions chain-assertions))
           (incf assertions (run-pss-signature-tests))
           (check (plusp selected) "OpenSSL E2E selected at least one case")
           (check (plusp assertions) "OpenSSL E2E executed at least one assertion")
           (incf assertions 2)
           t)
          (error (condition) (setf body-failure condition)))
      (setf cleanup-failures (%openssl-e2e-cleanup-directory directory files)))
    (when body-failure
      (when cleanup-failures
        (format *error-output* "OpenSSL E2E cleanup also failed: ~{~A~^; ~}~%"
                cleanup-failures))
      (error body-failure))
    (when cleanup-failures
      (error "OpenSSL E2E cleanup failed: ~{~A~^; ~}" cleanup-failures))
    (incf assertions)
    (check (every (lambda (file) (not (probe-file file))) files)
           "OpenSSL E2E removes all temporary certificates and private keys")
    (incf assertions)
    (check (not (uiop:directory-exists-p directory))
           "OpenSSL E2E removes its temporary directory")
    (format t "OpenSSL E2E: selected test count: ~D; assertions: ~D~%"
            selected assertions)
    t))
