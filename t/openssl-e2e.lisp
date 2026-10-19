(in-package #:cl-tls-kit/test)

(defparameter *openssl-e2e-port* 45100)

(defun %openssl-e2e-run (program arguments)
  (multiple-value-bind (output error-output exit-code)
      (uiop:run-program (cons program arguments)
                        :output :string :error-output :string
                        :ignore-error-status t)
    (declare (ignore error-output))
    (values output exit-code)))

(defun %openssl-e2e-certificate (openssl path key-name common-name days
                                         &key ca (key-type :rsa)
                                         signer-certificate signer-key)
  (let* ((request (concatenate 'string path ".csr"))
         (serial (and signer-certificate
                      (concatenate 'string signer-certificate ".srl")))
         (key-options
           (if (eq key-type :ecdsa)
               (list "-newkey" "ec" "-pkeyopt" "ec_paramgen_curve:P-256")
               (list "-newkey" "rsa:2048")))
         (extensions
           (list "-addext"
                 (format nil "subjectAltName=DNS:~A" common-name)
                 "-addext"
                 (if ca
                     "basicConstraints=critical,CA:TRUE"
                     "basicConstraints=critical,CA:FALSE")
                 "-addext"
                 (if ca
                     "keyUsage=critical,keyCertSign,digitalSignature"
                     "keyUsage=critical,digitalSignature")
                 "-addext" "extendedKeyUsage=serverAuth")))
    (multiple-value-bind (output exit-code)
        (%openssl-e2e-run
         openssl
         (append (list "req" (if signer-certificate "-new" "-x509"))
                 key-options
                 (list "-nodes")
                 (unless signer-certificate
                   (list "-days" (princ-to-string days)))
                 (list "-subj" (format nil "/CN=~A" common-name))
                 extensions
                 (list "-keyout" key-name
                       "-out" (if signer-certificate request path))))
      (declare (ignore output))
      (unless (zerop exit-code)
        (error "OpenSSL certificate request failed")))
    (when signer-certificate
      (multiple-value-bind (output exit-code)
          (%openssl-e2e-run
           openssl
           (list "x509" "-req" "-in" request
                 "-CA" signer-certificate "-CAkey" signer-key
                 "-CAcreateserial" "-copy_extensions" "copy"
                 "-days" (princ-to-string days) "-out" path))
        (declare (ignore output))
        (unless (zerop exit-code)
          (error "OpenSSL certificate signing failed")))
      (delete-file request)
      (when (probe-file serial)
        (delete-file serial)))))

(defun %openssl-e2e-start
    (openssl port certificate key suite groups
     &key certificate-chain stateless reverse tickets)
  (let ((arguments
         (append
          (list openssl "s_server" "-accept" (princ-to-string port)
                "-cert" certificate "-key" key "-tls1_3")
          (when certificate-chain
            (list "-cert_chain" certificate-chain))
          (list "-ciphersuites" suite "-groups" groups "-alpn" "http/1.1")
          (when stateless (list "-stateless"))
          (unless tickets (list "-no_ticket"))
          (if reverse (list "-rev") (list "-www"))
          (list "-quiet"))))
    (uiop:launch-program arguments
                         :output *standard-output* :error-output *error-output*
                         :wait nil)))

(defun %openssl-e2e-pem-certificate (path)
  (cl-tls-kit.x509:parse-certificate-der
   (cl-tls-kit:pem-block-der
    (first (cl-tls-kit:pem-decode (uiop:read-file-string path))))))

(defun %openssl-e2e-driver
    (host port provider suite groups
     &key trust-anchors now ticket-store (hostname "localhost"))
  (apply #'cl-tls-kit:make-tls13-client-driver-over-tcp
         host port
         (append
          (list :provider provider
                :on-send nil
                :alpn (list "http/1.1")
                :cipher-suites (vector suite)
                :supported-groups groups
                :trust-anchors trust-anchors
                :ticket-store ticket-store
                :now (or now (get-universal-time)))
          (when hostname (list :hostname hostname)))))

(defun %openssl-e2e-http-request ()
  (map 'vector #'char-code
       (format nil "GET / HTTP/1.0~C~CHost: localhost~C~CConnection: close~C~C~C~C"
               #\Return #\Linefeed #\Return #\Linefeed
               #\Return #\Linefeed #\Return #\Linefeed)))

(defun %openssl-e2e-read-application (driver &optional expected-length)
  (if expected-length
      (loop with fragments = nil
            with total = 0
            repeat 128
            for plaintext = (cl-tls-kit:tls13-client-driver-read-record driver)
            do (when plaintext
                 (let ((fragment (cl-tls-kit:tls-plaintext-fragment plaintext)))
                   (push fragment fragments)
                   (incf total (length fragment))
                   (when (>= total expected-length)
                     (return
                      (apply #'concatenate
                             '(vector (unsigned-byte 8))
                             (nreverse fragments))))))
            finally (error "OpenSSL returned too little application data"))
      (loop repeat 16
            for plaintext = (cl-tls-kit:tls13-client-driver-read-record driver)
            when plaintext return (cl-tls-kit:tls-plaintext-fragment plaintext)
            finally (error "OpenSSL did not return application data"))))

(defun %openssl-e2e-with-server
    (openssl suite groups certificate key function
     &key certificate-chain stateless reverse tickets)
  (let* ((port (prog1 *openssl-e2e-port* (incf *openssl-e2e-port*)))
         (server nil))
    (labels ((wait-for-server ()
               (let* ((package (or (find-package '#:sb-bsd-sockets)
                                   (progn
                                     (require :sb-bsd-sockets)
                                     (find-package '#:sb-bsd-sockets))))
                      (make-socket (find-symbol "MAKE-INET-SOCKET" package))
                      (connect (find-symbol "SOCKET-CONNECT" package))
                      (close-socket (find-symbol "SOCKET-CLOSE" package))
                      (refused-type
                        (find-symbol "CONNECTION-REFUSED-ERROR" package)))
                 (loop repeat 50
                       for ready =
                         (let ((socket (funcall make-socket :stream :tcp)))
                           (unwind-protect
                                (handler-case
                                    (progn
                                      (funcall connect socket #(127 0 0 1) port)
                                      t)
                                  (error (condition)
                                    (if (and refused-type
                                             (typep condition refused-type))
                                        nil
                                        (error condition))))
                             (funcall close-socket socket)))
                       when ready return t
                       do (unless (uiop:process-alive-p server)
                            (error "OpenSSL server exited before listening"))
                          (sleep 0.1)
                       finally
                         (error "OpenSSL server did not listen on port ~D"
                                port)))))
      (unwind-protect
           (progn
             (setf server
                   (%openssl-e2e-start openssl port certificate key suite groups
                                       :certificate-chain certificate-chain
                                       :stateless stateless :reverse reverse
                                       :tickets tickets))
             (wait-for-server)
             (funcall function port))
        (when server
          (ignore-errors (uiop:terminate-process server))
          (ignore-errors (uiop:wait-process server)))))))

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
         (ecdsa-certificate (namestring (merge-pathnames "ecdsa.crt" directory)))
         (ecdsa-key (namestring (merge-pathnames "ecdsa.key" directory)))
         (provider (cl-tls-kit:make-cl-crypto-kit-provider))
         (selected 0)
         (assertions 0)
         (chain-material
          (list :first-certificate
                (namestring (merge-pathnames "intermediate-one.crt" directory))
                :first-key
                (namestring (merge-pathnames "intermediate-one.key" directory))
                :second-certificate
                (namestring (merge-pathnames "intermediate-two.crt" directory))
                :second-key
                (namestring (merge-pathnames "intermediate-two.key" directory))
                :leaf-certificate
                (namestring (merge-pathnames "chain-leaf.crt" directory))
                :leaf-key
                (namestring (merge-pathnames "chain-leaf.key" directory))
                :chain
                (namestring (merge-pathnames "chain.pem" directory)))))
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
           (progn
  (incf selected)
  (%openssl-e2e-with-server
   openssl "TLS_AES_128_GCM_SHA256" "X25519" certificate key
   (lambda (port)
     (let* ((store (cl-tls-kit:make-tls13-ticket-store))
            (trust-anchor (%openssl-e2e-pem-certificate certificate)))
       (let ((first-driver
               (%openssl-e2e-driver
                "localhost" port provider #x1301 (list #x001d)
                :trust-anchors (list trust-anchor) :ticket-store store)))
         (unwind-protect
              (progn
                (cl-tls-kit:tls13-client-driver-connect first-driver)
                (incf assertions)
                (check (not (cl-tls-kit:tls13-client-driver-resumed-p first-driver))
                       "first OpenSSL connection completes a full handshake")
                (cl-tls-kit:tls13-client-driver-write
                 first-driver (%openssl-e2e-http-request))
                (incf assertions)
                (check (search "HTTP/1.0"
                               (map 'string (function code-char)
                                    (%openssl-e2e-read-application first-driver)))
                       "first OpenSSL connection processes a ticket and application data"))
           (cl-tls-kit:tls13-client-driver-close first-driver)))
       (let ((second-driver
               (%openssl-e2e-driver
                "localhost" port provider #x1301 (list #x001d)
                :trust-anchors (list trust-anchor) :ticket-store store)))
         (unwind-protect
              (progn
                (cl-tls-kit:tls13-client-driver-connect second-driver)
                (incf assertions)
                (check (cl-tls-kit:tls13-client-driver-resumed-p second-driver)
                       "second OpenSSL connection resumes with the stored PSK")
                (cl-tls-kit:tls13-client-driver-write
                 second-driver (%openssl-e2e-http-request))
                (incf assertions)
                (check (search "HTTP/1.0"
                               (map 'string (function code-char)
                                    (%openssl-e2e-read-application second-driver)))
                       "resumed OpenSSL connection carries application data"))
           (cl-tls-kit:tls13-client-driver-close second-driver)))))
   :tickets t)
  (incf selected)
  (%openssl-e2e-with-server
   openssl "TLS_AES_256_GCM_SHA384" "P-256" certificate key
   (lambda (port)
     (let* ((store (cl-tls-kit:make-tls13-ticket-store))
            (trust-anchor (%openssl-e2e-pem-certificate certificate))
            (groups (list #x001d #x0017)))
       (let ((first-driver
               (%openssl-e2e-driver
                "localhost" port provider #x1302 groups
                :trust-anchors (list trust-anchor) :ticket-store store
                :hostname nil)))
         (unwind-protect
              (progn
                (cl-tls-kit:tls13-client-driver-connect first-driver)
                (incf assertions)
                (check
                 (and (not (cl-tls-kit:tls13-client-driver-resumed-p first-driver))
                      (cl-tls-kit::tls13-client-driver-hello-retry-request-received
                       first-driver)
                      (= (cl-tls-kit::tls13-client-driver-suite first-driver) #x1302)
                      (eq (cl-tls-kit::tls13-client-driver-hash first-driver) :sha384))
                 "OpenSSL HRR selects SHA384 during a full handshake")
                (cl-tls-kit:tls13-client-driver-write
                 first-driver (%openssl-e2e-http-request))
                (incf assertions)
                (check (search "HTTP/1.0"
                               (map 'string (function code-char)
                                    (%openssl-e2e-read-application first-driver)))
                       "OpenSSL completes the SHA384 HRR handshake and sends a ticket")
                (incf assertions)
                (check (plusp (cl-tls-kit::%tls13-ticket-store-count store))
                       "SHA384 NewSessionTicket is stored for the next connection"))
           (cl-tls-kit:tls13-client-driver-close first-driver)))
       (let ((second-driver
               (%openssl-e2e-driver
                "localhost" port provider #x1302 groups
                :trust-anchors (list trust-anchor) :ticket-store store
                :hostname nil)))
         (unwind-protect
              (progn
                (cl-tls-kit:tls13-client-driver-connect second-driver)
                (incf assertions)
                (check
                 (and (cl-tls-kit:tls13-client-driver-resumed-p second-driver)
                      (cl-tls-kit::tls13-client-driver-hello-retry-request-received
                       second-driver)
                      (= (cl-tls-kit::tls13-client-driver-suite second-driver) #x1302)
                      (eq (cl-tls-kit::tls13-client-driver-hash second-driver) :sha384))
                 "OpenSSL resumes with a SHA384 binder after HRR")
                (cl-tls-kit:tls13-client-driver-write
                 second-driver (%openssl-e2e-http-request))
                (incf assertions)
                (check (search "HTTP/1.0"
                               (map 'string (function code-char)
                                    (%openssl-e2e-read-application second-driver)))
                       "resumed SHA384 HRR connection carries application data"))
           (cl-tls-kit:tls13-client-driver-close second-driver)))))
   :tickets t :stateless t)
  (incf selected))
           (incf selected)
           (%openssl-e2e-with-server
            openssl "TLS_AES_128_GCM_SHA256" "P-256" certificate key
            (lambda (port)
              (let ((driver (%openssl-e2e-driver
                             "127.0.0.1" port provider #x1301 '(#x001d #x0017)
                             :trust-anchors
                             (list (%openssl-e2e-pem-certificate certificate)))))
                (unwind-protect
                     (progn
                       (cl-tls-kit:tls13-client-driver-connect driver)
                       (incf assertions)
                       (check
                        (and
                         (eq (cl-tls-kit::tls13-client-driver-state driver)
                             :connected)
                         (cl-tls-kit::tls13-client-driver-hello-retry-request-received
                          driver))
                        "OpenSSL stateless HRR accepts the echoed cookie")
                       (incf assertions)
                       (check (string= (cl-tls-kit:tls13-client-driver-negotiated-alpn
                                        driver)
                                       "http/1.1")
                              "OpenSSL negotiates ALPN after HelloRetryRequest")
                       (let ((payload
                               (make-array 32768 :element-type '(unsigned-byte 8)
                                                 :initial-element 65)))
                         (loop for position from 511 below 32768 by 512
                               do (setf (aref payload position) 10))
                         (cl-tls-kit:tls13-client-driver-write driver payload))
                       (incf assertions)
                       (check (= (length (%openssl-e2e-read-application driver 32768))
                                 32768)
                              "OpenSSL receives an application write split above 16 KiB")
                       (cl-tls-kit:tls13-client-driver-close driver)
                       (incf assertions)
                       (check (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
                              "cl-tls-kit sends close_notify"))
                  (cl-tls-kit:tls13-client-driver-close driver))))
            :stateless t
            :reverse t)
           (%openssl-e2e-certificate openssl wrong-certificate wrong-key "wrong.local" 1)
           (%openssl-e2e-certificate openssl other-certificate other-key "other.local" 1)
           (%openssl-e2e-certificate openssl anchor-certificate anchor-key "localhost" 1 :ca t)
           (%openssl-e2e-certificate
            openssl (getf chain-material :first-certificate)
            (getf chain-material :first-key) "intermediate-one" 1
            :ca t :signer-certificate anchor-certificate :signer-key anchor-key)
           (%openssl-e2e-certificate
            openssl (getf chain-material :second-certificate)
            (getf chain-material :second-key) "intermediate-two" 1
            :ca t :signer-certificate (getf chain-material :first-certificate)
            :signer-key (getf chain-material :first-key))
           (%openssl-e2e-certificate
            openssl (getf chain-material :leaf-certificate)
            (getf chain-material :leaf-key) "localhost" 1
            :signer-certificate (getf chain-material :second-certificate)
            :signer-key (getf chain-material :second-key))
           (with-open-file (stream (getf chain-material :chain)
                                   :direction :output :if-exists :supersede)
             (write-string (uiop:read-file-string
                            (getf chain-material :first-certificate))
                           stream)
             (write-string (uiop:read-file-string
                            (getf chain-material :second-certificate))
                           stream))
           (%openssl-e2e-certificate openssl ecdsa-certificate ecdsa-key "localhost" 1
                                     :key-type :ecdsa)
           (incf selected)
           (%openssl-e2e-with-server
            openssl "TLS_AES_128_GCM_SHA256" "X25519"
            (getf chain-material :leaf-certificate)
            (getf chain-material :leaf-key)
            (lambda (port)
              (let ((driver (%openssl-e2e-driver
                             "127.0.0.1" port provider #x1301 '(#x001d)
                             :trust-anchors
                             (list (%openssl-e2e-pem-certificate
                                    anchor-certificate)))))
                (unwind-protect
                     (progn
                       (cl-tls-kit:tls13-client-driver-connect driver)
                       (incf assertions)
                       (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                                  :connected)
                              "TLS 1.3 builds an unordered intermediate chain without the root certificate"))
                  (cl-tls-kit:tls13-client-driver-close driver))))
            :certificate-chain (getf chain-material :chain))
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
      (ignore-errors (delete-file anchor-key))
      (ignore-errors (delete-file ecdsa-certificate))
      (ignore-errors (delete-file ecdsa-key))
      (dolist (key '(:first-certificate :first-key
                     :second-certificate :second-key
                     :leaf-certificate :leaf-key :chain))
        (ignore-errors (delete-file (getf chain-material key)))))))
