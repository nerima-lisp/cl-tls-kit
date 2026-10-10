(in-package #:cl-tls-kit/test)

(defun run-openssl-chain-tests (openssl provider)
  (multiple-value-bind (output exit-code)
      (%openssl-e2e-run
       "mktemp" (list "-d" (namestring
                            (merge-pathnames "cl-tls-chain.XXXXXXXX"
                                             (uiop:temporary-directory)))))
    (unless (zerop exit-code) (error "Cannot create TLS chain fixture directory"))
    (let* ((directory (uiop:ensure-directory-pathname
                       (string-trim '(#\Space #\Newline #\Return) output)))
           (files nil)
           (selected 0)
           (assertions 0))
      (labels ((path (name)
                 (let ((file (merge-pathnames name directory)))
                   (pushnew file files :test #'equal)
                   (namestring file)))
               (run (&rest arguments)
                 (multiple-value-bind (result status)
                     (%openssl-e2e-run openssl arguments)
                   (declare (ignore result))
                   (unless (zerop status)
                     (error "OpenSSL TLS chain fixture command failed"))))
               (verify (condition message)
                 (incf assertions)
                 (check condition message))
               (request (name subject &rest extensions)
                 (apply #'run
                        (append (list "req" "-new" "-newkey" "rsa:2048" "-nodes"
                                      "-subj" subject "-keyout" (path (format nil "~A.key" name))
                                      "-out" (path (format nil "~A.csr" name)))
                                (loop for extension in extensions
                                      append (list "-addext" extension)))))
               (sign (name issuer serial digest)
                 (run "x509" "-req" "-in" (path (format nil "~A.csr" name))
                      "-CA" (path (format nil "~A.crt" issuer))
                      "-CAkey" (path (format nil "~A.key" issuer))
                      "-set_serial" serial "-days" "1" "-copy_extensions" "copy"
                      digest "-sigopt" "rsa_padding_mode:pss"
                      "-sigopt" "rsa_pss_saltlen:digest"
                      "-out" (path (format nil "~A.crt" name)))))
        (unwind-protect
             (progn
               (%openssl-e2e-certificate openssl (path "root.crt") (path "root.key")
                                         "TLS test root" 1 :ca t)
               (request "intermediate" "/CN=TLS test intermediate"
                        "basicConstraints=critical,CA:TRUE,pathlen:0"
                        "keyUsage=critical,keyCertSign,cRLSign")
               (sign "intermediate" "root" "2" "-sha512")
               (loop for digest in '("-sha256" "-sha384" "-sha512")
                     for serial from 3
                     for name = (format nil "leaf~D" serial)
                     do (request name "/CN=localhost"
                                 "subjectAltName=DNS:localhost"
                                 "basicConstraints=critical,CA:FALSE"
                                 "keyUsage=critical,digitalSignature"
                                 "extendedKeyUsage=serverAuth")
                        (sign name "intermediate" (princ-to-string serial) digest)
                        (incf selected)
                        (multiple-value-bind (result status)
                            (%openssl-e2e-run
                             openssl (list "verify" "-CAfile" (path "root.crt")
                                           "-untrusted" (path "intermediate.crt")
                                           "-verify_hostname" "localhost"
                                           (path (format nil "~A.crt" name))))
                          (declare (ignore result))
                          (verify (zerop status) "OpenSSL accepts the generated PSS chain"))
                        (%openssl-e2e-with-server
                         openssl "TLS_AES_128_GCM_SHA256" "X25519"
                         (path (format nil "~A.crt" name)) (path (format nil "~A.key" name))
                         (lambda (port)
                           (let ((driver (%openssl-e2e-driver
                                          "127.0.0.1" port provider #x1301 '(#x001d)
                                          :trust-anchors
                                          (list (%openssl-e2e-pem-certificate (path "root.crt"))))))
                             (unwind-protect
                                  (progn
                                    (cl-tls-kit:tls13-client-driver-connect driver)
                                    (verify (eq (cl-tls-kit::tls13-client-driver-state driver)
                                                :connected)
                                            "TLS validates a PSS chain with the root omitted")
                                    (cl-tls-kit:tls13-client-driver-write
                                     driver (%openssl-e2e-http-request))
                                    (verify (search "HTTP/1.0"
                                                    (map 'string #'code-char
                                                         (%openssl-e2e-read-application driver)))
                                            "The verified PSS chain carries application data"))
                               (cl-tls-kit:tls13-client-driver-close driver))))
                         :chain (path "intermediate.crt")))
               (format t "OpenSSL chain tests: selected: ~D; assertions: ~D~%"
                       selected assertions)
               (values selected assertions))
          (dolist (file files) (when (probe-file file) (delete-file file)))
          (uiop:delete-empty-directory directory))))))
