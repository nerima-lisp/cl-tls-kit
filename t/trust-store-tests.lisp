(in-package #:cl-tls-kit/test)

(defun %trust-store-test-certificate-pem ()
  (let* ((algorithm (make-der-sequence (make-der-oid '(1 3 101 112))))
         (key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (signature (make-array 64 :element-type '(unsigned-byte 8) :initial-element 9))
         (time-node (lambda (value)
                      (make-der-node :tag #x17
                                     :value (map '(vector (unsigned-byte 8))
                                                 #'char-code value))))
         (tbs (make-der-sequence
               (make-der-integer 1)
               algorithm
               (make-der-sequence)
               (make-der-sequence (funcall time-node "250101000000Z")
                                  (funcall time-node "260101000000Z"))
               (make-der-sequence)
               (make-der-sequence algorithm (make-der-bit-string key)))))
    (pem-encode
     (make-pem-block
      :label "CERTIFICATE"
      :der (der-encode
            (make-der-sequence tbs algorithm (make-der-bit-string signature)))))))

(defun %trust-store-test-write-file (contents)
  (loop repeat 20
        for path = (merge-pathnames
                    (format nil "cl-tls-kit-ca-~D.pem" (random 1000000000))
                    (uiop:temporary-directory))
        for stream = (open path :direction :output :if-exists nil
                           :if-does-not-exist :create)
        when stream
          do (let ((complete nil))
               (unwind-protect
                    (progn
                      (write-string contents stream)
                      (finish-output stream)
                      (setf complete t)
                      (return-from %trust-store-test-write-file path))
                 (close stream)
                 (unless complete (ignore-errors (delete-file path)))))
        finally (error "Could not create trust-store test file")))

(defun %trust-store-test-errors-p (thunk)
  (handler-case
      (progn (funcall thunk) nil)
    (trust-store-error () t)
    (error () nil)))

(defun run-trust-store-tests ()
  (let* ((certificate-pem (%trust-store-test-certificate-pem))
         (explicit-pem (format nil "~%~A" certificate-pem))
         (ssl-pem certificate-pem)
         (nix-pem (format nil "~A~%~%" certificate-pem))
         (explicit-path (%trust-store-test-write-file explicit-pem))
         (ssl-path (%trust-store-test-write-file ssl-pem))
         (nix-path (%trust-store-test-write-file nix-pem))
         (malformed-path
           (%trust-store-test-write-file
            "-----BEGIN CERTIFICATE-----~%!!!!~%-----END CERTIFICATE-----~%")))
    (unwind-protect
         (progn
           (check (string= explicit-pem
                           (load-trust-store-pem
                            :ca-file explicit-path
                            :environment (lambda (name)
                                           (cond ((string= name "SSL_CERT_FILE") ssl-path)
                                                 ((string= name "NIX_SSL_CERT_FILE") nix-path)))))
                  "explicit CA file takes precedence")
           (let ((environment (lambda (name)
                                (cond ((string= name "SSL_CERT_FILE") ssl-path)
                                      ((string= name "NIX_SSL_CERT_FILE") nix-path)))))
             (check (string= ssl-pem (load-trust-store-pem :environment environment))
                    "SSL_CERT_FILE takes precedence over NIX_SSL_CERT_FILE")
             (check (equal ssl-path (default-trust-store-path environment))
                    "default path keeps SSL_CERT_FILE precedence")
             (check (equal ssl-path (load-trust-store :environment environment))
                    "load-trust-store keeps its path return contract"))
           (check (string= nix-pem
                           (load-trust-store-pem
                            :environment (lambda (name)
                                           (when (string= name "NIX_SSL_CERT_FILE") nix-path))))
                  "NIX_SSL_CERT_FILE is used when SSL_CERT_FILE is unset")
           (let ((seen-argv nil))
             (check (string= certificate-pem
                             (cl-tls-kit::%load-trust-store-pem
                              :environment (lambda (name) (declare (ignore name)) nil)
                              :platform :macos
                              :command-runner (lambda (argv)
                                                (setf seen-argv argv)
                                                (values certificate-pem "" 0))))
                    "System Roots Keychain export returns validated PEM")
             (check (equal seen-argv
                           '("/usr/bin/security" "find-certificate" "-a" "-p"
                             "/System/Library/Keychains/SystemRootCertificates.keychain"))
                    "System Roots Keychain uses the required argv"))
           (let ((cl-tls-kit:*default-ca-paths* (list ssl-path)))
             (check (string= ssl-pem
                             (cl-tls-kit::%load-trust-store-pem
                              :environment (lambda (name) (declare (ignore name)) nil)
                              :platform :linux
                              :command-runner (lambda (argv)
                                                (declare (ignore argv))
                                                (error "Unexpected Keychain command"))))
                    "non-macOS defaults use the existing file search"))
           (let ((cl-tls-kit:*default-ca-paths* (list ssl-path)))
             (check (%trust-store-test-errors-p
                     (lambda ()
                       (cl-tls-kit::%load-trust-store-pem
                        :environment (lambda (name) (declare (ignore name)) nil)
                        :platform :macos
                        :command-runner (lambda (argv)
                                          (declare (ignore argv))
                                          (values certificate-pem "failure" 1)))))
                    "Keychain command failure signals trust-store-error"))
           (check (%trust-store-test-errors-p
                   (lambda ()
                     (cl-tls-kit::%load-trust-store-pem
                      :environment (lambda (name) (declare (ignore name)) nil)
                      :platform :macos
                      :command-runner (lambda (argv)
                                        (declare (ignore argv))
                                        (values "" "" 0)))))
                  "empty Keychain output signals trust-store-error")
           (check (%trust-store-test-errors-p
                   (lambda () (load-trust-store-pem :ca-file malformed-path)))
                  "malformed PEM signals trust-store-error")
           (check (%trust-store-test-errors-p
                   (lambda ()
                     (cl-tls-kit::%load-trust-store-pem
                      :environment (lambda (name) (declare (ignore name)) nil)
                      :platform :macos
                      :command-runner
                      (lambda (argv)
                        (declare (ignore argv))
                        (values (pem-encode (make-pem-block :label "OTHER" :der #(1)))
                                "" 0)))))
                  "PEM without certificates signals trust-store-error")
           (check
             (let ((opaque-pem
                    (pem-encode
                     (make-pem-block :label "CERTIFICATE" :der #(1 2 3)))))
               (string=
                opaque-pem
                (cl-tls-kit::%load-trust-store-pem
                 :environment (lambda (name) (declare (ignore name)) nil)
                 :platform :macos
                 :command-runner
                 (lambda (argv)
                   (declare (ignore argv))
                   (values opaque-pem "" 0)))))
             "PEM framing validation leaves certificate parsing to consumers")
           (check (%trust-store-test-errors-p
                   (lambda ()
                     (cl-tls-kit::%load-trust-store-pem
                      :environment (lambda (name) (declare (ignore name)) nil)
                      :platform :macos
                      :command-runner (lambda (argv)
                                        (declare (ignore argv))
                                        (values (format nil "~Ajunk" certificate-pem) "" 0)))))
                  "Keychain output with trailing junk signals trust-store-error")
           (let* ((oversized-pem
                    (make-string (1+ (* 16 1024 1024)) :initial-element #\A))
                   (oversized-path (%trust-store-test-write-file oversized-pem)))
             (unwind-protect
                  (progn
                    (check (%trust-store-test-errors-p
                            (lambda ()
                              (load-trust-store-pem :ca-file oversized-path)))
                           "CA file larger than 16 MiB signals trust-store-error")
                    (check (%trust-store-test-errors-p
                            (lambda ()
                              (cl-tls-kit::%load-trust-store-pem
                               :environment (lambda (name) (declare (ignore name)) nil)
                               :platform :macos
                               :command-runner (lambda (argv)
                                                 (declare (ignore argv))
                                                 (values oversized-pem "" 0)))))
                           "PEM larger than 16 MiB signals trust-store-error"))
               (when (probe-file oversized-path)
                 (delete-file oversized-path))))
           (let* ((pem-512
                    (with-output-to-string (output)
                      (dotimes (index 512)
                        (write-string certificate-pem output))))
                   (pem-513 (concatenate 'string pem-512 certificate-pem)))
             (check
              (string=
               pem-512
               (cl-tls-kit::%load-trust-store-pem
                :environment (lambda (name) (declare (ignore name)) nil)
                :platform :macos
                :command-runner (lambda (argv)
                                  (declare (ignore argv))
                                  (values pem-512 "" 0))))
              "512 certificate PEM blocks are accepted")
             (check (%trust-store-test-errors-p
                     (lambda ()
                       (cl-tls-kit::%load-trust-store-pem
                        :environment (lambda (name) (declare (ignore name)) nil)
                        :platform :macos
                        :command-runner (lambda (argv)
                                          (declare (ignore argv))
                                          (values pem-513 "" 0)))))
                    "more than 512 certificate PEM blocks signal trust-store-error"))
             t)
      (dolist (path (list explicit-path ssl-path nix-path malformed-path))
        (when (probe-file path) (delete-file path))))))