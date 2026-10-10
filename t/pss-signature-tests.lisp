(in-package #:cl-tls-kit/test)

(defun run-pss-signature-tests ()
  (let ((openssl (or (uiop:getenv "OPENSSL") "openssl"))
        (assertions 0)
        (directory nil)
        (names '("key.pem" "good256.pem" "good384.pem" "good512.pem"
                 "good256.der" "good384.der" "good512.der"
                 "bad-hash.tbs" "bad-hash.sig")))
    (labels ((check-pss (condition message)
               (incf assertions)
               (unless condition (error "PSS signature test failed: ~A" message)))
             (run-command (program arguments)
               (multiple-value-bind (output exit-code)
                   (%openssl-e2e-run program arguments)
                 (unless (zerop exit-code)
                   (error "PSS signature test command failed: ~A (exit ~D)"
                          program exit-code))
                 output))
             (path (name) (namestring (merge-pathnames name directory)))
             (bytes (name)
               (with-open-file (stream (path name) :element-type '(unsigned-byte 8))
                 (let ((result (make-array (file-length stream)
                                           :element-type '(unsigned-byte 8))))
                   (read-sequence result stream)
                   result)))
             (write-bytes (name data)
               (with-open-file (stream (path name) :direction :output
                                       :element-type '(unsigned-byte 8)
                                       :if-exists :error)
                 (write-sequence data stream)))
             (sequence-bytes (&rest values)
               (let ((content (apply #'concatenate '(vector (unsigned-byte 8)) values)))
                 (concatenate '(vector (unsigned-byte 8)) #(48)
                              (cl-tls-kit::%encode-length (length content)) content)))
             (parts (name)
               (cl-tls-kit.x509::%children
                (nth-value 0 (cl-tls-kit.x509::%read-der (bytes name)))))
             (raw (node) (cl-tls-kit.x509::der-raw node))
             (tbs (certificate)
               (cl-tls-kit.x509::x509-certificate-tbs-certificate certificate))
             (signature (certificate)
               (cl-tls-kit.x509::x509-certificate-signature certificate))
             (verified-signature (certificate issuer)
               (handler-case
                   (progn (cl-tls-kit::%verify-signature certificate issuer nil) t)
                 (cl-tls-kit:bad-signature () :bad-signature))))
      (unwind-protect
           (progn
             (setf directory
                   (uiop:ensure-directory-pathname
                    (string-trim '(#\Return #\Linefeed)
                                 (run-command
                                  "mktemp"
                                  (list "-d"
                                        (namestring
                                         (merge-pathnames "cl-tls-kit-pss.XXXXXXXX"
                                                          (uiop:temporary-directory))))))))
             (dolist (case '((256 32) (384 48) (512 64)))
               (destructuring-bind (hash salt) case
                 (let ((pem (format nil "good~D.pem" hash))
                       (der (format nil "good~D.der" hash)))
                   (run-command
                    openssl
                    (append
                     (list "req" "-new" "-x509" "-nodes" "-days" "2"
                           "-subj" "/CN=pss-test.invalid")
                     (if (= hash 256)
                         (list "-newkey" "rsa:2048" "-keyout" (path "key.pem"))
                         (list "-key" (path "key.pem")))
                     (list "-out" (path pem) (format nil "-sha~D" hash)
                           "-sigopt" "rsa_padding_mode:pss" "-sigopt"
                           (format nil "rsa_pss_saltlen:~D" salt))))
                   (run-command openssl (list "x509" "-in" (path pem)
                                              "-outform" "DER" "-out" (path der))))))
             (let* ((parts256 (parts "good256.der"))
                    (algorithm384 (raw (second (parts "good384.der"))))
                    (fields (mapcar #'raw
                                    (cl-tls-kit.x509::%children (first parts256))))
                    (c256 (cl-tls-kit.x509:parse-certificate-der (bytes "good256.der")))
                    (c384 (cl-tls-kit.x509:parse-certificate-der (bytes "good384.der")))
                    (c512 (cl-tls-kit.x509:parse-certificate-der (bytes "good512.der")))
                    (key (cl-tls-kit::%crypto-public-key
                          (cl-tls-kit.x509:x509-certificate-public-key c256)))
                    (verify (%openssl-e2e-call "VERIFY-SIGNATURE")))
               ;; Sign the SHA384-declared TBS using SHA256 to catch fixed-hash verification.
               (setf (nth (if (= (aref (first fields) 0) #xa0) 2 1) fields)
                     algorithm384)
               (write-bytes "bad-hash.tbs" (apply #'sequence-bytes fields))
               (run-command openssl
                            (list "dgst" "-sha256" "-sign" (path "key.pem")
                                  "-sigopt" "rsa_padding_mode:pss"
                                  "-sigopt" "rsa_pss_saltlen:32"
                                  "-out" (path "bad-hash.sig") (path "bad-hash.tbs")))
               (let ((bad (cl-tls-kit.x509:parse-certificate-der
                           (sequence-bytes
                            (bytes "bad-hash.tbs") algorithm384
                            (der-encode (make-der-bit-string (bytes "bad-hash.sig")))))))
                 (dolist (case (list (list c256 :rsa-pss-rsae-sha256)
                                    (list c384 :rsa-pss-rsae-sha384)
                                    (list c512 :rsa-pss-rsae-sha512)))
                   (destructuring-bind (certificate scheme) case
                     (check-pss (funcall verify scheme key (tbs certificate)
                                        (signature certificate))
                                "known-good signature verifies with the real provider")))
                 (check-pss (not (funcall verify :rsa-pss-rsae-sha384 key
                                         (tbs bad) (signature bad)))
                            "wrong declared hash fails the real provider")
                 (check-pss (funcall verify :rsa-pss-rsae-sha256 key
                                     (tbs bad) (signature bad))
                            "negative control has a valid SHA256 signature")
                 (dolist (certificate (list c256 c384 c512))
                   (check-pss (eq t (verified-signature certificate c256))
                              "TLS verifies the declared known-good PSS scheme"))
                 (check-pss (eq :bad-signature (verified-signature bad c256))
                            "TLS rejects the declared SHA384/actual SHA256 signature")
                 (check-pss
                  (handler-case
                      (progn
                        (cl-tls-kit.x509:parse-certificate-der
                         (sequence-bytes (raw (first parts256)) algorithm384
                                         (raw (third parts256))))
                        nil)
                    (cl-tls-kit.x509:x509-error () t))
                  "different TBS/outer PSS parameters reject despite equal OIDs")
                 (dolist (case (list (list c256 :sha256 32) (list c384 :sha384 48)
                                    (list c512 :sha512 64)))
                   (destructuring-bind (certificate hash salt) case
                     (check-pss
                      (equal (cl-tls-kit.x509:x509-certificate-signature-parameters certificate)
                             (list :hash hash :mgf-hash hash
                                   :salt-length salt :trailer-field 1))
                      "actual DER retains canonical PSS parameters")))))
             (format t "PSS signature assertions: ~D~%" assertions)
             assertions)
        (when directory
          (dolist (name names)
            (let ((file (merge-pathnames name directory)))
              (when (probe-file file) (delete-file file))))
          (uiop:delete-empty-directory directory))))))
