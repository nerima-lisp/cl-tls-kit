(in-package #:cl-tls-kit/test)

(defun run-client-driver-tests ()
  (run-client-driver-lifecycle-tests)
  (run-client-driver-alpn-tests)
  (run-client-driver-order-tests)
  (let* ((sent nil)
         (provider
           (cl-tls-kit::%make-tls13-crypto-provider
            (lambda (hash salt ikm)
              (declare (ignore salt ikm))
              (make-array (if (eq hash :sha384) 48 32)
                          :element-type '(unsigned-byte 8)))
            (lambda (hash secret info length)
              (declare (ignore hash secret info))
              (make-array length :element-type '(unsigned-byte 8)))
            (lambda (hash) (if (eq hash :sha384) 48 32))
            (lambda (hash bytes)
              (declare (ignore bytes))
              (make-array (if (eq hash :sha384) 48 32)
                          :element-type '(unsigned-byte 8)))
            (lambda (hash key bytes)
              (declare (ignore hash key))
              (make-array 32 :element-type '(unsigned-byte 8)))
            (lambda (algorithm key nonce plaintext aad)
              (declare (ignore algorithm key nonce aad))
              (concatenate '(vector (unsigned-byte 8)) plaintext #(0 0 0 0 0 0 0 0
                                                                    0 0 0 0 0 0 0 0)))
            (lambda (algorithm key nonce ciphertext aad)
              (declare (ignore algorithm key nonce aad))
              (subseq ciphertext 0 (- (length ciphertext) 16)))
            (lambda (left right) (equalp left right))))
         (key-exchange
           (list :random
                 (lambda (length)
                   (make-array length :element-type '(unsigned-byte 8)
                               :initial-element 7))
                 :generate
                 (lambda (group)
                   (declare (ignore group))
                   (values (make-array 32 :element-type '(unsigned-byte 8))
                           (make-array 32 :element-type '(unsigned-byte 8))))
                 :shared-secret
                 (lambda (group private public)
                   (declare (ignore group private public))
                   (make-array 32 :element-type '(unsigned-byte 8)))))
         (driver
           (cl-tls-kit:make-tls13-client-driver
            :provider provider
            :key-exchange key-exchange
            :hostname "example.test"
            :alpn '("h2")
            :on-send (lambda (ignored wire)
                       (declare (ignore ignored))
                       (push wire sent)))))
    (run-client-driver-verification-mode-tests provider key-exchange)
    (run-client-driver-hrr-tests provider key-exchange)
    (cl-tls-kit:tls13-client-driver-start driver)
    (check (null (cl-tls-kit:tls13-client-driver-negotiated-alpn driver))
           "driver exposes no negotiated ALPN before EncryptedExtensions")
    (check (= (length sent) 1) "driver emits ClientHello")
    (let ((hello (decode-handshake (first sent))))
      (check (typep hello 'tls13-client-hello) "driver emits a ClientHello message")
      (check (find 0 (tls13-client-hello-extensions hello)
                   :key #'tls-extension-type)
             "driver includes SNI")
      (check (find 51 (tls13-client-hello-extensions hello)
                   :key #'tls-extension-type)
             "driver includes key_share")
      (check (not (every #'zerop (tls13-client-hello-random hello)))
             "driver ClientHello random uses CSPRNG")
      (check (not (every #'zerop (tls13-client-hello-session-id hello)))
             "driver ClientHello session ID uses CSPRNG"))
    (let ((explicit-driver
            (cl-tls-kit:make-tls13-client-driver
             :provider provider :key-exchange key-exchange
             :cipher-suites #( #x1305 #x1301)
             :on-send (lambda (ignored wire)
                        (declare (ignore ignored))
                        (setf sent (list wire))))))
      (cl-tls-kit:tls13-client-driver-start explicit-driver)
      (let ((hello (decode-handshake (first sent))))
        (check (not (member #x1305
                            (coerce (tls13-client-hello-cipher-suites hello)
                                    'list)))
               "ClientHello omits unsupported CCM-8")))
    (let ((bad-suite (make-tls13-server-hello
                      #x0303 (make-array 32 :element-type '(unsigned-byte 8)) #()
                      #x1305 (list (make-tls-extension 43 #(3 4))
                                   (make-tls-extension
                                    51 (encode-key-share-server-extension
                                        #x001d #(1 2)))))))
      (check (handler-case
                 (progn (tls13-client-driver-step
                         driver (encode-handshake 2 bad-suite)) nil)
               (tls13-client-driver-error (condition)
                 (eq (tls13-client-driver-error-reason condition)
                     :unoffered-cipher-suite))
               (tls13-negotiation-error (condition)
                 (and (eq (cl-tls-kit::tls-client-error-reason condition) :cipher-suite)
                      (eq (tls13-negotiation-error-field condition)
                          :cipher-suite))))
             "driver rejects an unoffered cipher suite"))
    (let ((bad-group (make-tls13-server-hello
                      #x0303 (make-array 32 :element-type '(unsigned-byte 8)) #()
                      #x1301 (list (make-tls-extension 43 #(3 4))
                                   (make-tls-extension
                                    51 (encode-key-share-server-extension
                                        #x0019 #(1 2)))))))
      (check (handler-case
                 (progn (tls13-client-driver-step
                         driver (encode-handshake 2 bad-group)) nil)
               (tls13-client-driver-error (condition)
                 (eq (tls13-client-driver-error-reason condition)
                     :unrequested-key-share-group)))
             "driver rejects an unrequested key-share group"))
    (let ((downgrade (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
      (replace downgrade #(68 79 87 78 71 82 68 1) :start1 24)
      (let ((bad-random (make-tls13-server-hello
                         #x0303 downgrade #() #x1301
                         (list (make-tls-extension 43 #(3 4))
                               (make-tls-extension
                                51 (encode-key-share-server-extension
                                    #x001d #(1 2)))))))
        (check (handler-case
                   (progn (tls13-client-driver-step
                           driver (encode-handshake 2 bad-random)) nil)
                 (tls13-client-driver-error (condition)
                   (eq (tls13-client-driver-error-reason condition)
                       :downgrade-sentinel)))
               "driver rejects a downgrade sentinel")))
    (let ((new-driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :new
             :transport-read (lambda (ignored)
                               (declare (ignore ignored))
                               #(20 3 3 0 1 1)))))
      (check (handler-case
                 (progn (tls13-client-driver-read-record new-driver) nil)
               (tls13-client-driver-error (condition)
                 (eq (tls13-client-driver-error-reason condition)
                     :unexpected-message)))
             "driver rejects CCS outside the compatibility window"))
    (let ((records (list #(20 3 1 0 1 1)
                         #(20 3 1 0 1 1))))
      (let ((allowed-driver
              (cl-tls-kit::%make-tls13-client-driver
               :state :awaiting-encrypted-extensions
               :compatibility-ccs-flight :server-hello
               :transport-read (lambda (ignored)
                                 (declare (ignore ignored))
                                 (pop records)))))
        (check (null (tls13-client-driver-read-record allowed-driver))
               "driver ignores the first valid compatibility CCS")
        (setf (cl-tls-kit::tls13-client-driver-state allowed-driver)
              :awaiting-certificate)
        (check (handler-case
                   (progn (tls13-client-driver-read-record allowed-driver) nil)
                 (tls13-client-driver-error (condition)
                   (eq (tls13-client-driver-error-reason condition)
                       :unexpected-message)))
               "driver rejects a repeated compatibility CCS")))
    (let ((records (list #(20 3 1 0 1 1)
                         #(20 3 1 0 1 1)))
          (hrr-driver driver))
      (setf (cl-tls-kit::tls13-client-driver-state hrr-driver)
            :awaiting-server-hello
            (cl-tls-kit::tls13-client-driver-compatibility-ccs-flight hrr-driver)
            :server-hello
            (cl-tls-kit::tls13-client-driver-compatibility-ccs-count hrr-driver)
            0
            (cl-tls-kit::tls13-client-driver-transport-read hrr-driver)
            (lambda (ignored)
              (declare (ignore ignored))
              (pop records)))
      (check (null (tls13-client-driver-read-record hrr-driver))
             "driver accepts one compatibility CCS after ServerHello")
      (tls13-client-driver-step
       hrr-driver
       (let ((body (encode-hello-retry-request
                    (make-tls13-hello-retry-request #x0303 #x0017 '()))))
         (concatenate '(vector (unsigned-byte 8))
                      #(2) (cl-tls-kit::%u24 (length body)) body)))
      (check (null (tls13-client-driver-read-record hrr-driver))
             "driver accepts one compatibility CCS after HRR"))
    (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 9))
           (sender (cl-tls-kit::make-tls13-traffic-state
                    provider :sha256 :aes-128-gcm secret 16 12))
           (receiver (cl-tls-kit::make-tls13-traffic-state
                      provider :sha256 :aes-128-gcm secret 16 12))
           (wire (cl-tls-kit::encrypt-tls13-traffic-record
                  (make-tls-plaintext cl-tls-kit::+tls-content-type-change-cipher-spec+
                                      #(1))
                  sender))
           (encrypted-ccs-driver
             (cl-tls-kit::%make-tls13-client-driver
              :state :awaiting-encrypted-extensions
              :handshake-read-state receiver
              :transport-read (lambda (ignored)
                                (declare (ignore ignored))
                                wire))))
      (check (handler-case
                 (progn (tls13-client-driver-read-record encrypted-ccs-driver) nil)
               (tls13-client-driver-error (condition)
                 (eq (tls13-client-driver-error-reason condition)
                     :unexpected-message)))
             "driver rejects an encrypted-boundary CCS"))
    (dolist (fragment '(#() #(0) #(1 1)))
      (let ((bad-driver
              (cl-tls-kit::%make-tls13-client-driver
               :state :awaiting-encrypted-extensions
               :transport-read (lambda (ignored)
                                 (declare (ignore ignored))
                                 (encode-tls-plaintext
                                  (make-tls-plaintext
                                   cl-tls-kit::+tls-content-type-change-cipher-spec+
                                   fragment))))))
        (check (handler-case
                   (progn (tls13-client-driver-read-record bad-driver) nil)
                 (tls13-client-driver-error (condition)
                   (eq (tls13-client-driver-error-reason condition)
                       :unexpected-message)))
               "driver rejects malformed compatibility CCS")))
    (let ((limit cl-tls-kit::+tls13-max-handshake-body-length+))
      (flet ((header (length)
               (vector 1 (ldb (byte 8 16) length)
                       (ldb (byte 8 8) length)
                       (ldb (byte 8 0) length))))
        (let ((boundary-driver
                (cl-tls-kit::%make-tls13-client-driver
                 :state :awaiting-server-hello)))
          (cl-tls-kit::%driver-feed-handshake boundary-driver
                                               (concatenate 'vector
                                                            (header limit) #(0)))
          (check (= (length (cl-tls-kit::tls13-client-driver-pending-handshake
                             boundary-driver))
                    5)
                 "handshake body limit accepts the exact boundary"))
        (let ((oversized-driver
                (cl-tls-kit::%make-tls13-client-driver
                 :state :awaiting-server-hello)))
          (check (handler-case
                     (progn (cl-tls-kit::%driver-feed-handshake
                             oversized-driver (header (1+ limit))) nil)
                   (tls13-client-driver-error (condition)
                     (eq (tls13-client-driver-error-reason condition)
                         :decode-error)))
                 "handshake body limit rejects one byte over the boundary"))
        ))
    (let* ((ticket (make-tls13-new-session-ticket
                    1 #() (make-array 60000 :element-type '(unsigned-byte 8)
                                       :initial-element 3)
                    (list (make-tls-extension
                           1 (make-array 60000 :element-type '(unsigned-byte 8)
                                         :initial-element 4)))
                    0))
           (message (encode-handshake 4 ticket))
           (bytes (apply #'concatenate '(vector (unsigned-byte 8))
                         (loop repeat 9 collect message)))
           (driver (cl-tls-kit::%make-tls13-client-driver :state :connected)))
      (check (> (length bytes) (+ 4 cl-tls-kit::+tls13-max-handshake-body-length+))
             "concatenated handshake input crosses the buffer policy limit")
      (check (handler-case
                 (progn (cl-tls-kit::%driver-feed-handshake driver bytes) t)
               (tls13-client-driver-error () nil))
             "driver processes complete messages before checking the next message")
      (check (zerop (length (cl-tls-kit::tls13-client-driver-pending-handshake driver)))
             "driver drains concatenated complete handshake messages"))
    (let* ((body-length (1+ cl-tls-kit::+tls13-max-handshake-body-length+))
           (header (vector 1 (ldb (byte 8 16) body-length)
                           (ldb (byte 8 8) body-length)
                           (ldb (byte 8 0) body-length)))
           (fragments (cons #(1 #x10)
                            (loop repeat 65
                                  collect (make-array 16384
                                                      :element-type '(unsigned-byte 8)
                                                      :initial-element 0))))
           (records (loop for fragment in fragments
                          collect (encode-tls-plaintext
                                   (make-tls-plaintext
                                    cl-tls-kit::+tls-content-type-handshake+
                                    fragment))))
           (driver (cl-tls-kit::%make-tls13-client-driver
                    :state :awaiting-server-hello
                    :transport-read (lambda (ignored)
                                      (declare (ignore ignored))
                                      (pop records)))))
      (setf (first records) (encode-tls-plaintext
                             (make-tls-plaintext
                              cl-tls-kit::+tls-content-type-handshake+
                              (concatenate 'vector header #(0)))))
      (check (handler-case
                 (loop while records
                       do (tls13-client-driver-read-record driver))
                 (tls13-client-driver-error (condition)
                   (eq (tls13-client-driver-error-reason condition)
                       :decode-error)))
             "public record path rejects oversized fragmented handshake"))
    (when (uiop:getenv "OPENSSL")
      (multiple-value-bind (directory-output error-output exit-code)
          (uiop:run-program '("mktemp" "-d") :output :string :error-output :string
                            :ignore-error-status t)
        (declare (ignore error-output))
        (check (zerop exit-code) "mktemp creates a unique certificate directory")
        (let* ((directory (pathname
                           (format nil "~A/"
                                   (string-right-trim '(#\Newline #\Return #\Space #\Tab)
                                                      directory-output))))
               (root-path (namestring (merge-pathnames "root.pem" directory)))
               (root-key-path (namestring (merge-pathnames "root.key" directory)))
               (intermediate-path (namestring (merge-pathnames "intermediate.pem" directory)))
               (intermediate-key-path (namestring (merge-pathnames "intermediate.key" directory)))
               (intermediate-csr-path (namestring (merge-pathnames "intermediate.csr" directory)))
               (intermediate-ext-path (namestring (merge-pathnames "intermediate.ext" directory)))
               (leaf-path (namestring (merge-pathnames "leaf.pem" directory)))
               (leaf-key-path (namestring (merge-pathnames "leaf.key" directory)))
               (leaf-csr-path (namestring (merge-pathnames "leaf.csr" directory)))
               (leaf-ext-path (namestring (merge-pathnames "leaf.ext" directory))))
          (unwind-protect
               (let ((openssl (or (uiop:getenv "OPENSSL") "openssl")))
          (labels ((run (arguments)
                     (multiple-value-bind (output error-output exit-code)
                         (uiop:run-program (cons openssl arguments)
                                           :output :string :error-output :string
                                           :ignore-error-status t)
                       (declare (ignore output error-output))
                       (check (zerop exit-code)
                              "OpenSSL generates the real certificate chain")))
                   (write-file (path contents)
                     (with-open-file (stream path :direction :output :if-exists :supersede)
                       (write-string contents stream)))
                   (der (path)
                     (cl-tls-kit:pem-block-der
                      (first (cl-tls-kit:pem-decode
                              (uiop:read-file-string path))))))
            (write-file intermediate-ext-path
                   (format nil "[v3_ca]~%basicConstraints=critical,CA:TRUE,pathlen:0~%keyUsage=critical,keyCertSign,cRLSign~%subjectKeyIdentifier=hash~%authorityKeyIdentifier=keyid,issuer~%"))
            (write-file leaf-ext-path
                   (format nil "[v3_leaf]~%basicConstraints=critical,CA:FALSE~%keyUsage=critical,digitalSignature~%extendedKeyUsage=serverAuth~%subjectAltName=DNS:example.test~%subjectKeyIdentifier=hash~%authorityKeyIdentifier=keyid,issuer~%"))
            (run (list "req" "-x509" "-newkey" "rsa:2048" "-nodes"
                       "-days" "1" "-subj" "/CN=R7 Root"
                       "-addext" "basicConstraints=critical,CA:TRUE,pathlen:1"
                       "-addext" "keyUsage=critical,keyCertSign,cRLSign"
                       "-keyout" root-key-path "-out" root-path))
            (run (list "req" "-new" "-newkey" "rsa:2048" "-nodes"
                       "-subj" "/CN=R7 Intermediate"
                       "-keyout" intermediate-key-path "-out" intermediate-csr-path))
            (run (list "x509" "-req" "-in" intermediate-csr-path
                       "-CA" root-path "-CAkey" root-key-path "-set_serial" "2"
                       "-days" "1" "-extfile" intermediate-ext-path "-extensions" "v3_ca"
                       "-out" intermediate-path))
            (run (list "req" "-new" "-newkey" "rsa:2048" "-nodes"
                       "-subj" "/CN=example.test"
                       "-keyout" leaf-key-path "-out" leaf-csr-path))
            (run (list "x509" "-req" "-in" leaf-csr-path
                       "-CA" intermediate-path "-CAkey" intermediate-key-path "-set_serial" "3"
                       "-days" "1" "-extfile" leaf-ext-path "-extensions" "v3_leaf"
                       "-out" leaf-path))
            (let* ((root-der (der root-path))
                   (intermediate-der (der intermediate-path))
                   (leaf-der (der leaf-path))
                   (root (cl-tls-kit.x509:parse-certificate-der root-der))
                   (leaf (cl-tls-kit.x509:parse-certificate-der leaf-der))
               (message (make-tls13-certificate
                         #() (list (make-tls13-certificate-entry leaf-der '())
                                   (make-tls13-certificate-entry intermediate-der '())
                                   (make-tls13-certificate-entry root-der '()))))
               (wire (encode-handshake 11 message))
               (records (loop for start from 0 below (length wire) by 16380
                              for end = (min (length wire) (+ start 16380))
                              collect (encode-tls-plaintext
                                       (make-tls-plaintext
                                        cl-tls-kit::+tls-content-type-handshake+
                                        (subseq wire start end)))))
               (driver (cl-tls-kit::%make-tls13-client-driver
                        :state :awaiting-certificate
                        :trust-anchors (list root)
                        :now (1+ (max (cl-tls-kit.x509:x509-certificate-not-before root)
                                      (cl-tls-kit.x509:x509-certificate-not-before leaf)))
                        :transport-read (lambda (ignored)
                                          (declare (ignore ignored))
                                          (pop records)))))
          (check (> (length wire) 1000)
                 "certificate fixture contains the real three-certificate chain")
          (check (< (length wire) cl-tls-kit::+tls13-max-handshake-body-length+)
                 "certificate fixture stays below the handshake limit")
          (loop while records do (tls13-client-driver-read-record driver))
          (run-client-driver-real-verification-mode-tests root leaf wire)
                  (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                             :awaiting-certificate-verify)
                         "public record path accepts a real leaf-intermediate-root chain"))))
            (dolist (path (list root-path root-key-path intermediate-path intermediate-key-path
                                 intermediate-csr-path intermediate-ext-path leaf-path leaf-key-path
                                 leaf-csr-path leaf-ext-path))
              (ignore-errors (delete-file path)))
            (ignore-errors (uiop:delete-directory-tree directory :validate t)))
          (check (not (probe-file directory))
                 "certificate directory is removed after the test")))))
  t)

(defun run-client-driver-real-verification-mode-tests (root leaf certificate-wire)
  (let ((provider (make-cl-crypto-kit-provider))
        (key-exchange
          (list :random (lambda (length)
                          (make-array length :element-type '(unsigned-byte 8)))
                :generate (lambda (group)
                            (declare (ignore group))
                            (values (make-array 32 :element-type '(unsigned-byte 8))
                                    (make-array 32 :element-type '(unsigned-byte 8)))))))
    (labels ((make-driver (mode hostname anchors)
               (let ((driver (make-tls13-client-driver
                              :provider provider :key-exchange key-exchange
                              :verify mode :hostname hostname :trust-anchors anchors
                              :now (1+ (max (cl-tls-kit.x509:x509-certificate-not-before root)
                                            (cl-tls-kit.x509:x509-certificate-not-before leaf))))))
                 (tls13-client-driver-start driver)
                 (setf (cl-tls-kit::tls13-client-driver-state driver) :awaiting-certificate)
                 driver))
             (rejects-p (driver condition-type)
               (handler-case
                   (progn (tls13-client-driver-step driver certificate-wire) nil)
                 (tls13-client-driver-error (condition)
                   (let ((reason (tls13-client-driver-error-reason condition)))
                     (and (consp reason)
                          (eq (first reason) :certificate-verification-failed)
                          (typep (getf (rest reason) :condition) condition-type)))))))
      (dolist (mode '(:required :optional))
        (let ((driver (make-driver mode "example.test" (list root))))
          (tls13-client-driver-step driver certificate-wire)
          (check (eq :awaiting-certificate-verify
                     (cl-tls-kit::tls13-client-driver-state driver))
                 "required and optional verify a real trusted certificate chain"))
        (check (rejects-p (make-driver mode "example.test" (list leaf)) 'untrusted-root)
               "required and optional reject a real untrusted certificate chain")
        (check (rejects-p (make-driver mode "wrong.test" (list root))
                          'certificate-hostname-mismatch)
               "required and optional reject a real certificate hostname mismatch"))
      (let ((driver (make-driver nil "wrong.test" nil)))
        (tls13-client-driver-step driver certificate-wire)
        (check (eq :awaiting-certificate-verify
                   (cl-tls-kit::tls13-client-driver-state driver))
               "explicit NIL accepts an untrusted mismatching real certificate")
        (check (handler-case
                   (progn
                     (tls13-client-driver-step
                      driver (encode-handshake
                              15 (make-tls13-certificate-verify
                                  #x0804 (make-array 256 :element-type '(unsigned-byte 8)))))
                     nil)
                 (tls13-client-driver-error (condition)
                   (equal '(:certificate-verify-failed :bad-signature)
                          (tls13-client-driver-error-reason condition))))
               "explicit NIL rejects forged RSA CertificateVerify using the real crypto provider"))))
  t)

(defun run-client-driver-verification-mode-tests (provider key-exchange)
  (check (handler-case
             (progn (make-tls13-client-driver :provider provider :verify :invalid) nil)
           (tls13-client-driver-error (condition)
             (eq :invalid-verify (tls13-client-driver-error-reason condition)))
           (program-error () nil))
         "public driver rejects invalid verification modes")
  (let* ((root (list :issuer "root" :subject "root" :not-before 0 :not-after 100
                     :basic-constraints '(:ca t)))
         (leaf (list :issuer "root" :subject "leaf" :not-before 0 :not-after 100
                     :signature-algorithm :rsa-pkcs1-sha256
                     :subject-alternative-names '((:dns "example.test"))))
         (chain (list leaf root)))
    (labels ((make-driver (mode hostname anchors)
               (make-tls13-client-driver
                :provider provider :key-exchange key-exchange :verify mode
                :hostname hostname :trust-anchors anchors :now 50
                :verify-signature (lambda (&rest arguments)
                                    (declare (ignore arguments)) t)))
             (rejects-p (driver condition-type)
               (handler-case
                   (progn (cl-tls-kit::%driver-verify-certificate-chain driver chain) nil)
                 (tls13-client-driver-error (condition)
                   (let ((reason (tls13-client-driver-error-reason condition)))
                     (and (consp reason)
                          (eq (first reason) :certificate-verification-failed)
                          (typep (getf (rest reason) :condition) condition-type)))))))
      (check (eq :required
                 (cl-tls-kit::tls13-client-driver-verify
                  (make-tls13-client-driver :provider provider)))
             "public driver defaults to required verification")
      (dolist (mode '(:required :optional))
        (check (cl-tls-kit::%driver-verify-certificate-chain
                (make-driver mode "example.test" (list root)) chain)
               "required and optional accept trusted matching certificates")
        (check (rejects-p (make-driver mode "example.test" (list '(:subject "other")))
                          'untrusted-root)
               "required and optional reject an untrusted root")
        (check (rejects-p (make-driver mode "wrong.test" (list root))
                          'certificate-hostname-mismatch)
               "required and optional reject a hostname mismatch"))
      (let ((driver (make-driver nil "wrong.test" nil))
            (legacy-calls 0))
        (check (cl-tls-kit::%driver-verify-certificate-chain driver nil)
               "explicit NIL skips chain policy without loading trust anchors")
        (tls13-client-driver-start driver)
        (setf (cl-tls-kit::tls13-client-driver-state driver) :awaiting-certificate-verify
              (cl-tls-kit::tls13-client-driver-peer-certificate driver)
              (cl-tls-kit.x509::make-x509-certificate :public-key :test-key)
              (cl-tls-kit::tls13-client-driver-verify-signature driver)
              (lambda (&rest arguments) (declare (ignore arguments)) nil)
              (cl-tls-kit::tls13-client-driver-verify-certificate-verify driver)
              (lambda (message) (declare (ignore message)) (incf legacy-calls) t))
        (check (handler-case
                   (progn (tls13-client-driver-step
                           driver (encode-handshake
                                   15 (make-tls13-certificate-verify #x0804 #(1))))
                          nil)
                 (tls13-client-driver-error (condition)
                   (equal '(:certificate-verify-failed :bad-signature)
                          (tls13-client-driver-error-reason condition))))
               "explicit NIL still rejects a CertificateVerify signature rejected by the provider")
        (check (= legacy-calls 1) "a successful legacy callback cannot bypass signature verification")
        (check (eq :awaiting-certificate-verify (cl-tls-kit::tls13-client-driver-state driver))
               "a forged CertificateVerify cannot advance the handshake"))))
  (dolist (valid-p '(t nil))
    (let* ((sent 0)
           (verify-data (make-array 32 :element-type '(unsigned-byte 8)))
           (driver (cl-tls-kit::%make-tls13-client-driver
                    :state :awaiting-finished :provider provider :hash :sha256 :suite #x1301
                    :server-finished-key verify-data :client-finished-key verify-data
                    :handshake-secret verify-data
                    :on-send (lambda (driver wire)
                               (declare (ignore driver wire))
                               (incf sent)))))
      (unless valid-p (setf (aref verify-data 31) 1))
      (if valid-p
          (progn
            (tls13-client-driver-step driver (encode-handshake 20 (make-tls13-finished verify-data)))
            (check (eq :connected (cl-tls-kit::tls13-client-driver-state driver))
                   "a valid Finished completes the handshake")
            (check (= sent 1) "a valid Finished emits client Finished")
            (check (and (cl-tls-kit::tls13-client-driver-application-read-state driver)
                        (cl-tls-kit::tls13-client-driver-application-write-state driver))
                   "a valid Finished installs application traffic states"))
          (progn
            (check (handler-case
                       (progn
                         (tls13-client-driver-step driver
                           (encode-handshake 20 (make-tls13-finished verify-data)))
                         nil)
                     (tls13-finished-mismatch () t))
                   "a tampered Finished is rejected")
            (check (eq :awaiting-finished (cl-tls-kit::tls13-client-driver-state driver))
                   "a tampered Finished cannot advance the handshake")
            (check (zerop sent) "a tampered Finished emits no client Finished")
            (check (not (or (cl-tls-kit::tls13-client-driver-master-secret driver)
                            (cl-tls-kit::tls13-client-driver-application-read-state driver)
                            (cl-tls-kit::tls13-client-driver-application-write-state driver)))
                   "a tampered Finished installs no application secrets")))))
  t)

(defun run-client-driver-alpn-tests ()
  (dolist (protocols '(("h2") ("unoffered") ("h2" "http/1.1")
                      ("h2" "unoffered")))
    (let* ((driver (cl-tls-kit::%make-tls13-client-driver
                    :state :awaiting-encrypted-extensions
                    :alpn '("h2" "http/1.1")))
           (wire (encode-handshake
                  8 (make-tls13-encrypted-extensions
                     (list (make-tls-extension
                            cl-tls-kit:+tls13-extension-application-layer-protocol-negotiation+
                            (encode-alpn-extension protocols))))))
           (accepted-p (equal protocols '("h2"))))
      (if accepted-p
          (progn
            (tls13-client-driver-step driver wire)
            (check (string= "h2" (tls13-client-driver-negotiated-alpn driver))
                   "driver accepts exactly one offered ALPN protocol"))
          (check (handler-case
                     (progn (tls13-client-driver-step driver wire) nil)
                   (tls13-client-driver-error (condition)
                     (eq :unexpected-alpn
                         (tls13-client-driver-error-reason condition))))
                 "driver rejects unoffered or multiple ALPN selections"))))
  t)

(defun run-client-driver-lifecycle-tests ()
  (let* ((closed 0)
         (driver (cl-tls-kit::%make-tls13-client-driver
                  :state :closed :close-notify-received t
                  :transport-close (lambda (driver)
                                     (declare (ignore driver))
                                     (incf closed)))))
    (tls13-client-driver-close driver)
    (tls13-client-driver-close driver)
    (check (= closed 1) "peer-closed driver releases its transport exactly once")
    (check (tls13-client-driver-closed-p driver) "public reader reports closed state")
    (check (tls13-client-driver-close-notify-received-p driver)
           "public reader reports the peer close_notify"))
  (let* ((closed 0)
         (failure (make-condition 'simple-error :format-control "write failed"))
         (driver (cl-tls-kit::%make-tls13-client-driver
                  :state :connected
                  :transport-write (lambda (driver wire)
                                     (declare (ignore driver wire))
                                     (error failure))
                  :transport-close (lambda (driver)
                                     (declare (ignore driver))
                                     (incf closed)))))
    (check (eq failure (handler-case (tls13-client-driver-close driver)
                         (error (condition) condition)))
           "close preserves its write failure")
    (check (= closed 1) "failed close_notify still releases the transport")
    (check (tls13-client-driver-closed-p driver)
           "failed close_notify closes the driver")
    (check (not (tls13-client-driver-close-notify-received-p driver))
           "local close does not imply an authenticated peer shutdown")
    (tls13-client-driver-close driver)
    (check (= closed 1) "failed close remains idempotent"))
  (let* ((failure (make-condition 'simple-error :format-control "write failed"))
         (driver (cl-tls-kit::%make-tls13-client-driver
                  :state :connected
                  :transport-write (lambda (driver wire)
                                     (declare (ignore driver wire))
                                     (error failure))
                  :transport-close (lambda (driver)
                                     (declare (ignore driver))
                                     (error "cleanup failed")))))
    (check (eq failure (handler-case (tls13-client-driver-close driver)
                         (error (condition) condition)))
           "transport cleanup does not replace the original write failure"))
  (let ((driver (cl-tls-kit::%make-tls13-client-driver
                 :state :closed :close-notify-received t
                 :transport-read (lambda (driver)
                                   (declare (ignore driver))
                                   (error "read after close_notify")))))
    (check (null (tls13-client-driver-read-record driver))
           "closed driver reads do not touch its transport"))
  (let* ((failure (make-condition 'simple-error :format-control "cleanup failed"))
         (driver (cl-tls-kit::%make-tls13-client-driver
                  :state :closed
                  :transport-close (lambda (driver)
                                     (declare (ignore driver))
                                     (error failure)))))
    (check (eq failure (handler-case (tls13-client-driver-close driver)
                         (error (condition) condition)))
           "transport cleanup failure is visible when no write failed"))
  (let* ((reads 0)
         (driver
           (cl-tls-kit::%make-tls13-client-driver
            :state :new :supported-groups '(#x001d)
            :cipher-suites #(#x1301) :signature-algorithms #(#x0804)
            :key-exchange
            (list :generate (lambda (group)
                              (declare (ignore group))
                              (values #(1) #(2)))
                  :random (lambda (length)
                            (make-array length :element-type '(unsigned-byte 8))))
            :transport-read
            (lambda (driver)
              (declare (ignore driver))
              (incf reads)
              (if (= reads 1)
                  (encode-tls-plaintext (make-tls-plaintext
                                         cl-tls-kit::+tls-content-type-alert+ #(1 0)))
                  (error "read after handshake close_notify"))))))
    (check (handler-case (progn (tls13-client-driver-connect driver) nil)
             (tls13-client-driver-error (condition)
               (eq :connection-closed (tls13-client-driver-error-reason condition))))
           "close_notify during handshake terminates connect")
    (check (= reads 1) "handshake close_notify does not restart transport reads"))
  t)
