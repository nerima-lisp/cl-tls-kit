(in-package #:cl-tls-kit/test)

(defun run-client-driver-tests ()
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
      (let* ((directory (merge-pathnames "cl-tls-kit-r6-certificate/"
                                        (uiop:temporary-directory)))
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
        (ensure-directories-exist directory)
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
          (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                     :awaiting-certificate-verify)
                 "public record path accepts a real leaf-intermediate-root chain")))))
  t)))
