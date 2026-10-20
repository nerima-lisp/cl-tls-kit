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
             (declare (ignore hash key bytes))
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
                 (progn (cl-tls-kit::%driver-client-step driver (encode-handshake 2 bad-suite)) nil)
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
                 (progn (cl-tls-kit::%driver-client-step driver (encode-handshake 2 bad-group)) nil)
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
                   (progn (cl-tls-kit::%driver-client-step driver (encode-handshake 2 bad-random)) nil)
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
                    (make-tls13-hello-retry-request #x0303 #x0017 (list (make-tls-extension 43 #(3 4)))))))
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
                    (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                               :awaiting-certificate-verify)
                           "public record path accepts a real leaf-intermediate-root chain"))))
            (dolist (path (list root-path root-key-path intermediate-path intermediate-key-path
                                intermediate-csr-path intermediate-ext-path leaf-path leaf-key-path
                                leaf-csr-path leaf-ext-path))
              (ignore-errors (delete-file path)))
            (ignore-errors (uiop:delete-directory-tree directory :validate t)))
          (check (not (probe-file directory))
                 "certificate directory is removed after the test"))))
    (let* ((shared-secret-calls 0)
           (writes '())
           (close-count 0)
           (group-exchange (copy-list key-exchange))
           (group-driver
            (cl-tls-kit:make-tls13-client-driver
             :provider provider
             :key-exchange group-exchange
             :supported-groups '(#x001d #x0017)
             :transport-write
             (lambda (ignored wire)
               (declare (ignore ignored))
               (push wire writes))
             :transport-close
             (lambda (ignored)
               (declare (ignore ignored))
               (incf close-count)))))
      (setf (getf group-exchange :shared-secret)
            (lambda (group private public)
              (declare (ignore group private public))
              (incf shared-secret-calls)
              (make-array 32 :element-type '(unsigned-byte 8))))
      (tls13-client-driver-start group-driver)
      (check (= (cl-tls-kit::tls13-client-driver-last-sent-key-share-group group-driver)
                #x001d)
             "ClientHello records the group whose share was sent")
      (check (member #x0017
                     (cl-tls-kit::tls13-client-driver-supported-groups group-driver))
             "test group is supported but was not sent")
      (let ((bad-group
             (make-tls13-server-hello
              #x0303 (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 1)
              #() #x1301
              (list (make-tls-extension 43 #(3 4))
                    (make-tls-extension
                     51 (encode-key-share-server-extension
                         #x0017
                         (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 2)))))))
        (check (handler-case
                   (progn
                     (tls13-client-driver-step group-driver
                                               (encode-handshake 2 bad-group))
                     nil)
                 (tls13-client-driver-error (condition)
                                            (eq (tls13-client-driver-error-reason condition)
                                                :unrequested-key-share-group)))
               "driver rejects a supported group without a sent share"))
      (check (zerop shared-secret-calls)
             "unrequested ServerHello group fails before shared-secret callback")
      (let* ((sent (nreverse writes))
             (hello-record (decode-tls-plaintext (first sent)))
             (hello (decode-handshake
                     (tls-plaintext-fragment hello-record)))
             (alert-record (decode-tls-plaintext (second sent))))
        (check (= (length sent) 2)
               "fatal group failure sends one alert after ClientHello")
        (check (= (cl-tls-kit::tls13-client-driver-last-sent-key-share-group group-driver)
                  (car (first (decode-key-share-extension
                               (tls-extension-data
                                (find 51 (tls13-client-hello-extensions hello)
                                      :key #'tls-extension-type))))))
               "sent ClientHello key_share matches the tracked group")
        (check (and (= (tls-plaintext-content-type alert-record)
                       cl-tls-kit::+tls-content-type-alert+)
                    (equalp (tls-plaintext-fragment alert-record) #(2 47)))
               "pre-key fatal alert uses plaintext illegal_parameter")
        (check (and (= close-count 1)
                    (eq (cl-tls-kit::tls13-client-driver-state group-driver)
                        :closed))
               "fatal protocol failure closes the transport once")))
    (labels ((run-retry (cookie-data)
                        (let* ((sent '())
                               (retry-driver
                                (cl-tls-kit:make-tls13-client-driver
                                 :provider provider
                                 :key-exchange key-exchange
                                 :on-send (lambda (ignored wire)
                                            (declare (ignore ignored))
                                            (push wire sent)))))
                          (tls13-client-driver-start retry-driver)
                          (let* ((extensions
                                  (append (list (make-tls-extension 43 #(3 4))) (when cookie-data (list (make-tls-extension 44 cookie-data)))))
                                 (body
                                  (encode-hello-retry-request
                                   (make-tls13-hello-retry-request
                                    #x0303 #x0017 extensions))))
                            (tls13-client-driver-step
                             retry-driver
                             (concatenate '(vector (unsigned-byte 8))
                                          #(2)
                                          (cl-tls-kit::%u24 (length body))
                                          body)))
                          (decode-handshake (first sent)))))
      (let* ((hello (run-retry nil))
             (extensions (tls13-client-hello-extensions hello))
             (share-extension (find 51 extensions :key #'tls-extension-type)))
        (check (null (find 44 extensions :key #'tls-extension-type))
               "HRR without cookie keeps ClientHello2 cookie-free")
        (check (= (caar (decode-key-share-extension
                         (tls-extension-data share-extension)))
                  #x0017)
               "HRR replaces key_share with the requested group")))
    (labels ((run-retry (cookie-data)
                        (let* ((sent '())
                               (retry-driver
                                (cl-tls-kit:make-tls13-client-driver
                                 :provider provider
                                 :key-exchange key-exchange
                                 :on-send (lambda (ignored wire)
                                            (declare (ignore ignored))
                                            (push wire sent)))))
                          (tls13-client-driver-start retry-driver)
                          (let* ((extensions
                                  (list (make-tls-extension 43 #(3 4)) (make-tls-extension 44 cookie-data)))
                                 (body
                                  (encode-hello-retry-request (make-tls13-hello-retry-request #x0303 #x0017 extensions))))
                            (tls13-client-driver-step
                             retry-driver
                             (concatenate '(vector (unsigned-byte 8))
                                          #(2)
                                          (cl-tls-kit::%u24 (length body))
                                          body)))
                          (decode-handshake (first sent)))))
      (let* ((cookie-data #(0 5 9 8 7 6 5))
             (hello (run-retry cookie-data))
             (extensions (tls13-client-hello-extensions hello))
             (cookie (find 44 extensions :key #'tls-extension-type))
             (key-share (find 51 extensions :key #'tls-extension-type)))
        (check (and cookie (equalp (tls-extension-data cookie) cookie-data))
               "ClientHello2 copies the HRR cookie opaque value exactly")
        (check (and cookie key-share
                    (= (count 44 extensions :key #'tls-extension-type) 1)
                    (= (count 51 extensions :key #'tls-extension-type) 1)
                    (< (position 51 extensions :key #'tls-extension-type)
                       (position 44 extensions :key #'tls-extension-type)))
               "ClientHello2 keeps one replacement key_share before cookie")))
    (labels ((check-write-case (length expected-records)
                               (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element 9))
                                      (sender (cl-tls-kit::make-tls13-traffic-state
                                               provider :sha256 :aes-128-gcm secret 16 12))
                                      (receiver (cl-tls-kit::make-tls13-traffic-state
                                                 provider :sha256 :aes-128-gcm secret 16 12))
                                      (writes '())
                                      (write-driver
                                       (cl-tls-kit::%make-tls13-client-driver
                                        :state :connected
                                        :application-write-state sender
                                        :transport-write
                                        (lambda (ignored wire)
                                          (declare (ignore ignored))
                                          (push wire writes))))
                                      (payload (make-array length
                                                           :element-type '(unsigned-byte 8)
                                                           :initial-element 0)))
                                 (dotimes (index length)
                                   (setf (aref payload index) (mod index 251)))
                                 (let* ((returned-wire
                                         (tls13-client-driver-write write-driver payload))
                                        (records (nreverse writes))
                                        (decoded
                                         (mapcar (lambda (wire)
                                                   (cl-tls-kit::decrypt-tls13-traffic-record
                                                    wire receiver))
                                                 records)))
                                   (check (= (length records) expected-records)
                                          "application write emits the expected record count")
                                   (check (equalp returned-wire (apply #'cl-tls-kit::%cat records))
                                          "application write returns all record wire bytes")
                                   (check (every (lambda (record)
                                                   (<= (length
                                                        (tls-ciphertext-fragment
                                                         (decode-tls-ciphertext record)))
                                                       cl-tls-kit::+tls-ciphertext-limit+))
                                                 records)
                                          "application write respects the ciphertext record limit")
                                   (check (every (lambda (plain)
                                                   (and (= (tls-plaintext-content-type plain)
                                                           cl-tls-kit::+tls-content-type-application-data+)
                                                        (<= (length (tls-plaintext-fragment plain))
                                                            cl-tls-kit::+tls-plaintext-limit+)))
                                                 decoded)
                                          "application fragments stay within the plaintext record limit")
                                   (check (equalp payload
                                                  (apply #'cl-tls-kit::%cat
                                                         (mapcar #'tls-plaintext-fragment decoded)))
                                          "fragmented application write preserves byte order")
                                   (check (= (cl-tls-kit::tls13-traffic-state-sequence-number sender)
                                             expected-records)
                                          "application write advances one sequence number per record")
                                   (check (= (cl-tls-kit::tls13-traffic-state-sequence-number receiver)
                                             expected-records)
                                          "record verification advances one sequence number per record")))))
      (check-write-case 0 1)
      (check-write-case 16384 1)
      (check-write-case 16385 2)
      (check-write-case 32777 3))
    (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 5))
           (write-state (cl-tls-kit::make-tls13-traffic-state
                         provider :sha256 :aes-128-gcm secret 16 12))
           (attempted '())
           (close-count 0)
           (write-driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :connected
             :application-write-state write-state
             :transport-write
             (lambda (ignored wire)
               (declare (ignore ignored))
               (push wire attempted)
               (when (= (length attempted) 2)
                 (error 'simple-error
                        :format-control "second record write failed"
                        :format-arguments '())))
             :transport-close
             (lambda (ignored)
               (declare (ignore ignored))
               (incf close-count)))))
      (check (handler-case
                 (progn
                   (tls13-client-driver-write
                    write-driver
                    (make-array 32769 :element-type '(unsigned-byte 8)
                                :initial-element 1))
                   nil)
               (simple-error (condition)
                             (string= (simple-condition-format-control condition)
                                      "second record write failed")))
             "application write preserves the middle transport failure")
      (check (= (length attempted) 2)
             "application write stops after its first failed record")
      (check (= (cl-tls-kit::tls13-traffic-state-sequence-number write-state) 2)
             "failed record consumes only its own sequence number")
      (check (and (= close-count 1)
                  (eq (cl-tls-kit::tls13-client-driver-state write-driver)
                      :closed))
             "application transport failure closes without a protocol alert"))
    (labels ((traffic-state (secret)
                            (cl-tls-kit::make-tls13-traffic-state
                             provider :sha256 :aes-128-gcm secret 16 12)))
      (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 4))
             (handshake-write (traffic-state secret))
             (handshake-read (traffic-state secret))
             (application-write (traffic-state secret))
             (writes '())
             (close-count 0)
             (handshake-driver
              (cl-tls-kit::%make-tls13-client-driver
               :state :awaiting-encrypted-extensions
               :handshake-write-state handshake-write
               :application-write-state application-write
               :transport-write
               (lambda (ignored wire)
                 (declare (ignore ignored))
                 (push wire writes))
               :transport-close
               (lambda (ignored)
                 (declare (ignore ignored))
                 (incf close-count)))))
        (setf (cl-tls-kit::tls13-traffic-state-sequence-number handshake-write) 3
              (cl-tls-kit::tls13-traffic-state-sequence-number handshake-read) 3
              (cl-tls-kit::tls13-traffic-state-sequence-number application-write) 8)
        (check (handler-case
                   (progn
                     (tls13-client-driver-step
                      handshake-driver
                      (encode-handshake
                       4 (make-tls13-new-session-ticket 1 #() #(7) '())))
                     nil)
                 (tls13-client-driver-error (condition)
                                            (eq (tls13-client-driver-error-reason condition)
                                                :unexpected-message)))
               "driver preserves handshake protocol failure")
        (let ((alert (cl-tls-kit::decrypt-tls13-traffic-record
                      (first writes) handshake-read)))
          (check (and (= (tls-plaintext-content-type alert)
                         cl-tls-kit::+tls-content-type-alert+)
                      (equalp (tls-plaintext-fragment alert) #(2 10)))
                 "post-ServerHello fatal alert uses handshake write keys"))
        (check (and (= (cl-tls-kit::tls13-traffic-state-sequence-number
                        handshake-write) 4)
                    (= (cl-tls-kit::tls13-traffic-state-sequence-number
                        handshake-read) 4)
                    (= (cl-tls-kit::tls13-traffic-state-sequence-number
                        application-write) 8)
                    (= close-count 1))
               "handshake alert uses and advances only handshake keys"))
      (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 6))
             (application-write (traffic-state secret))
             (application-read (traffic-state secret))
             (handshake-write (traffic-state secret))
             (writes '())
             (close-count 0)
             (connected-driver
              (cl-tls-kit::%make-tls13-client-driver
               :state :connected
               :handshake-write-state handshake-write
               :application-write-state application-write
               :transport-write
               (lambda (ignored wire)
                 (declare (ignore ignored))
                 (push wire writes))
               :transport-close
               (lambda (ignored)
                 (declare (ignore ignored))
                 (incf close-count)))))
        (setf (cl-tls-kit::tls13-traffic-state-sequence-number application-write) 4
              (cl-tls-kit::tls13-traffic-state-sequence-number application-read) 4
              (cl-tls-kit::tls13-traffic-state-sequence-number handshake-write) 8)
        (check (handler-case
                   (progn
                     (tls13-client-driver-step
                      connected-driver
                      (encode-handshake
                       8 (make-tls13-encrypted-extensions '())))
                     nil)
                 (tls13-client-driver-error (condition)
                                            (eq (tls13-client-driver-error-reason condition)
                                                :unexpected-message)))
               "connected driver preserves protocol failure")
        (let ((alert (cl-tls-kit::decrypt-tls13-traffic-record
                      (first writes) application-read)))
          (check (and (= (tls-plaintext-content-type alert)
                         cl-tls-kit::+tls-content-type-alert+)
                      (equalp (tls-plaintext-fragment alert) #(2 10)))
                 "connected fatal alert uses application write keys"))
        (check (and (= (cl-tls-kit::tls13-traffic-state-sequence-number
                        application-write) 5)
                    (= (cl-tls-kit::tls13-traffic-state-sequence-number
                        application-read) 5)
                    (= (cl-tls-kit::tls13-traffic-state-sequence-number
                        handshake-write) 8)
                    (= close-count 1))
               "connected alert advances only application keys"))
      (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 8))
             (peer-write (traffic-state secret))
             (peer-read (traffic-state secret))
             (local-write (traffic-state secret))
             (writes '())
             (close-count 0)
             (peer-wire
              (cl-tls-kit::encrypt-tls13-traffic-record
               (make-tls-plaintext cl-tls-kit::+tls-content-type-alert+ #(2 47))
               peer-write))
             (peer-driver
              (cl-tls-kit::%make-tls13-client-driver
               :state :connected
               :application-read-state peer-read
               :application-write-state local-write
               :transport-read (lambda (ignored)
                                 (declare (ignore ignored))
                                 peer-wire)
               :transport-write (lambda (ignored wire)
                                  (declare (ignore ignored))
                                  (push wire writes))
               :transport-close (lambda (ignored)
                                  (declare (ignore ignored))
                                  (incf close-count)))))
        (check (handler-case
                   (progn (tls13-client-driver-read-record peer-driver) nil)
                 (tls13-client-driver-error (condition)
                                            (let ((reason (tls13-client-driver-error-reason condition)))
                                              (and (consp reason) (eq (first reason) :peer-alert)))))
               "peer fatal alert remains the original error")
        (check (and (null writes)
                    (zerop (cl-tls-kit::tls13-traffic-state-sequence-number
                            local-write))
                    (= close-count 1))
               "peer fatal alert is not reflected and closes the transport")))
    (let* ((writes '())
           (close-count 0)
           (new-driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :new
             :transport-write
             (lambda (ignored wire)
               (declare (ignore ignored))
               (push wire writes))
             :transport-close
             (lambda (ignored)
               (declare (ignore ignored))
               (incf close-count)))))
      (check (handler-case
                 (progn
                   (tls13-client-driver-write new-driver #(1))
                   nil)
               (tls13-client-driver-error (condition)
                                          (eq (tls13-client-driver-error-reason condition)
                                              :not-connected)))
             "application write rejects local misuse")
      (check (and (eq (cl-tls-kit::tls13-client-driver-state new-driver) :new)
                  (null writes)
                  (zerop close-count))
             "local API misuse sends no alert and leaves the driver open"))
    (let* ((writes '())
           (close-count 0)
           (read-driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :connected
             :transport-read
             (lambda (ignored)
               (declare (ignore ignored))
               (error 'simple-error
                      :format-control "transport read failed"
                      :format-arguments '()))
             :transport-write
             (lambda (ignored wire)
               (declare (ignore ignored))
               (push wire writes))
             :transport-close
             (lambda (ignored)
               (declare (ignore ignored))
               (incf close-count)))))
      (check (handler-case
                 (progn (tls13-client-driver-read-record read-driver) nil)
               (simple-error (condition)
                             (string= (simple-condition-format-control condition)
                                      "transport read failed")))
             "driver preserves a transport receive failure")
      (check (and (null writes)
                  (zerop close-count)
                  (eq (cl-tls-kit::tls13-client-driver-state read-driver)
                      :connected))
             "transport receive failure sends no protocol alert"))
    (let* ((attempted-alerts 0)
           (close-count 0)
           (failed-driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :awaiting-server-hello
             :cipher-suites #( #x1301)
             :supported-groups '(#x001d #x0017)
             :selected-group #x001d
             :last-sent-key-share-group #x001d
             :transport-write
             (lambda (ignored wire)
               (declare (ignore ignored wire))
               (incf attempted-alerts)
               (error 'simple-error
                      :format-control "alert transport write failed"
                      :format-arguments '()))
             :transport-close
             (lambda (ignored)
               (declare (ignore ignored))
               (incf close-count)
               (error 'simple-error
                      :format-control "transport close failed"
                      :format-arguments '()))))
           (bad-group
            (make-tls13-server-hello
             #x0303 (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 1)
             #() #x1301
             (list (make-tls-extension 43 #(3 4))
                   (make-tls-extension
                    51 (encode-key-share-server-extension
                        #x0017
                        (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 2)))))))
      (check (handler-case
                 (progn
                   (tls13-client-driver-step
                    failed-driver (encode-handshake 2 bad-group))
                   nil)
               (tls13-client-driver-error (condition)
                                          (eq (tls13-client-driver-error-reason condition)
                                              :unrequested-key-share-group)))
             "alert and close failures preserve the original protocol error")
      (check (and (= attempted-alerts 1)
                  (= close-count 1)
                  (eq (cl-tls-kit::tls13-client-driver-state failed-driver)
                      :closed))
             "failed alert write is followed by one best-effort close"))
    (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 7))
           (application-read
            (cl-tls-kit::make-tls13-traffic-state
             provider :sha256 :aes-128-gcm secret 16 12))
           (application-write
            (cl-tls-kit::make-tls13-traffic-state
             provider :sha256 :aes-128-gcm secret 16 12))
           (alert-read
            (cl-tls-kit::make-tls13-traffic-state
             provider :sha256 :aes-128-gcm secret 16 12))
           (writes '())
           (close-count 0)
           (record-driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :connected
             :application-read-state application-read
             :application-write-state application-write
             :transport-read (lambda (ignored)
                               (declare (ignore ignored))
                               #(22 3 3 0 0))
             :transport-write (lambda (ignored wire)
                                (declare (ignore ignored))
                                (push wire writes))
             :transport-close (lambda (ignored)
                                (declare (ignore ignored))
                                (incf close-count)))))
      (check (handler-case
                 (progn (tls13-client-driver-read-record record-driver) nil)
               (cl-tls-kit::tls-record-error () t))
             "malformed TLSCiphertext remains the original record error")
      (let ((alert (cl-tls-kit::decrypt-tls13-traffic-record
                    (first writes) alert-read)))
        (check (and (= (tls-plaintext-content-type alert)
                       cl-tls-kit::+tls-content-type-alert+)
                    (equalp (tls-plaintext-fragment alert) #(2 10)))
               "connected TLS record failure sends encrypted unexpected_message"))
      (check (and (= (cl-tls-kit::tls13-traffic-state-sequence-number
                      application-read) 0)
                  (= (cl-tls-kit::tls13-traffic-state-sequence-number
                      application-write) 1)
                  (= (cl-tls-kit::tls13-traffic-state-sequence-number
                      alert-read) 1)
                  (= close-count 1))
             "record failure keeps its read sequence and closes once"))
    (let* ((retry-writes '())
           (close-count 0)
           (retry-driver
            (make-tls13-client-driver
             :provider provider
             :key-exchange key-exchange
             :supported-groups '(#x001d #x0017 #x0018)
             :transport-write
             (lambda (ignored wire)
               (declare (ignore ignored))
               (push wire retry-writes))
             :transport-close
             (lambda (ignored)
               (declare (ignore ignored))
               (incf close-count))))
           (send-retry
            (lambda (group)
              (let* ((body
                      (encode-hello-retry-request
                       (make-tls13-hello-retry-request #x0303 group (list (make-tls-extension 43 #(3 4))))))
                     (wire
                      (concatenate '(vector (unsigned-byte 8))
                                   #(2)
                                   (cl-tls-kit::%u24 (length body))
                                   body)))
                (tls13-client-driver-step retry-driver wire)))))
      (tls13-client-driver-start retry-driver)
      (funcall send-retry #x0017)
      (check (= (cl-tls-kit::tls13-client-driver-last-sent-key-share-group
                 retry-driver)
                #x0017)
             "first HRR selects its requested key share")
      (setf retry-writes nil)
      (check (handler-case
                 (progn (funcall send-retry #x0018) nil)
               (tls13-client-driver-error (condition)
                                          (eq (tls13-client-driver-error-reason condition)
                                              :unexpected-hrr)))
             "second HRR with a different supported group is rejected")
      (check (and (= (length retry-writes) 1)
                  (= close-count 1)
                  (eq (cl-tls-kit::tls13-client-driver-state retry-driver)
                      :closed))
             "second HRR sends one alert and closes the transport")
      (let ((alert (decode-tls-plaintext (first retry-writes))))
        (check (and (= (tls-plaintext-content-type alert)
                       cl-tls-kit::+tls-content-type-alert+)
                    (equalp (tls-plaintext-fragment alert) #(2 10)))
               "second HRR uses a plaintext unexpected_message before keys")))
    (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 10))
           (read-state
            (cl-tls-kit::make-tls13-traffic-state
             provider :sha256 :aes-128-gcm secret 16 12))
           (write-state
            (cl-tls-kit::make-tls13-traffic-state
             provider :sha256 :aes-128-gcm secret 16 12))
           (writes '())
           (close-count 0)
           (sequence-driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :connected
             :application-read-state read-state
             :application-write-state write-state
             :transport-read (lambda (ignored)
                               (declare (ignore ignored))
                               #(23 3 3 0 0))
             :transport-write (lambda (ignored wire)
                                (declare (ignore ignored))
                                (push wire writes))
             :transport-close (lambda (ignored)
                                (declare (ignore ignored))
                                (incf close-count))))
           (max-sequence (1- (expt 2 64))))
      (setf (cl-tls-kit::tls13-traffic-state-sequence-number read-state)
            max-sequence)
      (check (handler-case
                 (progn (tls13-client-driver-read-record sequence-driver) nil)
               (tls-sequence-overflow () t))
             "record sequence exhaustion remains the original error")
      (check (and (null writes)
                  (= close-count 1)
                  (eq (cl-tls-kit::tls13-client-driver-state sequence-driver)
                      :closed))
             "sequence exhaustion closes without sending an alert"))
    (let* ((bad-provider (cl-tls-kit::copy-tls13-crypto-provider provider))
           (secret (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 11))
           (read-state
            (cl-tls-kit::make-tls13-traffic-state
             bad-provider :sha256 :aes-128-gcm secret 16 12))
           (write-state
            (cl-tls-kit::make-tls13-traffic-state
             provider :sha256 :aes-128-gcm secret 16 12))
           (wire
            (cl-tls-kit::encode-tls-ciphertext
             (cl-tls-kit::make-tls-ciphertext
              cl-tls-kit::+tls-content-type-application-data+
              (make-array 17 :element-type '(unsigned-byte 8)
                          :initial-element 0))))
           (writes '())
           (close-count 0)
           (record-driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :connected
             :application-read-state read-state
             :application-write-state write-state
             :transport-read (lambda (ignored)
                               (declare (ignore ignored))
                               wire)
             :transport-write (lambda (ignored output)
                                (declare (ignore ignored))
                                (push output writes))
             :transport-close (lambda (ignored)
                                (declare (ignore ignored))
                                (incf close-count)))))
      (setf (cl-tls-kit::tls13-crypto-provider-aead-open bad-provider)
            (lambda (algorithm key nonce ciphertext aad)
              (declare (ignore algorithm key nonce ciphertext aad))
              (error 'tls-record-error :reason :provider-record-failure)))
      (check (handler-case
                 (progn (tls13-client-driver-read-record record-driver) nil)
               (tls-record-error () t))
             "base record error remains the original error")
      (check (and (null writes)
                  (= close-count 1)
                  (eq (cl-tls-kit::tls13-client-driver-state record-driver)
                      :closed))
             "base record error closes without sending an alert"))
    (let* ((write-state
            (cl-tls-kit::make-tls13-traffic-state
             provider :sha256 :aes-128-gcm
             (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-element 12)
             16 12))
           (writes '())
           (close-count 0)
           (transport-record-driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :connected
             :application-write-state write-state
             :transport-read
             (let ((first-read-p t))
               (lambda (ignored)
                 (declare (ignore ignored))
                 (when first-read-p
                   (setf first-read-p nil)
                   (error (quote tls-record-error) :reason :transport-record-failure))))
             :transport-write (lambda (ignored wire)
                                (declare (ignore ignored))
                                (push wire writes))
             :transport-close (lambda (ignored)
                                (declare (ignore ignored))
                                (incf close-count)))))
      (check (handler-case
                 (progn
                   (tls13-client-driver-read-record transport-record-driver)
                   nil)
               (tls-record-error () t))
             "transport record failure remains the original error")
      (check
       (and
        (eq (cl-tls-kit::tls13-client-driver-state transport-record-driver) :connected)
        (null writes)
        (zerop close-count)
        (handler-case
            (tls13-client-driver-read-record transport-record-driver)
          (tls13-client-driver-error (condition)
                                     (eq (tls13-client-driver-error-reason condition) :eof)))
        (eq (cl-tls-kit::tls13-client-driver-state transport-record-driver) :closed)
        (null writes)
        (= close-count 1))
       "transport EOF preserves the read error and closes without an alert"))
    (let* ((secret (make-array 32 :element-type '(unsigned-byte 8) :initial-element 14))
           (read-state (cl-tls-kit::make-tls13-traffic-state provider :sha256 :aes-128-gcm secret 16 12))
           (write-state (cl-tls-kit::make-tls13-traffic-state provider :sha256 :aes-128-gcm secret 16 12))
           (peer-write (cl-tls-kit::make-tls13-traffic-state provider :sha256 :aes-128-gcm secret 16 12))
           (peer-read (cl-tls-kit::make-tls13-traffic-state provider :sha256 :aes-128-gcm secret 16 12))
           (wire (cl-tls-kit::encrypt-tls13-traffic-record
                  (make-tls-plaintext cl-tls-kit::+tls-content-type-alert+ #(1 0))
                  peer-write))
           (writes '())
           (close-count 0)
           (driver (cl-tls-kit::%make-tls13-client-driver
                    :state :connected
                    :application-read-state read-state
                    :application-write-state write-state
                    :transport-read (lambda (ignored) (declare (ignore ignored)) wire)
                    :transport-write (lambda (ignored output)
                                       (declare (ignore ignored))
                                       (push output writes))
                    :transport-close (lambda (ignored)
                                       (declare (ignore ignored))
                                       (incf close-count)))))
      (check (null (tls13-client-driver-read-record driver))
             "peer close_notify ends application reads")
      (check (and (cl-tls-kit::tls13-client-driver-close-notify-received driver)
                  (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
                  (= close-count 1) (= (length writes) 1)
                  (= (cl-tls-kit::tls13-traffic-state-sequence-number read-state) 1)
                  (= (cl-tls-kit::tls13-traffic-state-sequence-number write-state) 1))
             "peer close_notify sends one response and closes both directions")
      (let ((response (cl-tls-kit::decrypt-tls13-traffic-record (first writes) peer-read)))
        (check (and (= (tls-plaintext-content-type response)
                       cl-tls-kit::+tls-content-type-alert+)
                    (equalp (tls-plaintext-fragment response) #(1 0))
                    (= (cl-tls-kit::tls13-traffic-state-sequence-number peer-read) 1))
               "peer close_notify response uses application write keys"))
      (check (handler-case
                 (progn (tls13-client-driver-write driver #()) nil)
               (tls13-client-driver-error (condition)
                                          (eq (tls13-client-driver-error-reason condition) :not-connected)))
             "peer close_notify prevents further application writes")
      (tls13-client-driver-close driver)
      (check (and (= close-count 1) (= (length writes) 1))
             "repeated close after peer close_notify is idempotent"))
    (let* ((close-wire
            (encode-tls-plaintext
             (make-tls-plaintext cl-tls-kit::+tls-content-type-alert+ #(1 0))))
           (writes '())
           (read-count 0)
           (close-count 0)
           (driver
            (make-tls13-client-driver
             :provider provider
             :key-exchange key-exchange
             :transport-read (lambda (ignored)
                               (declare (ignore ignored))
                               (incf read-count)
                               close-wire)
             :transport-write (lambda (ignored wire)
                                (declare (ignore ignored))
                                (push wire writes))
             :transport-close (lambda (ignored)
                                (declare (ignore ignored))
                                (incf close-count)))))
      (check (handler-case
                 (progn (tls13-client-driver-connect driver) nil)
               (tls13-client-driver-error (condition)
                                          (eq (tls13-client-driver-error-reason condition)
                                              :close-notify-during-handshake)))
             "handshake close_notify returns an explicit connect error")
      (check (and (= read-count 1) (= (length writes) 1)
                  (= close-count 1)
                  (eq (cl-tls-kit::tls13-client-driver-state driver) :closed))
             "handshake close_notify stops reading and closes without reflection")
      (let ((initial-record (decode-tls-plaintext (first writes))))
        (check (= (tls-plaintext-content-type initial-record)
                  cl-tls-kit::+tls-content-type-handshake+)
               "handshake close_notify does not send a fatal alert")))
    (let* ((secret (make-array 32 :element-type '(unsigned-byte 8) :initial-element 15))
           (write-state (cl-tls-kit::make-tls13-traffic-state
                         provider :sha256 :aes-128-gcm secret 16 12))
           (attempts 0)
           (close-count 0)
           (driver
            (cl-tls-kit::%make-tls13-client-driver
             :state :connected
             :application-write-state write-state
             :transport-write (lambda (ignored wire)
                                (declare (ignore ignored wire))
                                (incf attempts)
                                (error 'simple-error
                                       :format-control "close_notify write failed"
                                       :format-arguments '()))
             :transport-close (lambda (ignored)
                                (declare (ignore ignored))
                                (incf close-count)
                                (error 'simple-error
                                       :format-control "transport close failed"
                                       :format-arguments '())))))
      (check (handler-case
                 (progn (tls13-client-driver-close driver) nil)
               (simple-error (condition)
                             (string= (simple-condition-format-control condition)
                                      "close_notify write failed")))
             "explicit close preserves the close_notify transport failure")
      (check (and (= attempts 1) (= close-count 1)
                  (eq (cl-tls-kit::tls13-client-driver-state driver) :closed))
             "explicit close cleans up after close_notify write failure")
      (tls13-client-driver-close driver)
      (check (and (= attempts 1) (= close-count 1))
             "explicit close remains idempotent after write failure"))
    (let* ((broken-exchange (copy-list key-exchange))
           (writes '())
           (close-count 0)
           (driver
            (make-tls13-client-driver
             :provider provider
             :key-exchange broken-exchange
             :transport-write (lambda (ignored wire)
                                (declare (ignore ignored))
                                (push wire writes))
             :transport-close (lambda (ignored)
                                (declare (ignore ignored))
                                (incf close-count)))))
      (setf (getf broken-exchange :shared-secret) nil)
      (tls13-client-driver-start driver)
      (let ((server-hello
             (make-tls13-server-hello
              #x0303
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
              #() #x1301
              (list (make-tls-extension 43 #(3 4))
                    (make-tls-extension
                     51 (encode-key-share-server-extension
                         #x001d
                         (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 2)))))))
        (check (handler-case
                   (progn
                     (tls13-client-driver-step
                      driver (encode-handshake 2 server-hello))
                     nil)
                 (tls13-client-driver-error (condition)
                                            (eq (tls13-client-driver-error-reason condition)
                                                :missing-key-exchange-function)))
               "missing shared-secret callback preserves its handshake error"))
      (check (and (= (length writes) 2)
                  (= close-count 1)
                  (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
                  (let ((alert (decode-tls-plaintext (first writes))))
                    (and (= (tls-plaintext-content-type alert)
                            cl-tls-kit::+tls-content-type-alert+)
                         (equalp (tls-plaintext-fragment alert) #(2 80)))))
             "missing shared-secret callback sends plaintext internal_error and closes"))
    (progn
      (let* ((key-exchange (cl-tls-kit::%driver-default-key-exchange))
             (generate (getf key-exchange :generate))
             (shared-secret (getf key-exchange :shared-secret))
             (private (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 1))
             (short-x25519-share
               (make-array 31 :element-type '(unsigned-byte 8)
                              :initial-element 1))
             (off-curve-p256-share
               (make-array 65 :element-type '(unsigned-byte 8)
                              :initial-element 0)))
        (setf (aref off-curve-p256-share 0) #x04)
        (check
         (handler-case
             (progn
               (funcall shared-secret #x001d private short-x25519-share)
               nil)
           (tls13-client-driver-error (condition)
             (eq (tls13-client-driver-error-reason condition)
                 :invalid-key-share)))
         "default X25519 exchange normalizes a wrong-length peer share")
        (multiple-value-bind (p256-private p256-public)
            (funcall generate #x0017)
          (check
           (handler-case
               (progn
                 (funcall shared-secret #x0017 p256-private off-curve-p256-share)
                 nil)
             (tls13-client-driver-error (condition)
               (eq (tls13-client-driver-error-reason condition)
                   :invalid-key-share)))
           "default P-256 exchange normalizes an off-curve peer share")
          (check
           (handler-case
               (progn
                 (funcall shared-secret #x0017 #() p256-public)
                 nil)
             (crypto-kit:crypto-error (condition)
               (string= (crypto-kit:crypto-error-message condition)
                        "Invalid P-256 private key length")))
           "default P-256 exchange preserves local key errors")))
      (progn
  (let* ((writes '())
         (early-data-driver
           (make-tls13-client-driver
            :provider provider
            :key-exchange key-exchange
            :hostname "example.test"
            :transport-write
            (lambda (ignored wire)
              (declare (ignore ignored))
              (push wire writes)))))
    (tls13-client-driver-start early-data-driver)
    (tls13-client-driver-step
     early-data-driver
     (encode-handshake
      2 (make-tls13-server-hello
         #x0303
         (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8)
         #() #x1301
         (list (make-tls-extension 43 #(3 4))
               (make-tls-extension
                51 (encode-key-share-server-extension
                    #x001d
                    (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 9)))))))
    (let* ((write-state
             (cl-tls-kit::tls13-client-driver-handshake-write-state
              early-data-driver))
           (alert-reader
             (make-tls13-traffic-state
              provider :sha256 :aes-128-gcm
              (tls13-traffic-state-secret write-state) 16 12))
           (failure
             (handler-case
                 (progn
                   (tls13-client-driver-step
                    early-data-driver
                    (encode-handshake
                     8 (make-tls13-encrypted-extensions
                        (list (make-tls-extension 42 #())))))
                   nil)
               (tls13-client-driver-error (condition)
                 (eq (tls13-client-driver-error-reason condition)
                     :unsupported-extension)))))
      (check failure
             "EncryptedExtensions rejects unoffered early_data")
      (let ((alert
              (decrypt-tls13-traffic-record (first writes) alert-reader)))
        (progn
          (check (and (= (tls-plaintext-content-type alert)
                         cl-tls-kit::+tls-content-type-alert+)
                      (equalp (tls-plaintext-fragment alert) #(2 110)))
                 "unoffered early_data sends encrypted unsupported_extension")
          (let ((api-assertions 0))
            (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 21))
                   (read-state
                     (cl-tls-kit::make-tls13-traffic-state
                      provider :sha256 :aes-128-gcm secret 16 12))
                   (peer-write
                     (cl-tls-kit::make-tls13-traffic-state
                      provider :sha256 :aes-128-gcm secret 16 12))
                   (wire
                     (cl-tls-kit::encrypt-tls13-traffic-record
                      (cl-tls-kit::make-tls-plaintext
                       cl-tls-kit::+tls-content-type-application-data+
                       #(0 1 128 255))
                      peer-write))
                   (driver
                     (cl-tls-kit::%make-tls13-client-driver
                      :state :connected
                      :application-read-state read-state
                      :transport-read
                      (lambda (ignored)
                        (declare (ignore ignored))
                        wire))))
              (multiple-value-bind (status octets)
                  (cl-tls-kit:tls13-client-driver-read-application-data driver)
                (incf api-assertions)
                (check (and (eq status :data)
                            (equalp octets #(0 1 128 255)))
                       "application-data read returns exact octets")))
            (let ((driver
                    (cl-tls-kit::%make-tls13-client-driver
                     :state :connected
                     :transport-read
                     (lambda (ignored)
                       (declare (ignore ignored))
                       :would-block))))
              (multiple-value-bind (status octets)
                  (cl-tls-kit:tls13-client-driver-read-application-data driver)
                (incf api-assertions)
                (check (and (eq status :would-block) (null octets))
                       "application-data read reports would-block")))
            (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 22))
                   (read-state
                     (cl-tls-kit::make-tls13-traffic-state
                      provider :sha256 :aes-128-gcm secret 16 12))
                   (write-state
                     (cl-tls-kit::make-tls13-traffic-state
                      provider :sha256 :aes-128-gcm secret 16 12))
                   (peer-write
                     (cl-tls-kit::make-tls13-traffic-state
                      provider :sha256 :aes-128-gcm secret 16 12))
                   (wire
                     (cl-tls-kit::encrypt-tls13-traffic-record
                      (cl-tls-kit::make-tls-plaintext
                       cl-tls-kit::+tls-content-type-alert+ #(1 0))
                      peer-write))
                   (driver
                     (cl-tls-kit::%make-tls13-client-driver
                      :state :connected
                      :application-read-state read-state
                      :application-write-state write-state
                      :transport-read
                      (lambda (ignored)
                        (declare (ignore ignored))
                        wire)
                      :transport-write
                      (lambda (ignored output)
                        (declare (ignore ignored output)))
                      :transport-close
                      (lambda (ignored)
                        (declare (ignore ignored))))))
              (let ((status
                      (cl-tls-kit:tls13-client-driver-read-application-data driver)))
                (incf api-assertions)
                (check (eq status :eof)
                       "application-data read reports close_notify as EOF")))
            (let ((driver
                    (cl-tls-kit::%make-tls13-client-driver
                     :state :connected
                     :transport-read
                     (lambda (ignored)
                       (declare (ignore ignored))
                       nil))))
              (incf api-assertions)
              (check (handler-case
                         (progn
                           (cl-tls-kit:tls13-client-driver-read-application-data driver)
                           nil)
                       (tls13-client-driver-error (condition)
                         (eq (tls13-client-driver-error-reason condition) :eof)))
                     "raw transport EOF remains an error"))
            (assert (= api-assertions 4))
            (format t "TLS 1.3 client application-data read API: assertions: ~D~%"
                    api-assertions))))))
  t))))
