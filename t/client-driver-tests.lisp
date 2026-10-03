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
         (driver
           (cl-tls-kit:make-tls13-client-driver
            :provider provider
            :key-exchange (list :generate
                                (lambda (group)
                                  (declare (ignore group))
                                  (values (make-array 32 :element-type '(unsigned-byte 8))
                                          (make-array 32 :element-type '(unsigned-byte 8))))
                                :shared-secret
                                (lambda (group private public)
                                  (declare (ignore group private public))
                                  (make-array 32 :element-type '(unsigned-byte 8))))
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
                     :unoffered-cipher-suite)))
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
  t))
