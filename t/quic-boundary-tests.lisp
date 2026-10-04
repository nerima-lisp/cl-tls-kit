(in-package #:cl-tls-kit/test)

(defun run-quic-boundary-tests ()
  (dolist (name '(make-quic-tls-boundary quic-tls-boundary-send
                  quic-tls-boundary-send-message quic-tls-boundary-feed
                  quic-tls-boundary-receive quic-tls-boundary-feed-crypto
                  quic-tls-boundary-send-with-transport-parameters
                  quic-tls-boundary-emit-secret quic-tls-boundary-emit-cipher-suite
                  quic-tls-boundary-emit-alpn quic-tls-boundary-cipher-suite
                  quic-tls-boundary-alpn))
    (check (eq (nth-value 1 (find-symbol (symbol-name name) :cl-tls-kit)) :external)
           "QUIC boundary is public from cl-tls-kit"))
  (let ((crypto '()) (secrets '()) (transport '()) (suites '()) (alpns '()))
    (let ((boundary
            (make-quic-tls-boundary
             :role :client :transport-parameters #(1 2 3)
             :on-crypto (lambda (boundary level bytes)
                          (declare (ignore boundary)) (push (list level bytes) crypto))
             :on-secret (lambda (boundary level direction secret)
                          (declare (ignore boundary)) (push (list level direction secret) secrets))
             :on-cipher-suite (lambda (boundary suite)
                                (declare (ignore boundary)) (push suite suites))
             :on-alpn (lambda (boundary alpn)
                        (declare (ignore boundary)) (push alpn alpns))
             :on-transport-parameters (lambda (boundary bytes)
                                        (declare (ignore boundary)) (push bytes transport)))))
      (let* ((hello (make-tls13-client-hello
                     #x0303 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                     #() #( #x1301 #x1302) nil))
             (wire (quic-tls-boundary-send-client-hello boundary :initial hello)))
        (check (= (aref wire 0) 1) "QUIC carries a TLS handshake header")
        (check (equalp (first (first crypto)) :initial) "ClientHello uses Initial CRYPTO")
        (check (equalp (quic-tls-boundary-send-message
                        (make-quic-tls-boundary :role :client) :initial 1 hello)
                       (quic-tls-boundary-send
                        (make-quic-tls-boundary :role :client) :initial 1
                        (encode-client-hello hello)))
               "public message output matches the raw CRYPTO handshake wire")
        (check (equalp (quic-tls-boundary-feed
                        (make-quic-tls-boundary :role :server
                                                :on-transport-parameters
                                                (lambda (boundary bytes)
                                                  (declare (ignore boundary))
                                                  (push bytes transport)))
                        :initial (subseq wire 0 7)) nil)
               "partial CRYPTO input is retained")
      (let ((server (make-quic-tls-boundary :role :server
                                               :on-transport-parameters
                                               (lambda (boundary bytes)
                                                 (declare (ignore boundary))
                                                 (push bytes transport)))))
          (quic-tls-boundary-feed server :initial wire)
          (check (equalp (quic-tls-boundary-received-transport-parameters server) #(1 2 3))
                 "transport parameters cross the TLS extension boundary")))
      (let* ((offset-wire (quic-tls-boundary-send
                           (make-quic-tls-boundary :role :client)
                           :initial 20 #(1 2 3)))
             (server (make-quic-tls-boundary :role :server)))
        (check (null (quic-tls-boundary-receive server :initial
                                                (subseq offset-wire 5)
                                                :offset 5))
               "out-of-order CRYPTO data waits for offset zero")
        (let ((messages (quic-tls-boundary-feed-crypto server :initial 0
                                                        (subseq offset-wire 0 5))))
          (check (= (length messages) 1)
                 "offset-aware CRYPTO data is reassembled")))
      (let* ((initial-part #(20 0))
             (handshake-wire (quic-tls-boundary-send
                              (make-quic-tls-boundary :role :client)
                              :handshake 20 #(4 5)))
             (server (make-quic-tls-boundary :role :server)))
        (check (null (quic-tls-boundary-feed server :initial initial-part))
               "incomplete Initial handshake stays at its encryption level")
        (quic-tls-boundary-feed server :handshake handshake-wire)
        (check (= (length (quic-tls-boundary-feed server :initial #(0 2 1 2))) 1)
               "sequential CRYPTO input is buffered independently per level"))
      (quic-tls-boundary-emit-secret boundary :handshake :write #(9 8))
      (check (equalp (first secrets) '(:handshake :write #(9 8)))
             "secret callback retains encryption level and direction")
      (quic-tls-boundary-emit-secret boundary :1-rtt :read #(7))
      (check (equalp (first secrets) '(:application :read #(7)))
             "legacy :1-rtt secret notification is normalized to :application")
      (quic-tls-boundary-emit-cipher-suite boundary #x1301)
      (quic-tls-boundary-emit-alpn boundary "h3")
      (check (equalp (first suites) #x1301) "cipher suite establishment is notified")
      (check (string= (first alpns) "h3") "ALPN establishment is notified")
      (check (= (quic-tls-boundary-cipher-suite boundary) #x1301)
             "selected cipher suite is retained")
      (check (string= (quic-tls-boundary-alpn boundary) "h3")
             "negotiated ALPN is retained")
      (check (handler-case
                 (progn (quic-tls-boundary-emit-secret boundary :0-rtt :read #(1)) nil)
               (quic-tls-boundary-error () t))
             "unsupported :0-rtt boundary level is rejected")
      (check (handler-case
                 (progn (quic-tls-boundary-emit-cipher-suite boundary #xffff) nil)
               (quic-tls-boundary-error () t))
             "unknown cipher suite is rejected")
      (check (handler-case
                 (progn (quic-tls-boundary-emit-alpn boundary "h2") nil)
               (quic-tls-boundary-error () t))
             "conflicting ALPN is rejected")
      (check (equalp (quic-tls-boundary-send-close-notify boundary :1-rtt) #(1 0))
             "close_notify is raw QUIC CRYPTO alert data")
      (check (quic-tls-boundary-close-notify-p #(1 0)) "close_notify classifier")
      (check (quic-tls-boundary-alert-p #(2 40)) "fatal alert classifier")
      (let ((update (quic-tls-boundary-send-key-update boundary :1-rtt 1)))
        (check (quic-tls-boundary-key-update-p update) "KeyUpdate remains a handshake message"))))
  (let* ((transcript-hash (lambda (bytes) (vector (length bytes) #xaa)))
         (boundary (make-quic-tls-boundary :role :server :hash-function transcript-hash))
         (hello (make-tls13-client-hello
                 #x0303 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
                 #() #( #x1301 #x1302) nil)))
    (let* ((hello-wire (quic-tls-boundary-send-client-hello
                        (make-quic-tls-boundary :role :client) :initial hello))
           (hrr (quic-tls-boundary-send-hrr boundary #x001d #(7 7))))
      (check (= (aref hrr 0) 2) "HRR is encoded as ServerHello handshake")
      (check (= (length (second (quic-tls-boundary-transcript boundary))) 6)
             "HRR transcript starts with message_hash replacement")
      (check (equalp (quic-tls-boundary-cookie boundary) #(7 7)) "HRR cookie is retained")
      (check (= (quic-tls-boundary-selected-group boundary) #x001d)
             "HRR key_share selection is retained")
      (let ((client (make-quic-tls-boundary :role :client
                                            :hash-function transcript-hash)))
        (quic-tls-boundary-feed client :initial
                                hello-wire)
        (quic-tls-boundary-feed client :initial hrr)
        (check (= (length (second (quic-tls-boundary-transcript client))) 6)
               "HRR receive path replaces the client transcript")
        (check (= (quic-tls-boundary-selected-group client) #x001d)
               "HRR receive path selects the requested key_share"))))
  (let* ((server-hello (make-tls13-server-hello
                        #x0303 (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 3)
                        #() #x1301 nil))
         (wire (encode-handshake 2 server-hello))
         (boundary (make-quic-tls-boundary :role :client)))
    (quic-tls-boundary-feed boundary :initial wire)
    (check (= (length (quic-tls-boundary-transcript boundary)) 1)
           "ordinary ServerHello is added to the QUIC transcript once"))
  (let* ((body #(0 6 0 57 0 2 9 8))
         (wire (concatenate '(vector (unsigned-byte 8)) #(8 0 0 8) body))
         (boundary (make-quic-tls-boundary :role :client)))
    (quic-tls-boundary-feed boundary :handshake wire)
    (check (equalp (quic-tls-boundary-received-transport-parameters boundary)
                   #(9 8))
           "server EncryptedExtensions carries transport_parameters 0x0039"))
  (let* ((parameters #(9 8))
         (server (make-quic-tls-boundary :role :server))
         (body (encode-encrypted-extensions
                (make-tls13-encrypted-extensions nil)))
         (wire (quic-tls-boundary-send-with-transport-parameters
                server :handshake 8 body parameters))
         (client (make-quic-tls-boundary :role :client)))
    (check (equalp (quic-tls-transport-parameters-extension parameters)
                   #(0 57 0 2 9 8))
           "RFC 9001 transport_parameters extension wire encoding")
    (quic-tls-boundary-receive client :handshake wire)
    (check (equalp (quic-tls-boundary-received-transport-parameters client)
                   parameters)
           "RFC 9001 transport parameters cross the public EE boundary")
    (check (handler-case
               (progn
                  (quic-tls-boundary-send-with-transport-parameters
                   (make-quic-tls-boundary :role :server) :initial 1
                  #() parameters)
                 nil)
             (quic-tls-boundary-error () t))
           "transport parameters reject a role/message mismatch"))
  t)
