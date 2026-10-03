(in-package #:cl-tls-kit/test)

(defun run-client-tests ()
  (let* ((reads 0) (writes nil) (events nil) (secrets nil) (close-calls 0)
        (provider (lambda (client input)
                    (declare (ignore client))
                    (push input events)
                    (if (eq input :start)
                        '(:state :awaiting-input)
                        '(:state :connected :alpn "h2")))))
    (let ((client (tls-kit::make-tls-client
                   :transport-read (lambda (client) (declare (ignore client)) (incf reads) #(1 2))
                   :transport-write (lambda (client bytes) (declare (ignore client)) (push bytes writes))
                   :provider (list :handshake provider
                                   :close-notify
                                   (lambda (client)
                                     (declare (ignore client))
                                     (incf close-calls)
                                     #(1 0)))
                   :record-protect (lambda (client bytes) (declare (ignore client)) (vector 9 (aref bytes 0)))
                   :record-unprotect (lambda (client bytes) (declare (ignore client)) (aref bytes 0))
                   :quic-message-callback (lambda (client message) (declare (ignore client)) (push message events))
                   :quic-secret-callback (lambda (client level direction secret)
                                           (declare (ignore client))
                                           (push (list level direction secret) secrets)))))
      (check (eq (tls-kit::tls-client-state client) :new) "client starts new")
      (check (handler-case (progn (tls-kit::tls-client-read client) nil)
               (tls-kit::tls-client-state-error () t)) "read before handshake is rejected")
      (tls-kit::tls-client-start client)
      (check (eq (tls-kit::tls-client-state client) :awaiting-server) "provider controls handshake state")
      (check (handler-case (progn (tls-kit::tls-client-step client '(:type :encrypted-extensions)) nil)
               (tls-kit::unexpected-message () t)) "unexpected message is rejected")
      (tls-kit::tls-client-step client '(:type :server-hello))
      (check (eq (tls-kit::tls-client-state client) :connected) "only provider result connects")
      (check (string= (tls-kit::tls-client-alpn client) "h2") "ALPN is provider result")
      (check (= (tls-kit::tls-client-read client) 1) "read crosses record boundary")
      (tls-kit::tls-client-write client #(7))
      (check (equalp (first writes) #(9 7)) "write crosses record boundary")
      (tls-kit::tls-client-emit-quic-message client :crypto)
      (tls-kit::tls-client-emit-quic-secret client :handshake :write #(3))
      (check (= reads 1) "transport read called once")
      (check (equalp (first secrets) '(:handshake :write #(3))) "QUIC secret callback boundary")
      (tls-kit::tls-client-close client)
      (check (eq (tls-kit::tls-client-state client) :closed) "close transitions state")
      (check (= close-calls 1) "provider creates close_notify once")
      (check (equalp (first writes) #(1 0)) "close_notify crosses the transport boundary")
      (tls-kit::tls-client-close client)
      (check (= close-calls 1) "repeated close does not resend close_notify")))
  (let ((client (tls-kit::make-tls-client)))
    (check (handler-case (progn (tls-kit::tls-client-check-server-random
                                client #(0 0 0 0 0 0 0 68 79 87 78 71 82 68 1)) nil)
             (tls-kit::tls12-downgrade-sentinel () t)) "TLS 1.2 downgrade sentinel is rejected")
    (check (handler-case (progn (tls-kit::tls-client-start client) nil)
             (tls-kit::tls-client-state-error () t)) "missing provider is rejected"))
  (let* ((client (tls-kit::make-tls-client))
         (hello (tls-kit::tls-client-make-client-hello client)))
    (check (not (every #'zerop (tls13-client-hello-random hello)))
           "default ClientHello random uses CSPRNG")
    (check (not (every #'zerop (tls13-client-hello-session-id hello)))
           "default ClientHello session ID uses CSPRNG"))
  (let ((client nil))
    (setf client
          (tls-kit::make-tls-client
           :provider
           (list :client-hello
                 (lambda (ignored)
                   (declare (ignore ignored))
                   (tls-kit::tls-client-make-client-hello
                    client :random (make-array 32 :element-type '(unsigned-byte 8))
                    :session-id #() :cipher-suites #( #x1301)
                    :supported-groups '(#x001d)
                    :key-share (list (cons #x001d #(1)))))
                 :handshake
                 (lambda (ignored input)
                   (declare (ignore ignored input))
                   '(:state :awaiting-input)))))
    (tls-kit::tls-client-start client)
    (let ((server-hello
            (make-tls13-server-hello
             #x0303 (make-array 32 :element-type '(unsigned-byte 8)) #()
             #x1302
             (list (make-tls-extension 43 #(3 4))
                   (make-tls-extension 51
                                       (encode-key-share-server-extension
                                        #x001d #(2)))))))
      (check (handler-case
                 (progn (tls-kit::tls-client-step client server-hello) nil)
               (tls13-negotiation-error (condition)
                 (eq (tls13-negotiation-error-field condition) :cipher-suite)))
             "client rejects an unoffered ServerHello cipher suite")))
  (let ((client (tls-kit::make-tls-client
                 :provider (list :handshake
                                 (lambda (client input)
                                   (declare (ignore client input))
                                   '(:state :connected :peer-certificate :leaf))))) )
    (check (handler-case (progn (tls-kit::tls-client-start client) nil)
             (tls-kit::tls-client-verification-error (condition)
               (eq (tls-kit::tls-client-verification-cause condition)
                   :missing-verification-callback)))
           "peer certificates are rejected without a verification callback"))
  (let ((client (tls-kit::make-tls-client
                 :provider (list :handshake
                                 (lambda (client input)
                                   (declare (ignore client input))
                                   '(:state :connected :peer-certificate :leaf)))
                 :verify-certificate (lambda (certificate)
                                       (declare (ignore certificate))
                                       nil))))
    (check (handler-case (progn (tls-kit::tls-client-start client) nil)
             (tls-kit::tls-client-verification-error () t))
           "verification failure is a client condition"))
  (let* ((client (tls-kit::make-tls-client
                  :provider (list :handshake
                                  (lambda (ignored input)
                                    (declare (ignore ignored input))
                                    '(:state :awaiting-input)))))
         (hello (make-tls13-server-hello
                 #x0303 (make-array 32 :element-type '(unsigned-byte 8)) #()
                 #x1301 (list (make-tls-extension 43 #(3 3))))))
    (tls-kit::tls-client-start client)
    (check (handler-case (progn (tls-kit::tls-client-step client hello) nil)
             (tls-kit::tls13-negotiation-error () t))
           "TLS 1.2 ServerHello version is rejected by negotiation boundary"))
  (let ((writes '()) (hellos 0)
        (client nil))
    (setf client
          (tls-kit::make-tls-client
           :hostname "example.test" :alpn-offered '("h2")
           :transport-write (lambda (ignored bytes)
                              (declare (ignore ignored)) (push bytes writes))
           :provider
           (list :client-hello
                 (lambda (ignored)
                   (declare (ignore ignored))
                   (incf hellos)
                   (tls-kit::tls-client-make-client-hello
                    client :key-share
                    (list (cons #x001d (make-array 32
                                                    :element-type '(unsigned-byte 8)
                                                    :initial-element hellos)))))
                 :digest
                 (lambda (algorithm bytes)
                   (declare (ignore algorithm bytes))
                   (make-array 32 :element-type '(unsigned-byte 8)))
                 :handshake
                 (lambda (ignored input)
                   (declare (ignore ignored input))
                   '(:state :awaiting-input)))))
    (tls-kit::tls-client-start client)
    (check (= hellos 1) "start emits the first ClientHello")
    (let* ((hrr (make-tls13-hello-retry-request
                 #x0303 #x001d '()))
           (hrr-body (encode-hello-retry-request hrr))
           (hrr-wire (concatenate '(vector (unsigned-byte 8))
                                  #(2 0 0 0) hrr-body)))
      (setf (aref hrr-wire 1) (ldb (byte 8 16) (length hrr-body))
            (aref hrr-wire 2) (ldb (byte 8 8) (length hrr-body))
            (aref hrr-wire 3) (ldb (byte 8 0) (length hrr-body)))
      (tls-kit::tls-client-step client hrr-wire)
      (check (= hellos 2) "HRR emits exactly one replacement ClientHello")
      (check (= (length writes) 2) "ClientHello and HRR retry cross transport")) )
  (let ((client nil) (reads (list (make-tls-plaintext 21 #(2 40)))))
    (setf client
          (tls-kit::make-tls-client
           :provider (list :key-update
                           (lambda (ignored request)
                             (declare (ignore ignored request))
                             '(:state :connected)))
           :transport-read (lambda (ignored)
                             (declare (ignore ignored))
                             (pop reads))
           :record-unprotect (lambda (ignored record)
                               (declare (ignore ignored))
                               record)))
    (setf (tls-kit::tls-client-state client) :connected)
    (check (handler-case (progn (tls-kit::tls-client-read client) nil)
             (tls-kit::tls-client-alert-error (condition)
               (and (= (tls-kit::tls-client-alert-level condition) 2)
                    (= (tls-kit::tls-client-alert-description condition) 40))))
           "fatal and warning alerts are surfaced as client conditions"))
  t)
