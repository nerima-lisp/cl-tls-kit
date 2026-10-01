(in-package #:cl-tls-kit)

;;; This file deliberately contains the client boundary, not a TLS
;;; implementation.  A provider owns handshake messages, record protection,
;;; and key schedule operations and communicates through the callbacks below.

(define-condition tls-client-error (error)
  ((client :initarg :client :reader tls-client-error-client)
   (reason :initarg :reason :reader tls-client-error-reason)))

(define-condition tls-client-state-error (tls-client-error)
  ((state :initarg :state :reader tls-client-state-error-state)
   (operation :initarg :operation :reader tls-client-state-error-operation))
  (:report (lambda (condition stream)
             (format stream "TLS client cannot ~A in state ~A"
                     (tls-client-state-error-operation condition)
                     (tls-client-state-error-state condition)))))

(define-condition unexpected-message (tls-client-error)
  ((message :initarg :message :reader unexpected-message-message)
   (expected :initarg :expected :reader unexpected-message-expected))
  (:report (lambda (condition stream)
             (format stream "Unexpected TLS message ~S (expected ~S)"
                     (unexpected-message-message condition)
                     (unexpected-message-expected condition)))))

(define-condition tls12-downgrade-sentinel (tls-client-error)
  ((version :initarg :version :reader tls12-downgrade-version))
  (:report (lambda (condition stream)
             (format stream "TLS 1.3 ServerHello contains a TLS 1.2 downgrade sentinel (~A)"
                     (tls12-downgrade-version condition)))))

(define-condition tls-client-verification-error (tls-client-error)
  ((certificate :initarg :certificate :reader tls-client-verification-certificate)
   (cause :initarg :cause :reader tls-client-verification-cause))
  (:report (lambda (condition stream)
             (format stream "TLS peer certificate verification failed~@[ (~A)~]"
                     (tls-client-verification-cause condition)))))

(defstruct (tls-client (:constructor %make-tls-client))
  transport-read transport-write
  provider record-protect record-unprotect key-schedule
  verify-certificate alpn-offered alpn peer-certificate
  quic-message-callback quic-secret-callback
  (state :new) expected-message)

(defun make-tls-client (&key transport-read transport-write transport
                              provider record-protect record-unprotect
                              key-schedule verify-certificate
                              alpn-offered quic-message-callback
                              quic-secret-callback)
  "Create a TLS 1.3 client boundary around callable provider operations.

TRANSPORT may be a property list containing :READ and :WRITE callbacks.  A
read callback receives the client and returns an encoded record or NIL.  A
write callback receives the client and encoded bytes.  Provider callbacks
receive the client and, for HANDSHAKE, an optional input message.  A
:CLOSE-NOTIFY provider callback receives the client and returns the encoded
record to pass to the transport write callback."
  (let ((read (or transport-read (getf transport :read)))
        (write (or transport-write (getf transport :write))))
    (%make-tls-client :transport-read read :transport-write write
                      :provider provider :record-protect record-protect
                      :record-unprotect record-unprotect
                      :key-schedule key-schedule
                      :verify-certificate verify-certificate
                      :alpn-offered (copy-list alpn-offered)
                      :quic-message-callback quic-message-callback
                      :quic-secret-callback quic-secret-callback)))

(defun %client-fail (client operation reason)
  (error 'tls-client-state-error :client client :operation operation
         :state (tls-client-state client) :reason reason))

(defun %provider-callback (client name)
  (let ((provider (tls-client-provider client)))
    (cond ((functionp provider) provider)
          ((and (listp provider) (functionp (getf provider name)))
           (getf provider name))
          (t nil))))

(defun %call-key-schedule (client event)
  (when (tls-client-key-schedule client)
    (funcall (tls-client-key-schedule client) client event)))

(declaim (ftype function %apply-provider-result))

(defun %octet-vector (value)
  (unless (and (vectorp value)
               (every (lambda (byte) (typep byte '(unsigned-byte 8))) value))
    (error 'type-error :datum value :expected-type '(vector (unsigned-byte 8))))
  value)

(defun tls-client-check-server-random (client server-random &key (version :tls-1.3))
  "Reject the RFC 8446 TLS 1.2/1.1 downgrade sentinels for TLS 1.3."
  (let ((random (%octet-vector server-random)))
    (when (and (eq version :tls-1.3) (>= (length random) 8))
      (let ((tail (subseq random (- (length random) 8))))
        (when (or (equalp tail #(68 79 87 78 71 82 68 1))
                  (equalp tail #(68 79 87 78 71 82 68 0)))
          (error 'tls12-downgrade-sentinel :client client :reason :downgrade
                 :version version))))
    t))

(defun tls-client-start (client)
  (unless (eq (tls-client-state client) :new)
    (%client-fail client :start :already-started))
  (unless (tls-client-provider client)
    (%client-fail client :start :missing-provider))
  (setf (tls-client-state client) :handshake
        (tls-client-expected-message client) :server-hello)
  (%call-key-schedule client :start)
  (let ((callback (%provider-callback client :handshake)))
    (when callback (%apply-provider-result client (funcall callback client :start))))
  client)

(defun %message-type (message)
  (and (listp message) (getf message :type)))

(defun %verify-peer (client certificate)
  (when (tls-client-verify-certificate client)
    (handler-case
        (unless (funcall (tls-client-verify-certificate client) certificate)
          (error "verification callback returned false"))
      (condition (cause)
        (error 'tls-client-verification-error :client client
               :certificate certificate :cause cause)))))

(defun %apply-provider-result (client result)
  (when (and (listp result) (getf result :server-random))
    (tls-client-check-server-random client (getf result :server-random)
                                     :version (or (getf result :version) :tls-1.3)))
  (when (and (listp result) (getf result :peer-certificate))
    (%verify-peer client (getf result :peer-certificate))
    (setf (tls-client-peer-certificate client) (getf result :peer-certificate)))
  (when (and (listp result) (getf result :alpn))
    (setf (tls-client-alpn client) (getf result :alpn)))
  (when (and (listp result) (getf result :key-schedule-event))
    (%call-key-schedule client (getf result :key-schedule-event)))
  (when (and (listp result) (getf result :unexpected-message))
    (error 'unexpected-message :client client :message (getf result :unexpected-message)
           :expected (tls-client-expected-message client)))
  (case (and (listp result) (getf result :state))
    (:awaiting-input (setf (tls-client-state client) :awaiting-server))
    (:connected (setf (tls-client-state client) :connected
                      (tls-client-expected-message client) nil))
    (:failed (%client-fail client :step :provider-failure)))
  client)

(defun tls-client-step (client &optional input)
  "Pass one provider-defined handshake input through the client boundary."
  (unless (member (tls-client-state client) '(:handshake :awaiting-server))
    (%client-fail client :step :not-in-handshake))
  (when (and input (tls-client-expected-message client)
             (not (eql (%message-type input) (tls-client-expected-message client))))
    (error 'unexpected-message :client client :message input
           :expected (tls-client-expected-message client)))
  (let ((callback (%provider-callback client :handshake)))
    (unless callback (%client-fail client :step :missing-handshake-callback))
    (%apply-provider-result client (funcall callback client input))))

(defun tls-client-read (client)
  (unless (eq (tls-client-state client) :connected)
    (%client-fail client :read :not-connected))
  (unless (tls-client-transport-read client)
    (%client-fail client :read :missing-transport))
  (let ((record (funcall (tls-client-transport-read client) client)))
    (when record
      (if (tls-client-record-unprotect client)
          (funcall (tls-client-record-unprotect client) client record)
          record))))

(defun tls-client-write (client plaintext)
  (unless (eq (tls-client-state client) :connected)
    (%client-fail client :write :not-connected))
  (unless (tls-client-transport-write client)
    (%client-fail client :write :missing-transport))
  (let ((record (if (tls-client-record-protect client)
                    (funcall (tls-client-record-protect client) client plaintext)
                    plaintext)))
    (funcall (tls-client-transport-write client) client record)))

(defun tls-client-emit-quic-message (client message)
  (unless (tls-client-quic-message-callback client)
    (%client-fail client :quic-message :missing-callback))
  (funcall (tls-client-quic-message-callback client) client message))

(defun tls-client-emit-quic-secret (client level direction secret)
  (unless (tls-client-quic-secret-callback client)
    (%client-fail client :quic-secret :missing-callback))
  (funcall (tls-client-quic-secret-callback client) client level direction secret))

(defun tls-client-close (client)
  (unless (eq (tls-client-state client) :closed)
    (let* ((provider (tls-client-provider client))
           (callback (and (listp provider)
                          (getf provider :close-notify))))
      (when callback
        (unless (tls-client-transport-write client)
          (%client-fail client :close :missing-transport))
        (let ((record (funcall callback client)))
          (when record
            (funcall (tls-client-transport-write client) client record)))))
    (setf (tls-client-state client) :closed))
  client)
