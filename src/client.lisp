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

(define-condition tls-client-alert-error (tls-client-error)
  ((level :initarg :level :reader tls-client-alert-level)
   (description :initarg :description :reader tls-client-alert-description))
  (:report (lambda (condition stream)
             (format stream "TLS peer sent alert ~D/~D"
                     (tls-client-alert-level condition)
                     (tls-client-alert-description condition)))))

(define-condition tls13-negotiation-error (tls-client-error)
  ((field :initarg :field :reader tls13-negotiation-error-field))
  (:report (lambda (condition stream)
             (format stream "Invalid TLS 1.3 negotiated ~A"
                     (tls13-negotiation-error-field condition)))))

(defstruct (tls-client (:constructor %make-tls-client))
  transport-read transport-write
  transport-close
  provider record-protect record-unprotect key-schedule
  verify-certificate hostname alpn-offered alpn peer-certificate
  certificate-message-received
  client-hello (client-hello-count 0)
  quic-message-callback quic-secret-callback
  (state :new) expected-message
  (transcript (make-array 0 :element-type '(unsigned-byte 8)))
  (hrr-seen nil) (key-update-count 0) close-notify-received)

(defun make-tls-client (&key transport-read transport-write transport transport-close
                              provider record-protect record-unprotect
                              key-schedule verify-certificate
                              hostname alpn-offered alpn quic-message-callback
                              quic-secret-callback)
  "Create a TLS 1.3 client boundary around callable provider operations.

TRANSPORT may be a property list containing :READ and :WRITE callbacks.  A
read callback receives the client and returns an encoded record or NIL.  A
write callback receives the client and encoded bytes.  Provider callbacks
receive the client and, for HANDSHAKE, an optional input message.  A
:CLOSE-NOTIFY provider callback receives the client and returns the encoded
record to pass to the transport write callback.  VERIFY-CERTIFICATE must be
provided before a peer certificate can be accepted."
  (let ((read (or transport-read (getf transport :read)))
        (write (or transport-write (getf transport :write))))
    (%make-tls-client :transport-read read :transport-write write
                      :transport-close (or transport-close (getf transport :close))
                      :provider provider :record-protect record-protect
                      :record-unprotect record-unprotect
                      :key-schedule key-schedule
                      :verify-certificate verify-certificate
                      :hostname (and hostname (normalize-hostname hostname))
                      :alpn-offered (copy-list alpn-offered)
                      :alpn alpn
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

(defun %tls-client-csprng-octets (length)
  (let* ((package (find-package '#:crypto-kit))
         (symbol (and package (find-symbol "RANDOM-OCTETS" package))))
    (unless (and symbol (fboundp symbol))
      (error 'tls-client-error :client nil :reason :missing-csprng))
    (%octet-vector (funcall symbol length))))

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

(defun %tls-client-check-server-hello (client hello)
  (unless (= (tls13-server-hello-legacy-version hello) #x0303)
    (error 'tls13-negotiation-error :client client :reason :legacy-version
           :field :legacy-version))
  (unless (member (tls13-server-hello-cipher-suite hello)
                  (if (and client (tls-client-client-hello client))
                      (coerce (tls13-client-hello-cipher-suites
                               (tls-client-client-hello client)) 'list)
                      '(#x1301 #x1302 #x1303 #x1304)))
    (error 'tls13-negotiation-error :client client :reason :cipher-suite
           :field :cipher-suite))
  (let ((versions (remove-if-not
                   (lambda (extension) (= (tls-extension-type extension) 43))
                   (tls13-server-hello-extensions hello))))
    (unless (and (= (length versions) 1)
                 (equalp (tls-extension-data (first versions)) #(3 4)))
      (error 'tls13-negotiation-error :client client :reason :supported-version
             :field :supported-version)))
  (when (and client (tls-client-client-hello client))
    (let* ((extension (find +tls13-extension-supported-groups+
                            (tls13-client-hello-extensions
                             (tls-client-client-hello client))
                            :key #'tls-extension-type))
           (requested (and extension
                            (let ((bytes (tls-extension-data extension)))
                              (multiple-value-bind (raw end)
                                  (%read-vector bytes 0 2)
                                (declare (ignore end))
                                (loop for position from 0 below (length raw) by 2
                                      collect (+ (ash (aref raw position) 8)
                                                 (aref raw (1+ position)))))))))
      (let ((key-share (find +tls13-extension-key-share+
                             (tls13-server-hello-extensions hello)
                             :key #'tls-extension-type)))
        (unless (and requested key-share
                     (member (car (decode-key-share-server-extension
                                   (tls-extension-data key-share)))
                             requested))
          (error 'tls13-negotiation-error :client client
                 :reason :key-share-group :field :key-share-group)))))
  t)

(defun tls-client-start (client)
  (unless (eq (tls-client-state client) :new)
    (%client-fail client :start :already-started))
  (unless (tls-client-provider client)
    (%client-fail client :start :missing-provider))
  (setf (tls-client-state client) :handshake
        (tls-client-expected-message client) :server-hello)
  (%call-key-schedule client :start)
  (let ((hello-callback (%provider-callback client :client-hello)))
    (when hello-callback
      (let* ((hello-result (funcall hello-callback client))
             (hello (if (and (listp hello-result) (getf hello-result :message))
                        (getf hello-result :message)
                        hello-result)))
        (unless (typep hello 'tls13-client-hello)
          (%client-fail client :start :invalid-client-hello))
        (setf (tls-client-client-hello client) hello)
        (incf (tls-client-client-hello-count client))
        (let ((wire (encode-handshake 1 hello)))
          (%client-transcript-add client wire)
          (when (tls-client-transport-write client)
            (funcall (tls-client-transport-write client) client wire))))))
  (let ((callback (%provider-callback client :handshake)))
    (when callback (%apply-provider-result client (funcall callback client :start))))
  client)

(defun %message-type (message)
  (cond ((listp message) (getf message :type))
        ((typep message 'tls13-server-hello) :server-hello)
        ((typep message 'tls13-hello-retry-request) :hello-retry-request)
        ((typep message 'tls13-encrypted-extensions) :encrypted-extensions)
        ((typep message 'tls13-certificate) :certificate)
        ((typep message 'tls13-certificate-verify) :certificate-verify)
        ((typep message 'tls13-finished) :finished)
        ((typep message 'tls13-certificate-request) :certificate-request)
        ((typep message 'tls13-key-update) :key-update)
        (t nil)))

(defun %client-message-number (type)
  (case type (:client-hello 1) (:server-hello 2) (:hello-retry-request 2)
    (:encrypted-extensions 8)
    (:certificate 11) (:certificate-request 13) (:certificate-verify 15)
    (:finished 20) (:new-session-ticket 4) (:key-update 24)))

(defun %client-transcript-add (client bytes)
  (when bytes
    (let ((bytes (%octet-vector bytes)))
      (setf (tls-client-transcript client)
            (concatenate '(vector (unsigned-byte 8))
                         (tls-client-transcript client) bytes)))))

(defun %client-hrr-transcript (client hrr-wire)
  "Replace the initial ClientHello transcript with RFC 8446 message_hash."
  (let* ((provider (tls-client-provider client))
         (digest (and (listp provider) (getf provider :digest)))
         (hash (progn
                 (unless digest (%client-fail client :hrr :missing-transcript-hash))
                 (funcall digest :sha256 (tls-client-transcript client)))))
    (setf (tls-client-transcript client)
          (concatenate '(vector (unsigned-byte 8))
                       (vector #xfe
                               (ldb (byte 8 16) (length hash))
                               (ldb (byte 8 8) (length hash))
                               (ldb (byte 8 0) (length hash)))
                       hash hrr-wire))))

(defun %client-advance-message (client type)
  (let ((expected (tls-client-expected-message client)))
    (when (and expected (not (eql type expected)))
      ;; KeyUpdate and post-handshake tickets are legal after Finished.
      (unless (or (and (eq expected :server-hello)
                    (eq type :hello-retry-request))
                  (and (eq expected :certificate)
                       (eq type :certificate-request))
                  (and (eq (tls-client-state client) :connected)
                       (member type '(:key-update :new-session-ticket))))
        (error 'unexpected-message :client client :message type :expected expected)))
    (case type
      (:server-hello (setf (tls-client-expected-message client) :encrypted-extensions))
      (:hello-retry-request
       (when (tls-client-hrr-seen client) (%client-fail client :step :second-hrr))
       (setf (tls-client-hrr-seen client) t
             (tls-client-expected-message client) :server-hello))
      (:encrypted-extensions (setf (tls-client-expected-message client) :certificate))
      (:certificate-request nil)
      (:certificate (setf (tls-client-expected-message client) :certificate-verify))
      (:certificate-verify (setf (tls-client-expected-message client) :finished))
      (:finished (setf (tls-client-state client) :connected
                       (tls-client-expected-message client) nil))
      (:key-update (incf (tls-client-key-update-count client)))))
  )

(defun %verify-peer (client certificate)
  (unless (tls-client-verify-certificate client)
    (error 'tls-client-verification-error :client client
           :certificate certificate :cause :missing-verification-callback))
  (handler-case
      (unless (funcall (tls-client-verify-certificate client) certificate)
        (error "verification callback returned false"))
    (condition (cause)
      (error 'tls-client-verification-error :client client
             :certificate certificate :cause cause))))

(defun %apply-provider-result (client result)
  (when (and (listp result) (getf result :transcript))
    (%client-transcript-add client (getf result :transcript)))
  (when (and (listp result) (getf result :message))
    (let ((type (%message-type (getf result :message))))
      (%client-advance-message client type)
      (when (getf result :wire) (%client-transcript-add client (getf result :wire)))))
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
  (when (and (listp result) (getf result :outgoing))
    (dolist (message (getf result :outgoing))
      (let ((wire (if (and (consp message) (integerp (car message)))
                      (encode-handshake (car message) (cdr message))
                      message)))
        (%client-transcript-add client wire)
        (when (tls-client-transport-write client)
          (funcall (tls-client-transport-write client) client wire)))))
  (when (and (listp result) (getf result :unexpected-message))
    (error 'unexpected-message :client client :message (getf result :unexpected-message)
           :expected (tls-client-expected-message client)))
  (case (and (listp result) (getf result :state))
    (:awaiting-input (setf (tls-client-state client) :awaiting-server))
    (:connected
     (when (and (tls-client-certificate-message-received client)
                (null (tls-client-peer-certificate client)))
       (error 'tls-client-verification-error :client client
              :certificate nil :cause :missing-peer-certificate))
     (setf (tls-client-state client) :connected
           (tls-client-expected-message client) nil))
    (:failed (%client-fail client :step :provider-failure)))
  client)

(defun tls-client-step (client &optional input)
  "Pass one provider-defined handshake input through the client boundary."
  (unless (member (tls-client-state client) '(:handshake :awaiting-server))
    (%client-fail client :step :not-in-handshake))
  (when input
    (when (and (vectorp input) (>= (length input) 4))
      (setf input (decode-handshake input)))
    (let ((type (%message-type input)))
      (unless type
        (%client-fail client :step :unsupported-message))
      (%client-advance-message client type)
      (when (typep input 'tls13-hello-retry-request)
        (setf (tls-client-expected-message client) :server-hello))
      (when (typep input 'tls13-server-hello)
        (%tls-client-check-server-hello client input)
        (tls-client-check-server-random client
                                         (tls13-server-hello-random input)))
      (when (typep input 'tls13-certificate-request)
        (setf (tls-client-expected-message client) :certificate))
      (when (typep input 'tls13-certificate)
        (setf (tls-client-certificate-message-received client) t))
      (when (typep input 'tls13-encrypted-extensions)
        (let ((extension (find +tls13-extension-application-layer-protocol-negotiation+
                                (tls13-encrypted-extensions-extensions input)
                                :key #'tls-extension-type)))
          (when extension
            (setf (tls-client-alpn client)
                  (first (decode-alpn-extension (tls-extension-data extension)))))))
      (when (and (not (listp input))
                 (or (typep input 'tls13-server-hello)
                (typep input 'tls13-hello-retry-request)
                (typep input 'tls13-encrypted-extensions)
                (typep input 'tls13-certificate)
                (typep input 'tls13-certificate-request)
                (typep input 'tls13-certificate-verify)
                (typep input 'tls13-finished)
                (typep input 'tls13-key-update)))
        (let ((wire (if (typep input 'tls13-hello-retry-request)
                        (let ((body (encode-hello-retry-request input)))
                          (concatenate '(vector (unsigned-byte 8))
                                       #(2 0 0 0) body))
                        (encode-handshake (%client-message-number type) input))))
          (when (typep input 'tls13-hello-retry-request)
            (let ((length (- (length wire) 4)))
              (setf (aref wire 1) (ldb (byte 8 16) length)
                    (aref wire 2) (ldb (byte 8 8) length)
                    (aref wire 3) (ldb (byte 8 0) length))))
          (if (typep input 'tls13-hello-retry-request)
              (%client-hrr-transcript client wire)
              (%client-transcript-add client wire))))))
    (when (typep input 'tls13-hello-retry-request)
      (let ((hello-callback (%provider-callback client :client-hello)))
        (unless hello-callback (%client-fail client :step :missing-retry-client-hello))
        (let ((hello (funcall hello-callback client)))
          (unless (typep hello 'tls13-client-hello)
            (%client-fail client :step :invalid-retry-client-hello))
          (setf (tls-client-client-hello client) hello)
          (incf (tls-client-client-hello-count client))
          (let ((wire (encode-handshake 1 hello)))
            (%client-transcript-add client wire)
            (when (tls-client-transport-write client)
              (funcall (tls-client-transport-write client) client wire))))))
  (let ((callback (%provider-callback client :handshake)))
    (unless callback (%client-fail client :step :missing-handshake-callback))
    (%apply-provider-result client (funcall callback client input))))

(defun tls-client-make-client-hello (client &key random session-id cipher-suites
                                             supported-groups key-share
                                             signature-algorithms)
  "Build a TLS 1.3 ClientHello carrying the configured SNI and ALPN.
The KEY-SHARE value is supplied by the crypto/provider integration."
  (let ((extensions
          (list (make-tls-extension +tls13-extension-supported-versions+ #(2 3 4))
                (make-tls-extension +tls13-extension-supported-groups+
                                     (%encode-vector
                                      (apply #'%cat
                                             (mapcar #'%hs-u16 (or supported-groups '(#x001d))))
                                      2))
                (make-tls-extension +tls13-extension-key-share+
                                     (encode-key-share-extension
                                      (or key-share (list (cons #x001d #()))))))))
    (when (tls-client-hostname client)
      (push (make-tls-extension +tls13-extension-server-name+
                                (encode-sni-extension (tls-client-hostname client)))
            extensions))
    (when (tls-client-alpn-offered client)
      (push (make-tls-extension +tls13-extension-application-layer-protocol-negotiation+
                                (encode-alpn-extension (tls-client-alpn-offered client)))
            extensions))
    (when signature-algorithms
      (push (make-tls-extension +tls13-extension-signature-algorithms+
                                (%client-u16-list signature-algorithms)) extensions))
    (make-tls13-client-hello #x0303
                             (or random (%tls-client-csprng-octets 32))
                             (or session-id (%tls-client-csprng-octets 32))
                             (or cipher-suites #( #x1301 #x1303))
                             (nreverse extensions))))

(defun %client-u16-list (values)
  (let ((body (make-array (* 2 (length values)) :element-type '(unsigned-byte 8))))
    (loop for value in values for i from 0
          do (setf (aref body (* 2 i)) (ldb (byte 8 8) value)
                   (aref body (1+ (* 2 i))) (ldb (byte 8 0) value)))
    (%encode-vector body 2 :minimum 2)))

(defun %tls-client-read-exact (stream buffer)
  (loop with position = 0
        while (< position (length buffer))
        for count = (read-sequence buffer stream :start position)
        do (when (= count position)
             (return-from %tls-client-read-exact nil))
           (setf position count)
        finally (return buffer)))

(defun %tls-client-stream-record-reader (stream)
  (let ((header (make-array 5 :element-type '(unsigned-byte 8))))
    (unless (%tls-client-read-exact stream header)
      (return-from %tls-client-stream-record-reader nil))
    (let* ((length (+ (ash (aref header 3) 8) (aref header 4)))
           (body (make-array length :element-type '(unsigned-byte 8))))
      (unless (%tls-client-read-exact stream body)
        (error 'tls-client-error :client nil :reason :truncated-record))
      (concatenate '(vector (unsigned-byte 8)) header body))))

(defun %make-tls-client-tcp-transport (host port)
  (unless (find-package '#:sb-bsd-sockets)
    (require :sb-bsd-sockets))
  (let* ((socket (funcall (find-symbol "MAKE-INET-SOCKET" '#:sb-bsd-sockets)
                          :stream :tcp))
         (address (funcall (find-symbol "GET-HOST-BY-NAME" '#:sb-bsd-sockets) host))
         (connect (find-symbol "SOCKET-CONNECT" '#:sb-bsd-sockets)))
    (funcall connect socket
             (funcall (find-symbol "HOST-ENT-ADDRESS" '#:sb-bsd-sockets) address) port)
    (let ((stream (funcall (find-symbol "SOCKET-MAKE-STREAM" '#:sb-bsd-sockets) socket
                           :input t :output t :element-type '(unsigned-byte 8))))
      (list :read (lambda (client) (declare (ignore client))
                    (%tls-client-stream-record-reader stream))
            :write (lambda (client bytes) (declare (ignore client))
                     (write-sequence bytes stream) (finish-output stream))
            :close (lambda (client) (declare (ignore client))
                     (close stream)
                     (funcall (find-symbol "SOCKET-CLOSE" '#:sb-bsd-sockets) socket))))))

(defun make-tls-client-over-tcp (host port &rest args &key &allow-other-keys)
  "Open a blocking SBCL TCP stream and return a client using TLS records on it.
This is the portable entry in this minimal implementation; non-SBCL images
must provide TRANSPORT callbacks directly to MAKE-TLS-CLIENT."
  (apply #'make-tls-client :transport (%make-tls-client-tcp-transport host port)
         args))

(defun tls-client-read (client)
  (unless (eq (tls-client-state client) :connected)
    (%client-fail client :read :not-connected))
  (unless (tls-client-transport-read client)
    (%client-fail client :read :missing-transport))
  (let ((record (funcall (tls-client-transport-read client) client)))
    (when record
      (let ((plaintext (if (tls-client-record-unprotect client)
                           (funcall (tls-client-record-unprotect client) client record)
                           record)))
        (when (typep plaintext 'tls-plaintext)
          (cond
            ((tls-close-notify-p plaintext)
             (setf (tls-client-close-notify-received client) t
                   (tls-client-state client) :closed))
            ((and (= (tls-plaintext-content-type plaintext) +tls-content-type-alert+)
                  (= (length (tls-plaintext-fragment plaintext)) 2))
             (error 'tls-client-alert-error
                    :client client :reason :peer-alert
                    :level (aref (tls-plaintext-fragment plaintext) 0)
                    :description (aref (tls-plaintext-fragment plaintext) 1)))
            ((tls-key-update-p plaintext)
             (let ((callback (%provider-callback client :key-update)))
               (unless callback
                 (%client-fail client :read :missing-key-update-callback))
               (%apply-provider-result
                client (funcall callback client
                                (aref (tls-plaintext-fragment plaintext) 4)))))))
        plaintext))))

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
    (setf (tls-client-state client) :closed)
    (when (tls-client-transport-close client)
      (funcall (tls-client-transport-close client) client)))
  client)

(defun tls-client-key-update (client &optional (request 0))
  "Send a post-handshake KeyUpdate through the provider boundary."
  (unless (eq (tls-client-state client) :connected)
    (%client-fail client :key-update :not-connected))
  (unless (member request '(0 1)) (%client-fail client :key-update :invalid-request))
  (let ((callback (%provider-callback client :key-update)))
    (unless callback (%client-fail client :key-update :missing-callback))
    (incf (tls-client-key-update-count client))
    (%apply-provider-result client (funcall callback client request))))

(defun tls-client-connect (client)
  "Start the TLS client and return it after the provider has emitted ClientHello."
  (tls-client-start client))

(export '(tls13-negotiation-error tls13-negotiation-error-field
          tls-client-connect tls-client-key-update))
