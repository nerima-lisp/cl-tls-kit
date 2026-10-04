(in-package #:cl-tls-kit)

(define-condition tls13-client-driver-error (error)
  ((reason :initarg :reason :reader tls13-client-driver-error-reason))
  (:report (lambda (condition stream)
             (format stream "TLS 1.3 client driver error: ~A"
                     (tls13-client-driver-error-reason condition)))))

(defstruct (tls13-client-driver (:constructor %make-tls13-client-driver))
  provider key-exchange on-send verify-certificate-verify
  transport-read transport-write transport-close
  hostname alpn negotiated-alpn cipher-suites supported-groups signature-algorithms
  client-hello private-key selected-group hash suite state
  certificate-chain peer-certificate trust-anchors now verify-signature
  (transcript (make-array 0 :element-type '(unsigned-byte 8)))
  early-secret handshake-secret master-secret handshake-traffic-secret
  client-finished-key server-finished-key
  handshake-read-state handshake-write-state
  application-read-state application-write-state
  (pending-handshake (make-array 0 :element-type '(unsigned-byte 8)))
  close-notify-received)

;; Certificate chains and their per-certificate extensions fit within this
;; policy limit while fragmented input cannot consume the uint24 wire maximum.
(defconstant +tls13-max-handshake-body-length+ (* 1024 1024))

(defun %driver-fail (reason)
  (error 'tls13-client-driver-error :reason reason))

(defun %driver-add-transcript (driver wire)
  (setf (tls13-client-driver-transcript driver)
        (concatenate '(vector (unsigned-byte 8))
                     (tls13-client-driver-transcript driver) wire)))

(defun %driver-digest (driver bytes)
  (funcall (tls13-crypto-provider-digest (tls13-client-driver-provider driver))
           (tls13-client-driver-hash driver) bytes))

(defun %driver-message-hash (driver)
  (let ((digest (%driver-digest driver (tls13-client-driver-transcript driver))))
    (when (> (length digest) #xffffff)
      (%driver-fail :transcript-too-long))
    (%cat (vector #xfe) (%u24 (length digest)) digest)))

(defun %driver-write-record (driver plaintext &optional state)
  (let ((wire (if state
                  (encrypt-tls13-traffic-record plaintext state)
                  (encode-tls-plaintext plaintext))))
    (when (tls13-client-driver-transport-write driver)
      (funcall (tls13-client-driver-transport-write driver) driver wire))
    wire))

(defun %driver-send (driver type message)
  (let ((wire (encode-handshake type message)))
    (%driver-add-transcript driver wire)
    (when (tls13-client-driver-on-send driver)
      (funcall (tls13-client-driver-on-send driver) driver wire))
    (%driver-write-record driver (make-tls-plaintext +tls-content-type-handshake+ wire)
                          (and (eq (tls13-client-driver-state driver) :awaiting-finished)
                               (tls13-client-driver-handshake-write-state driver)))
    wire))

(defun %driver-traffic-algorithm (suite)
  (case suite
    (#x1301 :aes-128-gcm)
    (#x1302 :aes-256-gcm)
    (#x1303 :chacha20-poly1305)
    (#x1304 :aes-128-ccm)
    (otherwise (%driver-fail :unsupported-cipher-suite))))

(defun %driver-make-traffic-state (driver secret)
  (make-tls13-traffic-state
   (tls13-client-driver-provider driver)
   (tls13-client-driver-hash driver)
   (%driver-traffic-algorithm (tls13-client-driver-suite driver))
   secret
   (tls13-cipher-suite-key-length (tls13-client-driver-suite driver)) 12))

(defun %driver-key-share (driver group)
  (let ((generate (and (listp (tls13-client-driver-key-exchange driver))
                       (getf (tls13-client-driver-key-exchange driver) :generate))))
    (unless generate (%driver-fail :missing-key-exchange-generator))
    (multiple-value-bind (private public) (funcall generate group)
      (setf (tls13-client-driver-private-key driver) private
            (tls13-client-driver-selected-group driver) group)
      (cons group public))))

(defun make-tls13-client-driver
    (&key provider key-exchange on-send verify-certificate-verify
          transport-read transport-write transport-close transport hostname alpn
          trust-anchors (now (get-universal-time)) verify-signature
          (cipher-suites #( #x1301 #x1302 #x1303))
          (supported-groups '(#x001d #x0017))
          (signature-algorithms #( #x0804 #x0805 #x0806 #x0403 #x0503)))
  "Create a TLS 1.3 client handshake driver.

The driver owns handshake message sequencing and transcript/key-schedule
progression. KEY-EXCHANGE supplies :GENERATE and :SHARED-SECRET functions;
the crypto provider supplies hash, HKDF, HMAC, and AEAD primitives."
  (unless (typep provider 'tls13-crypto-provider) (%driver-fail :provider))
  (let* ((offered-suites (coerce
                          (remove #x1305 (coerce cipher-suites 'list))
                          'vector))
         (suite (and (plusp (length offered-suites))
                     (aref offered-suites 0))))
    (unless suite (%driver-fail :unsupported-cipher-suite))
    (let ((driver (%make-tls13-client-driver
                   :provider provider :key-exchange key-exchange :on-send on-send
                   :transport-read (or transport-read (getf transport :read))
                   :transport-write (or transport-write (getf transport :write))
                   :transport-close (or transport-close (getf transport :close))
                   :verify-certificate-verify verify-certificate-verify
                   :hostname hostname :alpn alpn :cipher-suites offered-suites
                   :supported-groups supported-groups
                   :signature-algorithms signature-algorithms
                   :trust-anchors trust-anchors :now now
                   :verify-signature verify-signature :suite suite
                   :hash (tls13-cipher-suite-hash suite) :state :new)))
      (setf (tls13-client-driver-early-secret driver)
            (tls13-early-secret provider (tls13-client-driver-hash driver)))
      driver)))

(defun tls13-client-driver-start (driver)
  (unless (eq (tls13-client-driver-state driver) :new)
    (%driver-fail :already-started))
  (let* ((group (first (tls13-client-driver-supported-groups driver)))
         (share (%driver-key-share driver group))
         (random (or (and (listp (tls13-client-driver-key-exchange driver))
                          (getf (tls13-client-driver-key-exchange driver) :random))
                     #'%tls-client-csprng-octets))
         (client (make-tls13-client-hello
                  #x0303
                  (funcall random 32)
                  (funcall random 32)
                  (tls13-client-driver-cipher-suites driver)
                  (append
                   (when (tls13-client-driver-hostname driver)
                     (list (make-tls-extension 0
                                               (encode-sni-extension
                                                (tls13-client-driver-hostname driver)))))
                   (when (tls13-client-driver-alpn driver)
                     (list (make-tls-extension 16
                                               (encode-alpn-extension
                                                (tls13-client-driver-alpn driver)))))
                         (list (make-tls-extension 43 #(2 3 4))
                         (make-tls-extension 10
                                              (%encode-vector
                                               (apply #'%cat
                                                      (mapcar #'%hs-u16
                                                              (tls13-client-driver-supported-groups driver)))
                                               2))
                         (make-tls-extension 13
                                              (%encode-vector
                                               (apply #'%cat
                                                      (map 'list #'%hs-u16
                                                           (tls13-client-driver-signature-algorithms driver)))
                                               2))
                         (make-tls-extension 45 #(1 1))
                         (make-tls-extension 51 (encode-key-share-extension (list share))))))))
    (setf (tls13-client-driver-client-hello driver) client
          (tls13-client-driver-state driver) :awaiting-server-hello)
    (%driver-send driver 1 client)
    driver))

(defun %driver-server-key-share (hello)
  (let ((extension (find 51 (tls13-server-hello-extensions hello)
                        :key #'tls-extension-type)))
    (unless extension (%driver-fail :missing-server-key-share))
    (decode-key-share-server-extension (tls-extension-data extension))))

(defun %driver-install-handshake-secret (driver server-share)
  (let ((shared (getf (tls13-client-driver-key-exchange driver) :shared-secret)))
    (unless shared (%driver-fail :missing-key-exchange-function))
    (let* ((dhe (funcall shared (tls13-client-driver-selected-group driver)
                         (tls13-client-driver-private-key driver) (cdr server-share)))
           (secret (tls13-handshake-secret
                    (tls13-client-driver-provider driver)
                    (tls13-client-driver-hash driver)
                    (tls13-client-driver-early-secret driver) dhe)))
      (setf (tls13-client-driver-handshake-secret driver) secret))))

(defun %driver-certificate-chain (message)
  (let ((entries (tls13-certificate-entries message)))
    (unless entries (%driver-fail :missing-server-certificate))
    (handler-case
        (mapcar (lambda (entry)
                  (cl-tls-kit.x509:parse-certificate-der
                   (tls13-certificate-entry-certificate entry)))
                entries)
      (error (condition)
        (declare (ignore condition))
        (%driver-fail :invalid-server-certificate)))))

(defun %driver-trust-anchors (driver)
  (or (tls13-client-driver-trust-anchors driver)
      (handler-case
          (let ((path (load-trust-store))
                (anchors nil))
            (dolist (block (pem-decode (uiop:read-file-string path)))
              (when (string= (pem-block-label block) "CERTIFICATE")
                (handler-case
                    (push (cl-tls-kit.x509:parse-certificate-der
                           (pem-block-der block))
                          anchors)
                  (error () nil))))
            (unless anchors
              (error 'untrusted-root :certificate nil))
            (setf (tls13-client-driver-trust-anchors driver) anchors))
        (certificate-verification-error (condition)
          (error condition))
        (error (condition)
          (declare (ignore condition))
          (error 'invalid-certificate-chain :certificate nil)))))

(defun %driver-verify-certificate-chain (driver chain)
  (handler-case
      (verify-certificate-chain
       chain :hostname (tls13-client-driver-hostname driver)
       :trust-anchors (%driver-trust-anchors driver)
       :now (tls13-client-driver-now driver)
       :verify-signature (tls13-client-driver-verify-signature driver))
    (certificate-verification-error (condition)
      (%driver-fail (list :certificate-verification-failed
                          :condition condition
                          :certificate (verification-error-certificate condition))))))

(defun tls13-client-driver-step (driver wire)
  "Consume one complete TLS handshake message and advance DRIVER.
Returns DRIVER; outgoing messages are delivered to ON-SEND."
  (let* ((bytes (coerce wire '(vector (unsigned-byte 8))))
         (message (decode-handshake bytes))
         (type (aref bytes 0))
         (prior-transcript (tls13-client-driver-transcript driver)))
    (when (and (eq (tls13-client-driver-state driver) :connected)
               (typep message 'tls13-key-update))
      (tls13-update-traffic-secret
       (tls13-client-driver-application-read-state driver))
      (when (= (tls13-key-update-request message) 1)
        (tls13-client-driver-key-update driver 0))
      (return-from tls13-client-driver-step driver))
    (when (and (eq (tls13-client-driver-state driver) :connected)
               (typep message 'tls13-new-session-ticket))
      (return-from tls13-client-driver-step driver))
    (when (and (= type 2) (typep message 'tls13-hello-retry-request))
      (unless (eq (tls13-client-driver-state driver) :awaiting-server-hello)
        (%driver-fail :unexpected-hrr))
      (setf (tls13-client-driver-transcript driver)
            (concatenate '(vector (unsigned-byte 8))
                         (%driver-message-hash driver)
                         bytes))
      (let* ((group (tls13-hello-retry-request-selected-group message))
             (initial-group (tls13-client-driver-selected-group driver)))
        (unless (member group (tls13-client-driver-supported-groups driver))
          (%driver-fail :hrr-unsupported-group))
        (when (= group initial-group)
          (%driver-fail :hrr-repeated-group))
        (let ((share (%driver-key-share driver group))
              (hello (tls13-client-driver-client-hello driver)))
          (setf (tls13-client-driver-client-hello driver)
                (make-tls13-client-hello
                 (tls13-client-hello-legacy-version hello)
                 (tls13-client-hello-random hello)
                 (tls13-client-hello-session-id hello)
                 (tls13-client-hello-cipher-suites hello)
                 (cons (make-tls-extension 51 (encode-key-share-extension (list share)))
                       (remove 51 (tls13-client-hello-extensions hello)
                               :key #'tls-extension-type)))))
        (%driver-send driver 1 (tls13-client-driver-client-hello driver))
      (return-from tls13-client-driver-step driver)))
    (unless (member (tls13-client-driver-state driver)
                    '(:awaiting-server-hello :awaiting-encrypted-extensions
                      :awaiting-certificate :awaiting-certificate-verify
                      :awaiting-finished))
      (%driver-fail :unexpected-message))
    (%driver-add-transcript driver bytes)
    (typecase message
      (tls13-server-hello
       (%tls-client-check-server-hello nil message)
       (handler-case
           (tls-client-check-server-random nil
                                           (tls13-server-hello-random message))
         (tls12-downgrade-sentinel (condition)
           (declare (ignore condition))
           (%driver-fail :downgrade-sentinel)))
       (unless (member (tls13-server-hello-cipher-suite message)
                       (coerce (tls13-client-driver-cipher-suites driver) 'list))
         (%driver-fail :unoffered-cipher-suite))
       (let ((server-share (%driver-server-key-share message)))
         (unless (member (car server-share)
                         (tls13-client-driver-supported-groups driver))
           (%driver-fail :unrequested-key-share-group)))
       (setf (tls13-client-driver-suite driver)
             (tls13-server-hello-cipher-suite message)
             (tls13-client-driver-hash driver)
             (tls13-cipher-suite-hash (tls13-server-hello-cipher-suite message)))
       (setf (tls13-client-driver-early-secret driver)
             (tls13-early-secret
              (tls13-client-driver-provider driver)
              (tls13-client-driver-hash driver)))
       (%driver-install-handshake-secret driver (%driver-server-key-share message))
       (let* ((provider (tls13-client-driver-provider driver))
              (hash (tls13-client-driver-hash driver))
              (transcript-hash (%driver-digest driver
                                               (tls13-client-driver-transcript driver)))
              (server-secret (tls13-derive-secret
                              provider hash
                              (tls13-client-driver-handshake-secret driver)
                              "s hs traffic" transcript-hash))
              (client-secret (tls13-derive-secret
                              provider hash
                              (tls13-client-driver-handshake-secret driver)
                              "c hs traffic" transcript-hash)))
         (setf (tls13-client-driver-server-finished-key driver)
               (tls13-finished-key provider hash server-secret)
               (tls13-client-driver-client-finished-key driver)
               (tls13-finished-key provider hash client-secret)
               (tls13-client-driver-handshake-read-state driver)
               (%driver-make-traffic-state driver server-secret)
               (tls13-client-driver-handshake-write-state driver)
               (%driver-make-traffic-state driver client-secret)))
       (setf (tls13-client-driver-state driver) :awaiting-encrypted-extensions))
      (tls13-encrypted-extensions
       (let ((extension (find +tls13-extension-application-layer-protocol-negotiation+
                              (tls13-encrypted-extensions-extensions message)
                              :key #'tls-extension-type)))
         (when extension
           (let ((protocols (decode-alpn-extension (tls-extension-data extension))))
             (unless (member (first protocols) (tls13-client-driver-alpn driver)
                             :test #'string=)
               (%driver-fail :unexpected-alpn))
             (setf (tls13-client-driver-negotiated-alpn driver)
                   (first protocols)))))
       (setf (tls13-client-driver-state driver) :awaiting-certificate))
      (tls13-certificate
       (let ((chain (%driver-certificate-chain message)))
         (setf (tls13-client-driver-certificate-chain driver) chain
               (tls13-client-driver-peer-certificate driver) (first chain))
         (%driver-verify-certificate-chain driver chain))
       (setf (tls13-client-driver-state driver) :awaiting-certificate-verify))
      (tls13-certificate-verify
       (let ((certificate (tls13-client-driver-peer-certificate driver)))
         (unless certificate (%driver-fail :missing-server-certificate))
         (when (tls13-client-driver-verify-certificate-verify driver)
           (funcall (tls13-client-driver-verify-certificate-verify driver) message))
         (handler-case
             (tls13-verify-certificate-verify
              (tls13-client-driver-client-hello driver) :server
              (cl-tls-kit.x509:x509-certificate-public-key certificate)
              (tls13-certificate-verify-algorithm message)
              (tls13-certificate-verify-signature message)
              (%driver-digest driver prior-transcript)
              (tls13-client-driver-verify-signature driver))
           (tls13-verification-error (condition)
             (%driver-fail (list :certificate-verify-failed
                                 (tls13-verification-error-reason condition))))))
       (setf (tls13-client-driver-state driver) :awaiting-finished))
      (tls13-finished
       (unless (tls13-verify-finished
                (tls13-compute-finished-verify-data
                 (tls13-client-driver-provider driver)
                 (tls13-client-driver-hash driver)
                 (tls13-client-driver-server-finished-key driver)
                 (%driver-digest driver prior-transcript))
                (tls13-finished-verify-data message))
         (%driver-fail :finished-mismatch))
       (let* ((provider (tls13-client-driver-provider driver))
              (master (tls13-master-secret
                       provider (tls13-client-driver-hash driver)
                       (tls13-client-driver-handshake-secret driver)))
              (transcript-hash (%driver-digest driver
                                               (tls13-client-driver-transcript driver)))
              (server-secret
                (tls13-traffic-secret provider (tls13-client-driver-hash driver)
                                      master :server transcript-hash
                                      :phase :application))
              (client-secret
                (tls13-traffic-secret provider (tls13-client-driver-hash driver)
                                      master :client transcript-hash
                                      :phase :application)))
         (setf (tls13-client-driver-master-secret driver) master
               (tls13-client-driver-application-read-state driver)
               (%driver-make-traffic-state driver server-secret)
               (tls13-client-driver-application-write-state driver)
               (%driver-make-traffic-state driver client-secret)))
       (let ((verify-data
               (tls13-compute-finished-verify-data
                (tls13-client-driver-provider driver)
                (tls13-client-driver-hash driver)
                (tls13-client-driver-client-finished-key driver)
                (%driver-digest driver (tls13-client-driver-transcript driver)))))
         (%driver-send driver 20 (make-tls13-finished verify-data)))
       (setf (tls13-client-driver-state driver) :connected))
      (otherwise (%driver-fail :unexpected-message)))
    driver))

(defun %driver-read-record (driver)
  (unless (tls13-client-driver-transport-read driver)
    (%driver-fail :missing-transport-reader))
  (funcall (tls13-client-driver-transport-read driver) driver))

(defun %driver-decrypt-record (driver wire)
  (let ((state (if (eq (tls13-client-driver-state driver) :connected)
                   (tls13-client-driver-application-read-state driver)
                   (tls13-client-driver-handshake-read-state driver))))
    (if state
        (decrypt-tls13-traffic-record wire state)
        (decode-tls-plaintext wire))))

(defun %driver-feed-handshake (driver bytes)
  (let ((pending (tls13-client-driver-pending-handshake driver)))
    (when (> (+ (length pending) (length bytes))
             (+ 4 +tls13-max-handshake-body-length+))
      (%driver-fail :decode-error))
    (setf (tls13-client-driver-pending-handshake driver)
          (concatenate '(vector (unsigned-byte 8)) pending bytes)))
  (loop for pending = (tls13-client-driver-pending-handshake driver)
        while (>= (length pending) 4)
        for length = (+ (ash (aref pending 1) 16)
                        (ash (aref pending 2) 8)
                        (aref pending 3))
        do (when (> length +tls13-max-handshake-body-length+)
             (%driver-fail :decode-error))
        while (>= (length pending) (+ 4 length))
        do (let ((message-wire (subseq pending 0 (+ 4 length))))
             (setf (tls13-client-driver-pending-handshake driver)
                   (subseq pending (+ 4 length)))
             (if (and (eq (tls13-client-driver-state driver) :connected)
                      (= (aref message-wire 0) 24))
                 (let ((message (decode-handshake message-wire)))
                   (tls13-update-traffic-secret
                    (tls13-client-driver-application-read-state driver))
                   (when (= (tls13-key-update-request message) 1)
                     (tls13-client-driver-key-update driver 0)))
                 (tls13-client-driver-step driver message-wire)))))

(defun tls13-client-driver-read-record (driver)
  "Read one blocking TLS record and process handshake/control records.
Returns application plaintext, NIL for a consumed handshake or KeyUpdate,
and marks the driver closed after a peer close_notify."
  (let* ((wire (%driver-read-record driver))
         (ignore-eof (unless wire (%driver-fail :eof))))
    (when (= (aref wire 0) +tls-content-type-change-cipher-spec+)
      (unless (and (member (tls13-client-driver-state driver)
                           '(:awaiting-server-hello :awaiting-encrypted-extensions
                             :awaiting-certificate :awaiting-certificate-verify
                             :awaiting-finished))
                   (= (length wire) 6)
                   (= (aref wire 3) 0)
                   (= (aref wire 4) 1)
                   (= (aref wire 5) 1))
        (%driver-fail :unexpected-message))
      (return-from tls13-client-driver-read-record nil))
    (let ((plaintext (if (and (eq (tls13-client-driver-state driver) :awaiting-server-hello)
                              (not (tls13-client-driver-handshake-read-state driver)))
                         (decode-tls-plaintext wire)
                         (%driver-decrypt-record driver wire))))
      (cond
        ((= (tls-plaintext-content-type plaintext)
            +tls-content-type-change-cipher-spec+)
         (%driver-fail :unexpected-message))
        ((tls-close-notify-p plaintext)
       (setf (tls13-client-driver-close-notify-received driver) t
             (tls13-client-driver-state driver) :closed)
       nil)
        ((and (= (tls-plaintext-content-type plaintext) +tls-content-type-alert+)
              (= (length (tls-plaintext-fragment plaintext)) 2))
         (%driver-fail (list :peer-alert
                             (aref (tls-plaintext-fragment plaintext) 0)
                             (aref (tls-plaintext-fragment plaintext) 1))))
        ((= (tls-plaintext-content-type plaintext) +tls-content-type-handshake+)
         (%driver-feed-handshake driver (tls-plaintext-fragment plaintext))
         nil)
        ((and (eq (tls13-client-driver-state driver) :connected)
              (= (tls-plaintext-content-type plaintext)
                 +tls-content-type-application-data+))
         plaintext)
        (t (%driver-fail :unexpected-record))))))

(defun tls13-client-driver-connect (driver)
  "Start DRIVER and block until the TLS 1.3 handshake reaches :CONNECTED."
  (tls13-client-driver-start driver)
  (loop until (eq (tls13-client-driver-state driver) :connected)
        do (tls13-client-driver-read-record driver))
  driver)

(defun tls13-client-driver-write (driver fragment)
  "Encrypt and write application data after the handshake."
  (unless (eq (tls13-client-driver-state driver) :connected)
    (%driver-fail :not-connected))
  (unless (tls13-client-driver-transport-write driver)
    (%driver-fail :missing-transport-writer))
  (%driver-write-record driver
                        (make-tls-plaintext +tls-content-type-application-data+
                                            fragment)
                        (tls13-client-driver-application-write-state driver)))

(defun tls13-client-driver-close (driver)
  "Send one encrypted close_notify and close the underlying transport."
  (unless (eq (tls13-client-driver-state driver) :closed)
    (when (eq (tls13-client-driver-state driver) :connected)
      (%driver-write-record
       driver (make-tls-plaintext +tls-content-type-alert+ #(1 0))
       (tls13-client-driver-application-write-state driver)))
    (setf (tls13-client-driver-state driver) :closed)
    (when (tls13-client-driver-transport-close driver)
      (funcall (tls13-client-driver-transport-close driver) driver)))
  driver)

(defun tls13-client-driver-key-update (driver &optional (request 0))
  "Send an encrypted KeyUpdate and ratchet the write traffic secret."
  (unless (and (eq (tls13-client-driver-state driver) :connected)
               (member request '(0 1)))
    (%driver-fail :invalid-key-update))
  (let ((wire (encode-handshake 24 (make-tls13-key-update request))))
    (when (tls13-client-driver-on-send driver)
      (funcall (tls13-client-driver-on-send driver) driver wire))
    (%driver-write-record
     driver (make-tls-plaintext +tls-content-type-handshake+ wire)
     (tls13-client-driver-application-write-state driver))
    (tls13-update-traffic-secret
     (tls13-client-driver-application-write-state driver)))
  driver)

(defun make-tls13-client-driver-over-tcp
    (host port &rest args &key &allow-other-keys)
  "Open a blocking SBCL TCP stream and attach it to a TLS 1.3 driver."
  (apply #'make-tls13-client-driver
         :transport (%make-tls-client-tcp-transport host port)
         args))

(export '(tls13-client-driver tls13-client-driver-p make-tls13-client-driver
          tls13-client-driver-start tls13-client-driver-step
          tls13-client-driver-connect tls13-client-driver-read-record
          tls13-client-driver-write tls13-client-driver-close
          tls13-client-driver-key-update make-tls13-client-driver-over-tcp
          tls13-client-driver-negotiated-alpn
          tls13-client-driver-error tls13-client-driver-error-reason))
