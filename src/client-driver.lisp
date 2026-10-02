(in-package #:cl-tls-kit)

(define-condition tls13-client-driver-error (error)
  ((reason :initarg :reason :reader tls13-client-driver-error-reason))
  (:report (lambda (condition stream)
             (format stream "TLS 1.3 client driver error: ~A"
                     (tls13-client-driver-error-reason condition)))))

(defstruct (tls13-client-driver (:constructor %make-tls13-client-driver))
  provider key-exchange on-send verify-certificate-verify
  hostname alpn cipher-suites supported-groups signature-algorithms
  client-hello private-key selected-group hash suite state
  certificate-chain peer-certificate trust-anchors now verify-signature
  (transcript (make-array 0 :element-type '(unsigned-byte 8)))
  early-secret handshake-secret master-secret handshake-traffic-secret
  client-finished-key server-finished-key)

(defun %driver-fail (reason)
  (error 'tls13-client-driver-error :reason reason))

(defun %driver-add-transcript (driver wire)
  (setf (tls13-client-driver-transcript driver)
        (concatenate '(vector (unsigned-byte 8))
                     (tls13-client-driver-transcript driver) wire)))

(defun %driver-digest (driver bytes)
  (funcall (tls13-crypto-provider-digest (tls13-client-driver-provider driver))
           (tls13-client-driver-hash driver) bytes))

(defun %driver-send (driver type message)
  (let ((wire (encode-handshake type message)))
    (%driver-add-transcript driver wire)
    (when (tls13-client-driver-on-send driver)
      (funcall (tls13-client-driver-on-send driver) driver wire))
    wire))

(defun %driver-key-share (driver group)
  (let ((generate (and (listp (tls13-client-driver-key-exchange driver))
                       (getf (tls13-client-driver-key-exchange driver) :generate))))
    (unless generate (%driver-fail :missing-key-exchange-generator))
    (multiple-value-bind (private public) (funcall generate group)
      (setf (tls13-client-driver-private-key driver) private
            (tls13-client-driver-selected-group driver) group)
      (cons group public))))

(defun make-tls13-client-driver
    (&key provider key-exchange on-send verify-certificate-verify hostname alpn
          trust-anchors (now (get-universal-time)) verify-signature
          (cipher-suites #( #x1301 #x1302 #x1303))
          (supported-groups '(#x001d #x0017))
          (signature-algorithms #( #x0804 #x0805 #x0806 #x0403 #x0503)))
  "Create a TLS 1.3 client handshake driver.

The driver owns handshake message sequencing and transcript/key-schedule
progression. KEY-EXCHANGE supplies :GENERATE and :SHARED-SECRET functions;
the crypto provider supplies hash, HKDF, HMAC, and AEAD primitives."
  (unless (typep provider 'tls13-crypto-provider) (%driver-fail :provider))
  (let* ((suite (aref cipher-suites 0))
         (driver (%make-tls13-client-driver
                  :provider provider :key-exchange key-exchange :on-send on-send
                  :verify-certificate-verify verify-certificate-verify
                  :hostname hostname :alpn alpn :cipher-suites cipher-suites
                  :supported-groups supported-groups
                  :signature-algorithms signature-algorithms
                  :trust-anchors trust-anchors :now now
                  :verify-signature verify-signature :suite suite
                  :hash (tls13-cipher-suite-hash suite) :state :new)))
    (setf (tls13-client-driver-early-secret driver)
          (tls13-early-secret provider (tls13-client-driver-hash driver)))
    driver))

(defun tls13-client-driver-start (driver)
  (unless (eq (tls13-client-driver-state driver) :new)
    (%driver-fail :already-started))
  (let* ((group (first (tls13-client-driver-supported-groups driver)))
         (share (%driver-key-share driver group))
         (client (make-tls13-client-hello
                  #x0303
                  (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element 0)
                  #()
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
                   (list (make-tls-extension 43 #(0 2 3 4))
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

(defun %driver-verify-certificate-chain (driver chain)
  (when (tls13-client-driver-trust-anchors driver)
    (handler-case
        (verify-certificate-chain
         chain :hostname (tls13-client-driver-hostname driver)
         :trust-anchors (tls13-client-driver-trust-anchors driver)
         :now (tls13-client-driver-now driver)
         :verify-signature (tls13-client-driver-verify-signature driver))
      (certificate-verification-error (condition)
        (%driver-fail (list :certificate-verification-failed
                            :condition condition
                            :certificate (verification-error-certificate condition)))))))

(defun tls13-client-driver-step (driver wire)
  "Consume one complete TLS handshake message and advance DRIVER.
Returns DRIVER; outgoing messages are delivered to ON-SEND."
  (let* ((bytes (coerce wire '(vector (unsigned-byte 8))))
         (message (decode-handshake bytes))
         (type (aref bytes 0))
         (prior-transcript (tls13-client-driver-transcript driver)))
    (when (and (= type 2) (typep message 'tls13-hello-retry-request))
      (unless (eq (tls13-client-driver-state driver) :awaiting-server-hello)
        (%driver-fail :unexpected-hrr))
      (setf (tls13-client-driver-transcript driver)
            (concatenate '(vector (unsigned-byte 8))
                         #(254 0 0 0)
                         (%driver-digest driver
                                         (tls13-client-driver-transcript driver))
                         bytes))
      (let* ((group (tls13-hello-retry-request-selected-group message))
             (share (%driver-key-share driver group))
             (hello (tls13-client-driver-client-hello driver)))
        (setf (tls13-client-driver-client-hello driver)
              (make-tls13-client-hello
               (tls13-client-hello-legacy-version hello)
               (tls13-client-hello-random hello)
               (tls13-client-hello-session-id hello)
               (tls13-client-hello-cipher-suites hello)
               (cons (make-tls-extension 51 (encode-key-share-extension (list share)))
                     (remove 51 (tls13-client-hello-extensions hello)
                             :key #'tls-extension-type))))
      )
      (%driver-send driver 1 (tls13-client-driver-client-hello driver))
      (return-from tls13-client-driver-step driver))
    (unless (member (tls13-client-driver-state driver)
                    '(:awaiting-server-hello :awaiting-encrypted-extensions
                      :awaiting-certificate :awaiting-certificate-verify
                      :awaiting-finished))
      (%driver-fail :unexpected-message))
    (%driver-add-transcript driver bytes)
    (typecase message
      (tls13-server-hello
       (%tls-client-check-server-hello nil message)
       (setf (tls13-client-driver-suite driver)
             (tls13-server-hello-cipher-suite message)
             (tls13-client-driver-hash driver)
             (tls13-cipher-suite-hash (tls13-server-hello-cipher-suite message)))
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
               (tls13-finished-key provider hash client-secret)))
       (setf (tls13-client-driver-state driver) :awaiting-encrypted-extensions))
      (tls13-encrypted-extensions
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

(export '(tls13-client-driver tls13-client-driver-p make-tls13-client-driver
          tls13-client-driver-start tls13-client-driver-step
          tls13-client-driver-error tls13-client-driver-error-reason))
