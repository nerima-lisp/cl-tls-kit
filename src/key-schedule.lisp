(in-package #:cl-tls-kit)

;;;; TLS 1.3 key schedule (RFC 8446, section 7.1).
;;;; All cryptographic operations cross TLS13-CRYPTO-PROVIDER.  This file does
;;;; not implement a digest or HMAC, and therefore cannot accidentally become
;;;; a second crypto provider.

(define-condition tls13-key-schedule-error (error)
  ((message :initarg :message :reader tls13-key-schedule-error-message))
  (:report (lambda (condition stream)
             (write-string (tls13-key-schedule-error-message condition) stream))))

(defstruct (tls13-crypto-provider
            (:constructor %make-tls13-crypto-provider
                (hkdf-extract hkdf-expand digest-length &optional digest hmac
                 aead-seal aead-open constant-time-equal)))
  hkdf-extract
  hkdf-expand
  digest-length
  digest
  hmac
  aead-seal
  aead-open
  constant-time-equal)

(defun %tls13-error (control &rest args)
  (error 'tls13-key-schedule-error :message (apply #'format nil control args)))

(defun %octets-p (value)
  (and (vectorp value)
       (subtypep (array-element-type value) '(unsigned-byte 8))))

(defun %require-octets (value name)
  (unless (%octets-p value)
    (%tls13-error "~A must be a vector of octets" name))
  value)

(defun %concat-octets (&rest vectors)
  (let ((result (make-array (reduce #'+ vectors :key #'length :initial-value 0)
                            :element-type '(unsigned-byte 8)))
        (position 0))
    (dolist (vector vectors result)
      (replace result vector :start1 position)
      (incf position (length vector)))))

(defun %u8 (value)
  (vector (ldb (byte 8 0) value)))

(defun %u16 (value)
  (vector (ldb (byte 8 8) value) (ldb (byte 8 0) value)))

(defun %tls13-callable (function name)
  (unless (functionp function)
    (%tls13-error "Crypto provider operation ~A is not callable" name))
  function)

(defun %tls13-hash-length (provider hash)
  (let ((length (funcall (%tls13-callable
                         (tls13-crypto-provider-digest-length provider)
                         "DIGEST-LENGTH")
                         hash)))
    (unless (and (integerp length) (plusp length))
      (%tls13-error "Crypto provider returned an invalid digest length"))
    length))

(defun make-cl-crypto-kit-provider ()
  "Return a provider backed by the currently loaded CL-CRYPTO-KIT package.

The provider contract is:
  HKDF-EXTRACT (hash salt ikm) -> octet vector
  HKDF-EXPAND (hash prk info length) -> octet vector
  DIGEST-LENGTH (hash) -> positive integer
  DIGEST (hash octets) -> octet vector
  HMAC (hash key octets) -> octet vector
  AEAD-SEAL (algorithm key nonce plaintext aad) -> octet vector
  AEAD-OPEN (algorithm key nonce ciphertext-and-tag aad) -> octet vector
  CONSTANT-TIME-EQUAL (left right) -> generalized boolean
The package is resolved at call time so this foundation keeps its weak crypto
dependency and does not refer to an uninterned package at read time."
  (let ((package (find-package '#:crypto-kit)))
    (unless package
      (%tls13-error "CL-CRYPTO-KIT is not loaded"))
    (flet ((operation (name)
             (let ((symbol (find-symbol name package)))
               (unless (and symbol (fboundp symbol))
                 (%tls13-error "CL-CRYPTO-KIT:~A is unavailable" name))
               (symbol-function symbol))))
      (%make-tls13-crypto-provider
       (operation "HKDF-EXTRACT")
       (operation "HKDF-EXPAND")
       (operation "DIGEST-LENGTH")
       (operation "DIGEST")
       (operation "HMAC")
       (operation "AEAD-SEAL")
       (operation "AEAD-OPEN")
       (operation "CONSTANT-TIME-EQUAL")))))

(defun %provider (provider)
  (unless (typep provider 'tls13-crypto-provider)
    (%tls13-error "PROVIDER must be a TLS13-CRYPTO-PROVIDER"))
  provider)

(defun tls13-hkdf-extract (provider hash salt ikm)
  "Perform HKDF-Extract through PROVIDER (RFC 5869 section 2.1)."
  (%provider provider)
  (%require-octets salt "SALT")
  (%require-octets ikm "IKM")
  (let ((result (funcall (%tls13-callable (tls13-crypto-provider-hkdf-extract provider)
                                         "HKDF-EXTRACT")
                         hash salt ikm)))
    (%require-octets result "HKDF-Extract result")
    result))

(defun tls13-hkdf-expand-label (provider hash secret label context length)
  "Perform TLS 1.3 HKDF-Expand-Label (RFC 8446 section 7.1)."
  (%provider provider)
  (%require-octets secret "SECRET")
  (%require-octets context "CONTEXT")
  (unless (<= (length context) 255)
    (%tls13-error "CONTEXT must contain at most 255 octets"))
  (unless (and (stringp label) (plusp (length label)) (<= (length label) 249)
               (every (lambda (character) (<= (char-code character) #xff)) label))
    (%tls13-error "LABEL must be a non-empty string of at most 249 octets"))
  (unless (and (integerp length) (<= 0 length) (<= length #xffff))
    (%tls13-error "LENGTH must be an integer between 0 and 65535"))
  (let* ((full-label (concatenate 'string "tls13 " label))
         (label-octets (make-array (length full-label)
                                   :element-type '(unsigned-byte 8)))
         (info nil)
         (result nil))
    (dotimes (index (length full-label))
      (let ((code (char-code (char full-label index))))
        (unless (<= code 127)
          (%tls13-error "LABEL must contain ASCII characters"))
        (setf (aref label-octets index) code)))
    (setf info (%concat-octets (%u16 length)
                               (%u8 (length label-octets)) label-octets
                               (%u8 (length context)) context)
          result (funcall (%tls13-callable
                           (tls13-crypto-provider-hkdf-expand provider)
                           "HKDF-EXPAND")
                          hash secret info length))
    (%require-octets result "HKDF-Expand-Label result")
    (unless (= (length result) length)
      (%tls13-error "Crypto provider returned ~D bytes, expected ~D" (length result) length))
    result))

(defun tls13-derive-secret (provider hash secret label transcript-hash)
  "Perform Derive-Secret (RFC 8446 section 7.1)."
  (%provider provider)
  (let ((hash-length (%tls13-hash-length provider hash)))
    (tls13-hkdf-expand-label provider hash secret label transcript-hash hash-length)))

(defun tls13-empty-hash (provider hash)
  "Return Hash(\"\") through the provider's digest boundary."
  (%provider provider)
  (let ((result (funcall (%tls13-callable (tls13-crypto-provider-digest provider)
                                         "DIGEST")
                         hash (make-array 0 :element-type '(unsigned-byte 8)))))
    (%require-octets result "Empty transcript hash")
    result))

(defun tls13-early-secret (provider hash &optional psk)
  "Derive the early secret from PSK, or the all-zero PSK when omitted."
  (%provider provider)
  (let* ((hash-length (%tls13-hash-length provider hash))
         (psk (or psk (make-array hash-length :element-type '(unsigned-byte 8)))))
    (tls13-hkdf-extract provider hash (make-array hash-length :element-type '(unsigned-byte 8)) psk)))

(defun tls13-handshake-secret (provider hash early-secret dhe-secret)
  "Derive the handshake secret from the early secret and (EC)DHE secret."
  (tls13-hkdf-extract provider hash
                       (tls13-hkdf-expand-label provider hash early-secret "derived"
                                                (tls13-empty-hash provider hash)
                                                (%tls13-hash-length provider hash))
                       dhe-secret))

(defun tls13-master-secret (provider hash handshake-secret)
  "Derive the master secret from the handshake secret."
  (let ((hash-length (%tls13-hash-length provider hash)))
    (tls13-hkdf-extract provider hash
                         (tls13-hkdf-expand-label provider hash handshake-secret "derived"
                                                  (tls13-empty-hash provider hash)
                                                  hash-length)
                         (make-array hash-length :element-type '(unsigned-byte 8)))))

(defun tls13-traffic-key-and-iv (provider hash traffic-secret key-length iv-length)
  "Return two values: TLS record protection key and IV (RFC 8446 section 7.3)."
  (values (tls13-hkdf-expand-label provider hash traffic-secret "key"
                                   (make-array 0 :element-type '(unsigned-byte 8)) key-length)
          (tls13-hkdf-expand-label provider hash traffic-secret "iv"
                                   (make-array 0 :element-type '(unsigned-byte 8)) iv-length)))

(defun tls13-finished-key (provider hash base-key)
  (tls13-hkdf-expand-label provider hash base-key "finished"
                           (make-array 0 :element-type '(unsigned-byte 8))
                       (%tls13-hash-length provider hash)))

(defun tls13-compute-finished-verify-data (provider hash finished-key transcript-hash)
  "Compute Finished verify_data through the provider HMAC boundary."
  (%provider provider)
  (%require-octets transcript-hash "TRANSCRIPT-HASH")
  (let ((hmac (tls13-crypto-provider-hmac provider)))
    (unless (functionp hmac)
      (%tls13-error "Crypto provider HMAC operation is unavailable"))
    (let ((result (funcall hmac hash finished-key transcript-hash)))
      (%require-octets result "Finished verify_data")
      result)))

(defun tls13-provider-constant-time-equal-p (provider left right)
  "Compare two octet vectors through the crypto provider."
  (%provider provider)
  (%require-octets left "LEFT")
  (%require-octets right "RIGHT")
  (let ((operation (tls13-crypto-provider-constant-time-equal provider)))
    (unless (functionp operation)
      (%tls13-error "Crypto provider constant-time comparison is unavailable"))
    (not (null (funcall operation left right)))))

(defun tls13-aead-seal (provider algorithm key nonce plaintext aad)
  "Seal a TLS record payload through the provider's AEAD boundary."
  (%provider provider)
  (%require-octets key "KEY")
  (%require-octets nonce "NONCE")
  (%require-octets plaintext "PLAINTEXT")
  (%require-octets aad "ADDITIONAL-DATA")
  (let ((operation (tls13-crypto-provider-aead-seal provider)))
    (unless (functionp operation)
      (%tls13-error "Crypto provider AEAD-SEAL is unavailable"))
    (%require-octets (funcall operation algorithm key nonce plaintext aad)
                     "AEAD seal result")))

(defun tls13-aead-open (provider algorithm key nonce ciphertext-and-tag aad)
  "Open a TLS record payload through the provider's AEAD boundary."
  (%provider provider)
  (%require-octets key "KEY")
  (%require-octets nonce "NONCE")
  (%require-octets ciphertext-and-tag "CIPHERTEXT-AND-TAG")
  (%require-octets aad "ADDITIONAL-DATA")
  (let ((operation (tls13-crypto-provider-aead-open provider)))
    (unless (functionp operation)
      (%tls13-error "Crypto provider AEAD-OPEN is unavailable"))
    (%require-octets (funcall operation algorithm key nonce ciphertext-and-tag aad)
                     "AEAD open result")))

(defun tls13-resumption-secret (provider hash master-secret transcript-hash)
  (tls13-derive-secret provider hash master-secret "res master" transcript-hash))

(defun tls13-traffic-secret (provider hash base-secret direction transcript-hash
                             &key (phase :handshake))
  "Derive a client or server handshake/application traffic secret.
DIRECTION is :CLIENT or :SERVER. PHASE is :HANDSHAKE or :APPLICATION."
  (unless (member direction '(:client :server))
    (%tls13-error "DIRECTION must be :CLIENT or :SERVER"))
  (unless (member phase '(:handshake :application))
    (%tls13-error "PHASE must be :HANDSHAKE or :APPLICATION"))
  (tls13-derive-secret provider hash base-secret
                       (cond ((and (eq phase :handshake) (eq direction :client)) "c hs traffic")
                             ((eq phase :handshake) "s hs traffic")
                             ((eq direction :client) "c ap traffic")
                             (t "s ap traffic"))
                       transcript-hash))

(defstruct (tls13-traffic-state
            (:constructor %make-tls13-traffic-state
                (provider hash algorithm secret key iv sequence-number)))
  provider hash algorithm secret key iv
  (sequence-number 0 :type (unsigned-byte 64)))

(defun make-tls13-traffic-state (provider hash algorithm secret key-length iv-length)
  "Create a record-protection state with sequence number zero."
  (%provider provider)
  (%require-octets secret "SECRET")
  (multiple-value-bind (key iv)
      (tls13-traffic-key-and-iv provider hash secret key-length iv-length)
    (%make-tls13-traffic-state provider hash algorithm secret key iv 0)))

(defun tls13-update-traffic-secret (state)
  "Apply TLS 1.3 KeyUpdate's traffic secret ratchet and reset its sequence."
  (check-type state tls13-traffic-state)
  (let* ((provider (tls13-traffic-state-provider state))
         (hash (tls13-traffic-state-hash state))
         (secret (tls13-hkdf-expand-label
                  provider hash (tls13-traffic-state-secret state)
                  "traffic upd" (make-array 0 :element-type '(unsigned-byte 8))
                  (%tls13-hash-length provider hash))))
    (multiple-value-bind (key iv)
        (tls13-traffic-key-and-iv provider hash secret
                                   (length (tls13-traffic-state-key state))
                                   (length (tls13-traffic-state-iv state)))
      (setf (tls13-traffic-state-secret state) secret
            (tls13-traffic-state-key state) key
            (tls13-traffic-state-iv state) iv
            (tls13-traffic-state-sequence-number state) 0))
    state))

(export '(tls13-aead-seal tls13-aead-open tls13-provider-constant-time-equal-p
          tls13-traffic-state tls13-traffic-state-p make-tls13-traffic-state
          tls13-traffic-state-provider tls13-traffic-state-hash
          tls13-traffic-state-algorithm tls13-traffic-state-secret
          tls13-traffic-state-key tls13-traffic-state-iv
          tls13-traffic-state-sequence-number tls13-update-traffic-secret))
