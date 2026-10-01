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
                (hkdf-extract hkdf-expand digest-length digest)))
  hkdf-extract
  hkdf-expand
  digest-length
  digest)

(defun %tls13-error (control &rest args)
  (error 'tls13-key-schedule-error :message (apply #'format nil control args)))

(defun %octets-p (value)
  (and (vectorp value)
       (subtypep (array-element-type value) '(unsigned-byte 8))))

(defun %require-octets (value name)
  (unless (%octets-p value)
    (%tls13-error "~A must be a vector of octets, got ~S" name value))
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

(defun make-cl-crypto-kit-provider ()
  "Return a provider backed by the currently loaded CL-CRYPTO-KIT package.

The provider contract is:
  HKDF-EXTRACT (hash salt ikm) -> octet vector
  HKDF-EXPAND (hash prk info length) -> octet vector
  DIGEST-LENGTH (hash) -> positive integer
  DIGEST (hash octets) -> octet vector
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
       (operation "DIGEST")))))

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
  (unless (and (stringp label) (<= (length label) 249))
    (%tls13-error "LABEL must be a string of at most 249 characters"))
  (unless (and (integerp length) (<= 0 length #xffff))
    (%tls13-error "LENGTH must be an integer between 0 and 65535"))
  (let* ((full-label (concatenate 'string "tls13 " label))
         (label-octets (make-array (length full-label)
                                   :element-type '(unsigned-byte 8)
                                   :initial-contents (map 'list #'char-code full-label)))
         (info (%concat-octets (%u16 length)
                               (%u8 (length label-octets)) label-octets
                               (%u8 (length context)) context))
         (result (funcall (%tls13-callable (tls13-crypto-provider-hkdf-expand provider)
                                           "HKDF-EXPAND")
                          hash secret info length)))
    (%require-octets result "HKDF-Expand-Label result")
    (unless (= (length result) length)
      (%tls13-error "Crypto provider returned ~D bytes, expected ~D" (length result) length))
    result))

(defun tls13-derive-secret (provider hash secret label transcript-hash)
  "Perform Derive-Secret (RFC 8446 section 7.1)."
  (%provider provider)
  (let ((hash-length (funcall (%tls13-callable
                               (tls13-crypto-provider-digest-length provider)
                               "DIGEST-LENGTH") hash)))
    (unless (and (integerp hash-length) (plusp hash-length))
      (%tls13-error "Crypto provider returned an invalid digest length"))
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
  (let* ((hash-length (funcall (tls13-crypto-provider-digest-length provider) hash))
         (psk (or psk (make-array hash-length :element-type '(unsigned-byte 8)))))
    (tls13-hkdf-extract provider hash (make-array hash-length :element-type '(unsigned-byte 8)) psk)))

(defun tls13-handshake-secret (provider hash early-secret dhe-secret)
  "Derive the handshake secret from the early secret and (EC)DHE secret."
  (tls13-hkdf-extract provider hash
                       (tls13-hkdf-expand-label provider hash early-secret "derived"
                                                (make-array 0 :element-type '(unsigned-byte 8))
                                                (funcall (tls13-crypto-provider-digest-length provider) hash))
                       dhe-secret))

(defun tls13-master-secret (provider hash handshake-secret)
  "Derive the master secret from the handshake secret."
  (tls13-hkdf-extract provider hash
                       (tls13-hkdf-expand-label provider hash handshake-secret "derived"
                                                (make-array 0 :element-type '(unsigned-byte 8))
                                                (funcall (tls13-crypto-provider-digest-length provider) hash))
                       (make-array 0 :element-type '(unsigned-byte 8))))

(defun tls13-traffic-key-and-iv (provider hash traffic-secret key-length iv-length)
  "Return two values: TLS record protection key and IV (RFC 8446 section 7.3)."
  (values (tls13-hkdf-expand-label provider hash traffic-secret "key"
                                   (make-array 0 :element-type '(unsigned-byte 8)) key-length)
          (tls13-hkdf-expand-label provider hash traffic-secret "iv"
                                   (make-array 0 :element-type '(unsigned-byte 8)) iv-length)))

(defun tls13-finished-key (provider hash base-key)
  (tls13-hkdf-expand-label provider hash base-key "finished"
                           (make-array 0 :element-type '(unsigned-byte 8))
                           (funcall (tls13-crypto-provider-digest-length provider) hash)))

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
