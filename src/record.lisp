(in-package #:cl-tls-kit)

;;; TLS 1.3 records deliberately depend on no particular crypto library.  An
;;; AEAD provider receives (key nonce input additional-data) and returns an
;;; octet vector.  The provider owns authentication and the tag format.

(defconstant +tls-record-version+ #x0303)
(defconstant +tls-plaintext-limit+ (expt 2 14))
(defconstant +tls-ciphertext-limit+ (+ (expt 2 14) 256))
(defconstant +tls-content-type-change-cipher-spec+ 20)
(defconstant +tls-content-type-alert+ 21)
(defconstant +tls-content-type-handshake+ 22)
(defconstant +tls-content-type-application-data+ 23)
(defconstant +tls-handshake-key-update+ 24)
(defconstant +tls-alert-close-notify+ 0)

(define-condition tls-record-error (error)
  ((reason :initarg :reason :reader tls-record-error-reason))
  (:report (lambda (condition stream)
             (format stream "TLS record error: ~A"
                     (tls-record-error-reason condition)))))
(define-condition tls-record-overflow (tls-record-error) ())
(define-condition tls-invalid-record (tls-record-error) ())
(define-condition tls-sequence-overflow (tls-record-error) ())
(define-condition tls-aead-error (tls-record-error) ())

(defstruct (tls-plaintext (:constructor %make-tls-plaintext (content-type fragment)))
  (content-type 23 :type (unsigned-byte 8))
  fragment)

(defstruct (tls-ciphertext (:constructor %make-tls-ciphertext
                                           (content-type legacy-version fragment)))
  (content-type 23 :type (unsigned-byte 8))
  (legacy-version +tls-record-version+ :type (unsigned-byte 16))
  fragment)

(defun %record-octets (object)
  (if (and (vectorp object)
           (every (lambda (byte) (typep byte '(unsigned-byte 8))) object))
      (coerce object '(vector (unsigned-byte 8)))
      (error 'type-error :datum object
             :expected-type '(vector (unsigned-byte 8)))))

(defun %record-fail (type reason)
  (error type :reason reason))

(defun %valid-content-type-p (type)
  (member type '(20 21 22 23)))

(defun %valid-plaintext-fragment-p (content-type fragment)
  (or (not (member content-type (list +tls-content-type-alert+
                                      +tls-content-type-handshake+)))
      (plusp (length fragment))))

(defun make-tls-plaintext (content-type fragment)
  (check-type content-type (unsigned-byte 8))
  (unless (%valid-content-type-p content-type)
    (%record-fail 'tls-invalid-record "invalid content type"))
  (let ((bytes (%record-octets fragment)))
    (when (> (length bytes) +tls-plaintext-limit+)
      (%record-fail 'tls-record-overflow "TLSPlaintext exceeds 2^14 octets"))
    (unless (%valid-plaintext-fragment-p content-type bytes)
      (%record-fail 'tls-invalid-record "empty handshake or alert fragment"))
    (%make-tls-plaintext content-type bytes)))

(defun encode-tls-plaintext (record)
  (check-type record tls-plaintext)
  (let ((fragment (%record-octets (tls-plaintext-fragment record))))
    (when (> (length fragment) +tls-plaintext-limit+)
      (%record-fail 'tls-record-overflow "TLSPlaintext exceeds 2^14 octets"))
    (concatenate '(vector (unsigned-byte 8))
                 (vector (tls-plaintext-content-type record)
                         #x03 #x03
                         (ldb (byte 8 8) (length fragment))
                         (ldb (byte 8 0) (length fragment)))
                 fragment)))

(defun decode-tls-plaintext (wire)
  (let ((bytes (%record-octets wire)))
    (when (< (length bytes) 5)
      (%record-fail 'tls-invalid-record "truncated TLSPlaintext header"))
    (let ((type (aref bytes 0))
          (version (+ (ash (aref bytes 1) 8) (aref bytes 2)))
          (length (+ (ash (aref bytes 3) 8) (aref bytes 4))))
      (unless (%valid-content-type-p type)
        (%record-fail 'tls-invalid-record "invalid TLSPlaintext content type"))
      (unless (= version +tls-record-version+)
        (%record-fail 'tls-invalid-record "invalid legacy_record_version"))
      (when (> length +tls-plaintext-limit+)
        (%record-fail 'tls-record-overflow "TLSPlaintext length exceeds 2^14"))
      (unless (= (+ 5 length) (length bytes))
        (%record-fail 'tls-invalid-record "TLSPlaintext length mismatch"))
      (make-tls-plaintext type (subseq bytes 5)))))

(defun make-tls-ciphertext (content-type fragment &key (legacy-version +tls-record-version+))
  (unless (%valid-content-type-p content-type)
    (%record-fail 'tls-invalid-record "invalid content type"))
  (unless (= legacy-version +tls-record-version+)
    (%record-fail 'tls-invalid-record "invalid legacy_record_version"))
  (let ((bytes (%record-octets fragment)))
    (when (> (length bytes) +tls-ciphertext-limit+)
      (%record-fail 'tls-record-overflow "TLSCiphertext exceeds 2^14+256 octets"))
    (%make-tls-ciphertext content-type legacy-version bytes)))

(defun encode-tls-ciphertext (record)
  (check-type record tls-ciphertext)
  (let ((fragment (%record-octets (tls-ciphertext-fragment record))))
    (when (> (length fragment) +tls-ciphertext-limit+)
      (%record-fail 'tls-record-overflow "TLSCiphertext exceeds 2^14+256 octets"))
    (concatenate '(vector (unsigned-byte 8))
                 (vector (tls-ciphertext-content-type record)
                         (ldb (byte 8 8) (tls-ciphertext-legacy-version record))
                         (ldb (byte 8 0) (tls-ciphertext-legacy-version record))
                         (ldb (byte 8 8) (length fragment))
                         (ldb (byte 8 0) (length fragment)))
                 fragment)))

(defun decode-tls-ciphertext (wire)
  (let ((bytes (%record-octets wire)))
    (when (< (length bytes) 5)
      (%record-fail 'tls-invalid-record "truncated TLSCiphertext header"))
    (let ((type (aref bytes 0))
          (version (+ (ash (aref bytes 1) 8) (aref bytes 2)))
          (length (+ (ash (aref bytes 3) 8) (aref bytes 4))))
      (unless (= type +tls-content-type-application-data+)
        (%record-fail 'tls-invalid-record "TLS 1.3 ciphertext type is not application_data"))
      (unless (= version +tls-record-version+)
        (%record-fail 'tls-invalid-record "invalid legacy_record_version"))
      (when (> length +tls-ciphertext-limit+)
        (%record-fail 'tls-record-overflow "TLSCiphertext length exceeds 2^14+256"))
      (unless (= (+ 5 length) (length bytes))
        (%record-fail 'tls-invalid-record "TLSCiphertext length mismatch"))
      (%make-tls-ciphertext type version (subseq bytes 5)))))

(defun tls-record-additional-data (content-type ciphertext-length)
  "Return the five-byte TLSCiphertext header authenticated as additional data."
  (check-type ciphertext-length (integer 0 #xffff))
  (unless (%valid-content-type-p content-type)
    (%record-fail 'tls-invalid-record "invalid content type"))
  (make-array 5 :element-type '(unsigned-byte 8)
              :initial-contents
              (list content-type #x03 #x03
                    (ldb (byte 8 8) ciphertext-length)
                    (ldb (byte 8 0) ciphertext-length))))

(defun tls-record-nonce (iv sequence-number)
  "Compute the TLS 1.3 nonce: left-zero-padded sequence XOR static IV."
  (let ((iv-bytes (%record-octets iv)))
    (unless (= (length iv-bytes) 12)
      (%record-fail 'tls-invalid-record "TLS 1.3 AEAD IV must be 12 octets"))
    (unless (typep sequence-number '(unsigned-byte 64))
      (%record-fail 'tls-sequence-overflow "sequence number is not uint64"))
    (let ((nonce (copy-seq iv-bytes)))
      (dotimes (i 8)
        (setf (aref nonce (+ 4 i))
              (logxor (aref nonce (+ 4 i))
                      (ldb (byte 8 (* 8 (- 7 i))) sequence-number))))
      nonce)))

(defun %next-sequence (sequence-number)
  (if (= sequence-number (1- (expt 2 64)))
      (%record-fail 'tls-sequence-overflow "record sequence number exhausted")
      (1+ sequence-number)))

(defun %ensure-sequence-available (sequence-number)
  (unless (typep sequence-number '(unsigned-byte 64))
    (%record-fail 'tls-sequence-overflow "sequence number is not uint64"))
  (when (= sequence-number (1- (expt 2 64)))
    (%record-fail 'tls-sequence-overflow "record sequence number exhausted"))
  sequence-number)

(defun %provider-result (provider key nonce input aad operation)
  (unless (functionp provider)
    (%record-fail 'tls-aead-error (format nil "~A provider is not callable" operation)))
  (handler-case (%record-octets (funcall provider key nonce input aad))
    (tls-record-error (condition) (error condition))
    (error (condition)
      (%record-fail 'tls-aead-error
                    (format nil "~A provider failed: ~A" operation condition)))))

(defun encrypt-tls-record (plaintext key iv sequence-number aead-encrypt
                           &key (padding-length 0) (tag-length 16))
  "Encrypt PLAINTEXT with the supplied provider and return wire TLSCiphertext.
TAG-LENGTH is the provider's fixed AEAD expansion and PADDING-LENGTH is the
number of zero octets added after the inner content type."
  (check-type plaintext tls-plaintext)
  (check-type padding-length (integer 0 #xffff))
  (check-type tag-length (integer 0 #xffff))
  (%ensure-sequence-available sequence-number)
  (let* ((content (%record-octets (tls-plaintext-fragment plaintext)))
         (inner (concatenate '(vector (unsigned-byte 8)) content
                             (vector (tls-plaintext-content-type plaintext))
                             (make-array padding-length
                                         :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
         (cipher-length (+ (length inner) tag-length))
         (nonce (tls-record-nonce iv sequence-number))
         (aad (tls-record-additional-data +tls-content-type-application-data+
                                          cipher-length))
         (cipher (progn
                   (when (> cipher-length +tls-ciphertext-limit+)
                     (%record-fail 'tls-record-overflow
                                   "encrypted record exceeds limit"))
                   (%provider-result aead-encrypt key nonce inner aad 'encryption))))
    (unless (= (length cipher) cipher-length)
      (%record-fail 'tls-aead-error "AEAD provider returned unexpected length"))
    (values (encode-tls-ciphertext
             (%make-tls-ciphertext +tls-content-type-application-data+
                                   +tls-record-version+ cipher))
            (%next-sequence sequence-number))))

(defun decrypt-tls-record (wire key iv sequence-number aead-decrypt
                           &key (tag-length 16))
  "Decrypt wire TLSCiphertext and return TLSPlaintext plus the next sequence."
  (check-type tag-length (integer 0 #xffff))
  (%ensure-sequence-available sequence-number)
  (let* ((record (decode-tls-ciphertext wire))
         (cipher (tls-ciphertext-fragment record))
         (cipher-length (length cipher))
         (aad (tls-record-additional-data (tls-ciphertext-content-type record)
                                          cipher-length)))
    (when (< cipher-length (1+ tag-length))
      (%record-fail 'tls-invalid-record
                    "ciphertext is shorter than the AEAD tag and content type"))
    (let ((plain (%provider-result aead-decrypt key
                                   (tls-record-nonce iv sequence-number)
                                   cipher aad 'decryption)))
      (when (zerop (length plain))
        (%record-fail 'tls-invalid-record "empty TLSInnerPlaintext"))
      (let ((end (1- (length plain))))
        (loop while (and (> end 0) (zerop (aref plain end))) do (decf end))
        (let ((type (aref plain end)))
          (unless (%valid-content-type-p type)
            (%record-fail 'tls-invalid-record "invalid inner content type"))
          (values (make-tls-plaintext type (subseq plain 0 end))
                  (%next-sequence sequence-number)))))))

(defun encrypt-tls13-record (plaintext provider algorithm key iv sequence-number
                             &key (padding-length 0) (tag-length 16))
  "Encrypt a record with a TLS13 crypto provider's AEAD-SEAL operation."
  (unless (and (typep provider 'tls13-crypto-provider)
               (functionp (tls13-crypto-provider-aead-seal provider)))
    (%record-fail 'tls-aead-error "provider has no AEAD-SEAL operation"))
  (encrypt-tls-record plaintext key iv sequence-number
                      (lambda (record-key nonce input aad)
                        (tls13-aead-seal provider algorithm record-key nonce input aad))
                      :padding-length padding-length :tag-length tag-length))

(defun decrypt-tls13-record (wire provider algorithm key iv sequence-number
                             &key (tag-length 16))
  "Decrypt a record with a TLS13 crypto provider's AEAD-OPEN operation."
  (unless (and (typep provider 'tls13-crypto-provider)
               (functionp (tls13-crypto-provider-aead-open provider)))
    (%record-fail 'tls-aead-error "provider has no AEAD-OPEN operation"))
  (decrypt-tls-record wire key iv sequence-number
                      (lambda (record-key nonce input aad)
                        (tls13-aead-open provider algorithm record-key nonce input aad))
                      :tag-length tag-length))

(defun encrypt-tls13-traffic-record (plaintext state &key (padding-length 0)
                                     (tag-length 16))
  "Encrypt using STATE and advance its sequence number after success."
  (check-type state tls13-traffic-state)
  (multiple-value-bind (wire next)
      (encrypt-tls13-record plaintext
                            (tls13-traffic-state-provider state)
                            (tls13-traffic-state-algorithm state)
                            (tls13-traffic-state-key state)
                            (tls13-traffic-state-iv state)
                            (tls13-traffic-state-sequence-number state)
                            :padding-length padding-length :tag-length tag-length)
    (setf (tls13-traffic-state-sequence-number state) next)
    (values wire state)))

(defun decrypt-tls13-traffic-record (wire state &key (tag-length 16))
  "Decrypt using STATE and advance its sequence number after success."
  (check-type state tls13-traffic-state)
  (multiple-value-bind (plaintext next)
      (decrypt-tls13-record wire
                            (tls13-traffic-state-provider state)
                            (tls13-traffic-state-algorithm state)
                            (tls13-traffic-state-key state)
                            (tls13-traffic-state-iv state)
                            (tls13-traffic-state-sequence-number state)
                            :tag-length tag-length)
    (setf (tls13-traffic-state-sequence-number state) next)
    (values plaintext state)))

(defun tls-key-update-p (plaintext)
  "Recognize the exact TLS 1.3 KeyUpdate handshake message."
  (and (typep plaintext 'tls-plaintext)
       (= (tls-plaintext-content-type plaintext) +tls-content-type-handshake+)
       (let ((bytes (tls-plaintext-fragment plaintext)))
         (and (= (length bytes) 5)
              (= (aref bytes 0) +tls-handshake-key-update+)
              (zerop (aref bytes 1)) (zerop (aref bytes 2))
              (= (aref bytes 3) 1)
              (<= (aref bytes 4) 1)))))

(defun tls-close-notify-p (plaintext)
  "Recognize the exact warning-level close_notify alert."
  (and (typep plaintext 'tls-plaintext)
       (= (tls-plaintext-content-type plaintext) +tls-content-type-alert+)
       (equalp (tls-plaintext-fragment plaintext) #(1 0))))

(export '(+tls-record-version+ +tls-plaintext-limit+ +tls-ciphertext-limit+
          +tls-content-type-alert+ +tls-content-type-handshake+
          +tls-content-type-application-data+ +tls-handshake-key-update+
          +tls-alert-close-notify+ tls-record-error tls-record-error-reason
          tls-record-overflow tls-invalid-record tls-sequence-overflow
          tls-aead-error tls-plaintext make-tls-plaintext tls-plaintext-p
          tls-plaintext-content-type tls-plaintext-fragment
          encode-tls-plaintext decode-tls-plaintext tls-ciphertext
          make-tls-ciphertext tls-ciphertext-p tls-ciphertext-content-type
          tls-ciphertext-legacy-version tls-ciphertext-fragment
          encode-tls-ciphertext decode-tls-ciphertext tls-record-nonce
          tls-record-additional-data encrypt-tls-record decrypt-tls-record
          encrypt-tls13-record decrypt-tls13-record
          encrypt-tls13-traffic-record decrypt-tls13-traffic-record
          tls-key-update-p tls-close-notify-p))
