(in-package #:cl-tls-kit/test)

;;;; These tests use a real provider when CL-CRYPTO-KIT is loaded.  They do
;;;; not substitute a mock digest for the RFC 5869 assertions.

(defun %hex (string)
  (let ((result (make-array (/ (length string) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length result) result)
      (setf (aref result i)
            (parse-integer string :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun %check-equal-octets (actual expected message)
  (unless (equalp actual expected)
    (error "Test failed: ~A" message)))

(defun run-key-schedule-tests (&optional provider)
  (let ((provider (or provider
                      (and (find-package '#:crypto-kit)
                           (cl-tls-kit::make-cl-crypto-kit-provider)))))
    (unless provider
      (error "CL-CRYPTO-KIT is required for key schedule vector tests."))
    ;; RFC 5869 test case 1, SHA-256.
    (let ((ikm (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x0b))
          (salt (%hex "000102030405060708090a0b0c"))
          (info (%hex "f0f1f2f3f4f5f6f7f8f9")))
      (%check-equal-octets
       (cl-tls-kit::tls13-hkdf-extract provider :sha256 salt ikm)
       (%hex "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
       "RFC 5869 Extract SHA-256")
      (%check-equal-octets
       (funcall (cl-tls-kit::tls13-crypto-provider-hkdf-expand provider)
                :sha256
                (%hex "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                info 42)
       (%hex "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
       "RFC 5869 Expand SHA-256"))
    ;; RFC 8446 label structure: uint16 length, opaque label<7..255>,
    ;; opaque context<0..255>, with the mandatory \"tls13 \" prefix.
    (let* ((captured nil)
           (stub (cl-tls-kit::%make-tls13-crypto-provider
                 (lambda (&rest args) (declare (ignore args)) #(0))
                 (lambda (hash secret info length)
                   (declare (ignore hash secret))
                   (setf captured info)
                   (make-array length :element-type '(unsigned-byte 8)))
                 (lambda (hash) (declare (ignore hash)) 32)
                 (lambda (hash octets) (declare (ignore hash octets)) #(0)))))
      (cl-tls-kit::tls13-hkdf-expand-label stub :sha256 (make-array 32 :element-type '(unsigned-byte 8))
                               "derived" (make-array 0 :element-type '(unsigned-byte 8)) 32)
      (%check-equal-octets captured (%hex "00200d746c733133206465726976656400")
                            "TLS 1.3 HKDF label encoding"))
    (let* ((expanded-labels '())
           (stub (cl-tls-kit::%make-tls13-crypto-provider
                  (lambda (hash salt ikm)
                    (declare (ignore hash salt ikm))
                    (make-array 32 :element-type '(unsigned-byte 8)))
                  (lambda (hash secret info length)
                    (declare (ignore hash secret))
                    (push info expanded-labels)
                    (make-array length :element-type '(unsigned-byte 8)))
                  (lambda (hash) (declare (ignore hash)) 32)
                  (lambda (hash octets) (declare (ignore hash octets)) #(0))
                  (lambda (hash key data) (declare (ignore hash key data)) #(0))
                  (lambda (algorithm key nonce plaintext aad)
                    (declare (ignore algorithm key nonce aad)) plaintext)
                  (lambda (algorithm key nonce ciphertext aad)
                    (declare (ignore algorithm key nonce aad)) ciphertext)
                  (lambda (left right) (equalp left right)))))
      (let ((state (cl-tls-kit::make-tls13-traffic-state
                    stub :sha256 :aes-128-gcm
                    (make-array 32 :element-type '(unsigned-byte 8)) 16 12)))
        (setf (cl-tls-kit::tls13-traffic-state-sequence-number state) 9)
        (cl-tls-kit::tls13-update-traffic-secret state)
        (%check-equal-octets (cl-tls-kit::tls13-traffic-state-secret state)
                             (make-array 32 :element-type '(unsigned-byte 8))
                             "traffic secret ratchet preserves digest length")
        (record-test-check (= (cl-tls-kit::tls13-traffic-state-sequence-number state) 0)
                           "traffic secret ratchet resets sequence")
        (record-test-check (some (lambda (info)
                                   (search "traffic upd" (map 'string #'code-char info)))
                                 expanded-labels)
                           "traffic secret ratchet uses traffic upd label")))
    (when (find-package '#:crypto-kit)
      (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element #x42))
             (state (cl-tls-kit::make-tls13-traffic-state
                     provider :sha256 :aes-128-gcm secret 16 12))
             (old-secret (copy-seq (cl-tls-kit::tls13-traffic-state-secret state)))
             (old-key (copy-seq (cl-tls-kit::tls13-traffic-state-key state))))
        (setf (cl-tls-kit::tls13-traffic-state-sequence-number state) 11)
        (cl-tls-kit::tls13-update-traffic-secret state)
        (record-test-check (not (equalp old-secret
                                        (cl-tls-kit::tls13-traffic-state-secret state)))
                           "real provider changes the traffic secret")
        (record-test-check (not (equalp old-key
                                        (cl-tls-kit::tls13-traffic-state-key state)))
                           "real provider changes the traffic key")
        (record-test-check (zerop (cl-tls-kit::tls13-traffic-state-sequence-number state))
                           "real provider ratchet resets sequence")))
    t))
