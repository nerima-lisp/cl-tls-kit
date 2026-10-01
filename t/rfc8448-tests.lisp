(in-package #:cl-tls-kit/test)

;;;; RFC 8448, section 3: Simple 1-RTT Handshake.
;;;;
;;;; The inputs and expected values below are the client-view values from the
;;;; trace.  The fixture intentionally stops at the provider boundary: this
;;;; file must not grow a second HKDF, digest, or HMAC implementation.

(defun rfc8448-%hex (string)
  (let ((result (make-array (/ (length string) 2)
                            :element-type '(unsigned-byte 8))))
    (dotimes (i (length result) result)
      (setf (aref result i)
            (parse-integer string :start (* i 2) :end (+ (* i 2) 2)
                           :radix 16)))))

(defparameter *rfc8448-simple-1rtt-client-fixture*
  '((:hash . :sha256)
    (:key-length . 16)
    (:iv-length . 12)
    (:psk . "0000000000000000000000000000000000000000000000000000000000000000")
    (:dhe-secret . "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
    (:client-handshake-transcript-hash
     . "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
    (:client-application-transcript-hash
     . "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
    (:early-secret
     . "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    (:handshake-secret
     . "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    (:client-handshake-traffic-secret
     . "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    (:master-secret
     . "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
    (:client-application-traffic-secret
     . "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
    (:client-handshake-key . "dbfaa693d1762c5b666af5d950258d01")
    (:client-handshake-iv . "5bd3c71b836e0b76bb73265f")
    (:client-application-key . "17422dda596ed5d9acd890e3c63f5051")
    (:client-application-iv . "5b78923dee08579033e523d9")
    (:client-finished-key
     . "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4")
    ;; RFC 8448 also prints the final verify_data.
    (:client-finished-verify-data
     . "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")))

(defun rfc8448-%fixture (name)
  (let ((value (cdr (assoc name *rfc8448-simple-1rtt-client-fixture*))))
    (if (and (stringp value) (every (lambda (character)
                                     (or (digit-char-p character 16)
                                         (char= character #\Space)))
                                   value))
        (rfc8448-%hex (remove #\Space value))
        value)))

(defun rfc8448-%check (actual expected name)
  (unless (equalp actual expected)
    (error "RFC 8448 test failed for ~A: got ~S, expected ~S"
           name actual expected)))

(defun run-rfc8448-tests (&optional provider)
  "Run the RFC 8448 client key-schedule checks, or report a real skip.

The crypto branch is intentionally not treated as passed when CL-CRYPTO-KIT
is absent."
  (let ((provider (or provider
                      (and (find-package '#:crypto-kit)
                           (cl-tls-kit::make-cl-crypto-kit-provider)))))
    (unless provider
      (format t "RFC 8448 Simple 1-RTT: SKIPPED (crypto provider unavailable)~%")
      (return-from run-rfc8448-tests :skipped))
    (let* ((hash (rfc8448-%fixture :hash))
           (psk (rfc8448-%fixture :psk))
           (dhe-secret (rfc8448-%fixture :dhe-secret))
           (handshake-hash (rfc8448-%fixture :client-handshake-transcript-hash))
           (application-hash
             (rfc8448-%fixture :client-application-transcript-hash))
           (values
             (cl-tls-kit::tls13-rfc8448-simple-1rtt-client-values
              provider hash psk dhe-secret handshake-hash application-hash
              (rfc8448-%fixture :key-length)
              (rfc8448-%fixture :iv-length)))
           (early-secret (getf values :early-secret))
           (handshake-secret (getf values :handshake-secret))
           (client-handshake-secret
             (getf values :client-handshake-traffic-secret))
           (master-secret (getf values :master-secret))
           (client-application-secret
             (getf values :client-application-traffic-secret)))
      (rfc8448-%check early-secret (rfc8448-%fixture :early-secret) :early-secret)
      (rfc8448-%check handshake-secret (rfc8448-%fixture :handshake-secret)
                       :handshake-secret)
      (rfc8448-%check client-handshake-secret
                       (rfc8448-%fixture :client-handshake-traffic-secret)
                       :client-handshake-traffic-secret)
      (rfc8448-%check master-secret (rfc8448-%fixture :master-secret)
                       :master-secret)
      (rfc8448-%check client-application-secret
                       (rfc8448-%fixture :client-application-traffic-secret)
                       :client-application-traffic-secret)
      (multiple-value-bind (key iv)
          (cl-tls-kit:tls13-traffic-key-and-iv
           provider hash client-handshake-secret
           (rfc8448-%fixture :key-length) (rfc8448-%fixture :iv-length))
        (rfc8448-%check key (rfc8448-%fixture :client-handshake-key)
                         :client-handshake-key)
        (rfc8448-%check iv (rfc8448-%fixture :client-handshake-iv)
                         :client-handshake-iv))
      (multiple-value-bind (key iv)
          (cl-tls-kit:tls13-traffic-key-and-iv
           provider hash client-application-secret
           (rfc8448-%fixture :key-length) (rfc8448-%fixture :iv-length))
        (rfc8448-%check key (rfc8448-%fixture :client-application-key)
                         :client-application-key)
        (rfc8448-%check iv (rfc8448-%fixture :client-application-iv)
                         :client-application-iv))
      (rfc8448-%check
       (cl-tls-kit:tls13-finished-key provider hash client-handshake-secret)
       (rfc8448-%fixture :client-finished-key) :client-finished-key)
      ;; The trace's final Finished uses the transcript hash after the full
      ;; handshake; this fixture currently supplies only the intermediate
      ;; hashes, so the provider HMAC boundary is tested separately.
      (format t "RFC 8448 Simple 1-RTT: PASS (Finished transcript assertion pending)~%")
      t)))
