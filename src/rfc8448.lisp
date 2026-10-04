(in-package #:cl-tls-kit)

;;;; RFC 8448 section 3 uses Derive-Secret with Hash("") as the context for
;;;; the two "derived" labels.  Keep this trace-specific composition here so
;;;; the generic key-schedule entry points remain unchanged.

(defun tls13-rfc8448-simple-1rtt-client-values
    (provider hash psk dhe-secret handshake-transcript-hash
     application-transcript-hash key-length iv-length)
  "Return the RFC 8448 Simple 1-RTT client key-schedule intermediates.

All digest, HKDF, and HMAC-related work remains behind PROVIDER.  The final
Finished verify_data is intentionally not returned because the current
provider contract has no HMAC operation."
  (let* ((empty-hash (tls13-empty-hash provider hash))
         (early-secret (tls13-early-secret provider hash psk))
         (handshake-derived
           (tls13-derive-secret provider hash early-secret "derived" empty-hash))
         (handshake-secret
           (tls13-hkdf-extract provider hash handshake-derived dhe-secret))
         (client-handshake-traffic-secret
           (tls13-traffic-secret provider hash handshake-secret :client
                                 handshake-transcript-hash :phase :handshake))
         (master-derived
           (tls13-derive-secret provider hash handshake-secret "derived" empty-hash))
         (master-secret
           (tls13-hkdf-extract provider hash master-derived
                               (make-array (length empty-hash)
                                           :element-type '(unsigned-byte 8))))
         (client-application-traffic-secret
           (tls13-traffic-secret provider hash master-secret :client
                                 application-transcript-hash :phase :application))
         (client-finished-key
           (tls13-finished-key provider hash client-handshake-traffic-secret)))
    (multiple-value-bind (handshake-key handshake-iv)
        (tls13-traffic-key-and-iv provider hash client-handshake-traffic-secret
                                   key-length iv-length)
      (multiple-value-bind (application-key application-iv)
          (tls13-traffic-key-and-iv provider hash
                                     client-application-traffic-secret
                                     key-length iv-length)
        (list :early-secret early-secret
              :handshake-secret handshake-secret
              :client-handshake-traffic-secret client-handshake-traffic-secret
              :master-secret master-secret
              :client-application-traffic-secret client-application-traffic-secret
              :client-handshake-key handshake-key
              :client-handshake-iv handshake-iv
              :client-application-key application-key
              :client-application-iv application-iv
              :client-finished-key client-finished-key)))))
