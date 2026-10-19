(in-package #:cl-tls-kit/test)

(defvar *client-resumption-assertions* 0)
(declaim (ftype (function (t) t) run-client-resumption-regression-tests))

(defun %client-resumption-check (condition message)
  (incf *client-resumption-assertions*)
  (check condition message))

(defun %client-resumption-hex (string)
  (let ((result (make-array (/ (length string) 2)
                            :element-type '(unsigned-byte 8))))
    (dotimes (index (length result) result)
      (setf (aref result index)
            (parse-integer string :start (* index 2) :end (* (1+ index) 2)
                           :radix 16)))))

(defun %client-resumption-octets-hex (octets)
  (format nil "~{~2,'0X~}" (coerce octets 'list)))

(defun %client-resumption-u16 (octets offset)
  (+ (ash (aref octets offset) 8) (aref octets (1+ offset))))

(defun %client-resumption-u32 (octets offset)
  (+ (ash (aref octets offset) 24)
     (ash (aref octets (+ offset 1)) 16)
     (ash (aref octets (+ offset 2)) 8)
     (aref octets (+ offset 3))))

(defun %client-resumption-psk-fields (data)
  (let* ((identity-length (%client-resumption-u16 data 2))
         (identity-end (+ 4 identity-length))
         (binder-list-offset (+ identity-end 4))
         (binder-length (aref data (+ binder-list-offset 2)))
         (binder-offset (+ binder-list-offset 3)))
    (values (subseq data 4 identity-end)
            (%client-resumption-u32 data identity-end)
            (subseq data binder-offset (+ binder-offset binder-length)))))

(defun %client-resumption-key-exchange ()
  (list :random
        (lambda (length)
          (make-array length :element-type '(unsigned-byte 8) :initial-element 3))
        :generate
        (lambda (group)
          (declare (ignore group))
          (values (%client-resumption-hex "01") (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element 4)))
        :shared-secret
        (lambda (group private peer)
          (declare (ignore group private peer))
          (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))))

(defun %client-resumption-driver
    (provider store hostname alpn
     &optional (cipher-suites #(#x1301))
       (supported-groups '(#x001d)))
  (let ((sent (list nil)))
    (values
     (apply #'make-tls13-client-driver
            (append (list :provider provider
                          :key-exchange (%client-resumption-key-exchange))
                    (when store (list :ticket-store store))
                    (list :hostname hostname
                          :alpn alpn
                          :cipher-suites cipher-suites
                          :supported-groups supported-groups
                          :on-send (lambda (driver wire)
                                     (declare (ignore driver))
                                     (push wire (car sent))))))
     sent)))

(defun %client-resumption-extension (hello type)
  (find type (tls13-client-hello-extensions hello) :key #'tls-extension-type))

(defun %client-resumption-server-hello (identity)
  (make-tls13-server-hello
   #x0303
   (make-array 32 :element-type (quote (unsigned-byte 8)) :initial-element 8)
   (make-array 0 :element-type (quote (unsigned-byte 8))) #x1301
   (append
    (list (make-tls-extension 43 (%client-resumption-hex "0304"))
          (make-tls-extension
           51 (encode-key-share-server-extension
               #x001d (make-array 32 :element-type (quote (unsigned-byte 8))
                                  :initial-element 9))))
    (when identity
      (list (make-tls-extension
             41 (make-array 2 :element-type (quote (unsigned-byte 8))
                            :initial-contents (list 0 identity))))))))

(defun %client-resumption-encrypted-extensions (protocols)
  (make-tls13-encrypted-extensions
   (list (make-tls-extension
          16 (encode-alpn-extension
              (if (stringp protocols) (list protocols) protocols))))))

(defun %client-resumption-has-psk-p (driver)
  (let* ((sent (cl-tls-kit::tls13-client-driver-client-hello driver))
         (extension (%client-resumption-extension sent 41)))
    (not (null extension))))

(defun run-client-resumption-tests (&optional provider)
  (let ((provider (or provider
                      (and (find-package '#:crypto-kit)
                           (cl-tls-kit:make-cl-crypto-kit-provider)))))
    (unless provider
      (format t "TLS 1.3 client resumption: SKIPPED (crypto provider unavailable)~%")
      (return-from run-client-resumption-tests :skipped))
    (let ((selected 0)
          (*client-resumption-assertions* 0))
      (let* ((master-secret
              (%client-resumption-hex
               "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"))
             (resumption-transcript-hash
              (%client-resumption-hex
               "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"))
             (resumption-master-secret
              (%client-resumption-hex
               "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"))
             (ticket-psk
              (%client-resumption-hex
               "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"))
             (early-secret
              (%client-resumption-hex
               "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c"))
             (dhe-secret
              (%client-resumption-hex
               "f44194756ff9ec9d25180635d66ea6824c6ab3bf179977be37f723570e7ccb2e"))
             (resumed-handshake-secret
              (%client-resumption-hex
               "005cb112fd8eb4ccc623bb88a07c64b3ede1605363fc7d0df8c7ce4ff0fb4ae6")))
        (incf selected)
        (%client-resumption-check
         (equalp (tls13-resumption-secret
                  provider :sha256 master-secret resumption-transcript-hash)
                 resumption-master-secret)
         "RFC 8448 section 3 resumption master secret")
        (%client-resumption-check
         (equalp (cl-tls-kit::tls13-resumption-psk
                  provider :sha256 resumption-master-secret (%client-resumption-hex "0000"))
                 ticket-psk)
         "RFC 8448 section 3 ticket PSK for nonce 0000")
        ;; Section 4 schedule inputs only; its 0-RTT ClientHello binder is not reused.
        (%client-resumption-check
         (equalp (tls13-early-secret provider :sha256 ticket-psk) early-secret)
         "RFC 8448 section 4 resumption early secret")
        (progn
          (%client-resumption-check
           (equalp (tls13-handshake-secret provider :sha256 early-secret dhe-secret)
                   resumed-handshake-secret)
           "RFC 8448 section 4 PSK plus DHE handshake secret")
          (%client-resumption-check
           (handler-case
               (progn
                 (tls13-early-secret provider :sha256 "PSK-SENTINEL-NOT-LOGGED")
                 nil)
             (cl-tls-kit::tls13-key-schedule-error (condition)
                                                   (not (search "PSK-SENTINEL-NOT-LOGGED"
                                                                (cl-tls-kit::tls13-key-schedule-error-message condition)))))
           "malformed PSK diagnostics omit the offending value")))
      (let ((now 1000000)
            (store nil))
        (setf store (make-tls13-ticket-store :clock (lambda () now)))
        (cl-tls-kit::%tls13-ticket-store-put
         store "Example.Test." "h2" (%client-resumption-hex "090807")
         (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42)
         :sha256 600 #xfffffffd)
        (incf now 125)
        (incf selected)
        (multiple-value-bind (driver sent)
            (%client-resumption-driver provider store "example.test" '("h2"))
          (tls13-client-driver-start driver)
          (let* ((wire (first (car sent)))
                 (hello (decode-handshake wire))
                 (extensions (tls13-client-hello-extensions hello))
                 (psk-extension (%client-resumption-extension hello 41))
                 (modes (%client-resumption-extension hello 45)))
            (%client-resumption-check (and psk-extension (eq psk-extension (car (last extensions))))
                                      "pre_shared_key is the final ClientHello extension")
            (%client-resumption-check (and modes (equalp (tls-extension-data modes) #(1 1)))
                                      "ClientHello offers only psk_dhe_ke")
            (%client-resumption-check (null (%client-resumption-extension hello 42))
                                      "non-0RTT ClientHello omits early_data")
            (multiple-value-bind (identity age binder)
                (%client-resumption-psk-fields (tls-extension-data psk-extension))
              (%client-resumption-check (equalp identity (%client-resumption-hex "090807"))
                                        "PSK identity is the stored ticket")
              (%client-resumption-check (= age 122)
                                        "obfuscated ticket age wraps modulo 2^32")
              (let* ((binder-length (length binder))
                     (truncated (subseq wire 0 (- (length wire) (+ 3 binder-length))))
                     (binder-hash (funcall (cl-tls-kit::tls13-crypto-provider-digest provider)
                                           :sha256 truncated))
                     (expected-binder
                      ;; Filled from an independent RFC 8446 HKDF/HMAC derivation.
                      (%client-resumption-hex "e93559879478fb841266de55d142f21c58651cdd3761ca20959bdbd616dc5162")))
                (%client-resumption-check
                 (and (equalp binder expected-binder)
                      (equalp binder
                              (cl-tls-kit::tls13-psk-binder
                               provider :sha256
                               (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element #x42)
                               binder-hash)))
                 "ClientHello binder matches the independent no-0RTT vector")))))
        (let ((now 7000)
              (store nil))
          (setf store (make-tls13-ticket-store :clock (lambda () now)))
          (cl-tls-kit::%tls13-ticket-store-put
           store "example.test" "h2" (%client-resumption-hex "01")
           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
           :sha256 1 0)
          (setf now 8000)
          (incf selected)
          (multiple-value-bind (driver sent)
              (%client-resumption-driver provider store "example.test" '("h2"))
            (tls13-client-driver-start driver)
            (%client-resumption-check (not (%client-resumption-has-psk-p driver))
                                      "expired ticket is not offered")
            (multiple-value-bind (expired-again ignored) (%client-resumption-driver provider store "example.test" (list "h2")) (declare (ignore ignored)) (tls13-client-driver-start expired-again) (%client-resumption-check (not (%client-resumption-has-psk-p expired-again)) "expired ticket is pruned before a later offer"))
            (%client-resumption-check
             (not (find 45 (tls13-client-hello-extensions
                            (decode-handshake (first (car sent))))
                        :key #'tls-extension-type))
             "expired ticket does not leave psk_key_exchange_modes")))
        (let ((store (make-tls13-ticket-store)))
  (cl-tls-kit::%tls13-ticket-store-put
   store "example.test" "h2" (%client-resumption-hex "01")
   (make-array 32 :element-type (quote (unsigned-byte 8)) :initial-element 2)
   :sha256 600 0)
  (incf selected)
  (multiple-value-bind (wrong-sni ignored)
      (%client-resumption-driver provider store "other.test" (list "h2"))
    (declare (ignore ignored))
    (tls13-client-driver-start wrong-sni)
    (%client-resumption-check (not (%client-resumption-has-psk-p wrong-sni))
                              "SNI mismatch does not offer a ticket"))
  (multiple-value-bind (wrong-alpn ignored)
      (%client-resumption-driver provider store "example.test" (list "http/1.1"))
    (declare (ignore ignored))
    (tls13-client-driver-start wrong-alpn)
    (%client-resumption-check (not (%client-resumption-has-psk-p wrong-alpn))
                              "ALPN mismatch does not offer a ticket"))
  (multiple-value-bind (matching ignored)
      (%client-resumption-driver provider store "example.test" (list "h2"))
    (declare (ignore ignored))
    (tls13-client-driver-start matching)
    (%client-resumption-check (%client-resumption-has-psk-p matching)
                              "SNI and ALPN mismatches leave the matching ticket available")))
        (incf selected)
        (multiple-value-bind (legacy-driver sent)
            (%client-resumption-driver provider nil "example.test" '("h2"))
          (tls13-client-driver-start legacy-driver)
          (let ((hello (decode-handshake (first (car sent)))))
            (%client-resumption-check (not (%client-resumption-extension hello 41))
                                      "old client call without a store omits pre_shared_key")
            (%client-resumption-check (not (%client-resumption-extension hello 45))
                                      "old client call without a store omits psk_key_exchange_modes")
            (%client-resumption-check (not (%client-resumption-extension hello 42))
                                      "old client call without a store omits early_data"))
          (%client-resumption-check
           (handler-case
               (progn
                 (cl-tls-kit::%driver-client-step
                  legacy-driver
                  (encode-handshake 2 (%client-resumption-server-hello 0)))
                 nil)
             (tls13-client-driver-error (condition)
                                        (eq (tls13-client-driver-error-reason condition)
                                            :unexpected-psk-identity)))
           "ServerHello rejects selected identity when no ticket was offered"))
        (incf selected)
        (let ((store (make-tls13-ticket-store)))
  (cl-tls-kit::%tls13-ticket-store-put
   store "example.test" "h2" (%client-resumption-hex "01")
   (make-array 32 :element-type (quote (unsigned-byte 8)) :initial-element 2)
   :sha256 600 0)
  #+sb-thread
(let* ((ready (sb-thread:make-semaphore))
       (gate (sb-thread:make-semaphore))
       (results (make-array 2 :initial-element :pending))
       (drivers
         (loop repeat 2
               collect
               (multiple-value-list
                (%client-resumption-driver provider store "example.test"
                                           (list "h2")))))
       (threads
         (loop for index below 2
               collect
               (let ((thread-index index))
                 (sb-thread:make-thread
                  (lambda ()
                    (sb-thread:signal-semaphore ready)
                    (sb-thread:wait-on-semaphore gate)
                    (let ((driver (first (nth thread-index drivers))))
                      (setf (aref results thread-index)
                            (handler-case
                                (progn
                                  (tls13-client-driver-start driver)
                                  (list :complete
                                        (%client-resumption-has-psk-p driver)))
                              (error (condition)
                                (list :error condition)))))))))))
  (loop repeat 2 do (sb-thread:wait-on-semaphore ready))
  (loop repeat 2 do (sb-thread:signal-semaphore gate))
  (mapc (function sb-thread:join-thread) threads)
  (%client-resumption-check (every #'consp results)
                            "both concurrent ticket consumers finish after release")
  (%client-resumption-check (notany (lambda (result) (eq (first result) :error)) results)
                            "concurrent ticket consumers report no worker errors")
  (%client-resumption-check
   (= (count-if (lambda (result)
                  (and (eq (first result) :complete) (second result)))
                results)
      1)
   "concurrent clients consume a ticket at most once")
  (multiple-value-bind (later ignored)
      (%client-resumption-driver provider store "example.test" (list "h2"))
    (declare (ignore ignored))
    (tls13-client-driver-start later)
    (%client-resumption-check (not (%client-resumption-has-psk-p later))
                              "concurrent clients cannot offer the ticket a second time")))
  #-sb-thread
  (let ((first (multiple-value-list
                (%client-resumption-driver provider store "example.test" (list "h2"))))
        (second (multiple-value-list
                 (%client-resumption-driver provider store "example.test" (list "h2")))))
    (tls13-client-driver-start (first first))
    (tls13-client-driver-start (first second))
    (%client-resumption-check
     (= (+ (if (%client-resumption-has-psk-p (first first)) 1 0)
           (if (%client-resumption-has-psk-p (first second)) 1 0))
        1)
     "sequential clients consume a ticket at most once")
    (multiple-value-bind (later ignored)
        (%client-resumption-driver provider store "example.test" (list "h2"))
      (declare (ignore ignored))
      (tls13-client-driver-start later)
      (%client-resumption-check (not (%client-resumption-has-psk-p later))
                                "sequential clients cannot offer the ticket a second time"))))
        (progn
          (incf selected)
          (let ((store (make-tls13-ticket-store)))
            (cl-tls-kit::%tls13-ticket-store-put
             store "example.test" "h2" (%client-resumption-hex "01")
             (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
             :sha256 600 0)
            (multiple-value-bind (driver ignored)
                (%client-resumption-driver provider store "example.test" '("h2"))
              (declare (ignore ignored))
              (tls13-client-driver-start driver)
              (cl-tls-kit::%driver-client-step
               driver (encode-handshake 2 (%client-resumption-server-hello nil)))
              (cl-tls-kit::%driver-client-step
               driver (encode-handshake 8 (%client-resumption-encrypted-extensions "h2")))
              (%client-resumption-check (not (tls13-client-driver-resumed-p driver))
                                        "ServerHello without selected_identity falls back to full handshake")
              (%client-resumption-check
               (eq (cl-tls-kit::tls13-client-driver-state driver) :awaiting-certificate)
               "declined PSK continues through certificate authentication")))
          (incf selected))
        (let ((store (make-tls13-ticket-store)))
          (cl-tls-kit::%tls13-ticket-store-put
           store "example.test" "h2" (%client-resumption-hex "01")
           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
           :sha256 600 0)
          (multiple-value-bind (driver ignored)
              (%client-resumption-driver provider store "example.test" '("h2" "http/1.1"))
            (declare (ignore ignored))
            (tls13-client-driver-start driver)
            (cl-tls-kit::%driver-client-step
             driver (encode-handshake 2 (%client-resumption-server-hello 0)))
            (cl-tls-kit::%driver-client-step
             driver (encode-handshake 8 (%client-resumption-encrypted-extensions "h2")))
            (%client-resumption-check (tls13-client-driver-resumed-p driver)
                                      "ServerHello selected PSK identity zero")
            (%client-resumption-check
             (eq (cl-tls-kit::tls13-client-driver-state driver) :awaiting-finished)
             "accepted PSK and matching ALPN skip certificate messages")))
        (incf selected)
        (progn
          (let ((store (make-tls13-ticket-store)))
            (cl-tls-kit::%tls13-ticket-store-put
             store "example.test" "h2" (%client-resumption-hex "01")
             (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
             :sha256 600 0)
            (multiple-value-bind (driver ignored)
                (%client-resumption-driver provider store "example.test" '("h2" "http/1.1"))
              (declare (ignore ignored))
              (tls13-client-driver-start driver)
              (cl-tls-kit::%driver-client-step
               driver (encode-handshake 2 (%client-resumption-server-hello 0)))
              (%client-resumption-check
               (handler-case
                   (progn
                     (cl-tls-kit::%driver-client-step
                      driver (encode-handshake
                              8 (%client-resumption-encrypted-extensions "http/1.1")))
                     nil)
                 (tls13-client-driver-error (condition)
                                            (eq (tls13-client-driver-error-reason condition)
                                                :resumed-alpn-mismatch)))
               "accepted PSK with a different negotiated ALPN aborts")))
          (let ((store (make-tls13-ticket-store)))
            (cl-tls-kit::%tls13-ticket-store-put
             store "example.test" "h2" (%client-resumption-hex "01")
             (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
             :sha256 600 0)
            (multiple-value-bind (driver ignored)
                (%client-resumption-driver provider store "example.test" '("h2" "http/1.1"))
              (declare (ignore ignored))
              (tls13-client-driver-start driver)
              (cl-tls-kit::%driver-client-step
               driver (encode-handshake 2 (%client-resumption-server-hello 0)))
              (%client-resumption-check
               (handler-case
                   (progn
                     (cl-tls-kit::%driver-client-step
                      driver (encode-handshake
                              8 (%client-resumption-encrypted-extensions
                                 '("h2" "http/1.1"))))
                     nil)
                 (tls13-client-driver-error (condition)
                                            (eq (tls13-client-driver-error-reason condition)
                                                :unexpected-alpn)))
               "ServerHello path rejects an ALPN response with multiple protocols"))))
        (incf selected)
        (let ((store (make-tls13-ticket-store)))
          (cl-tls-kit::%tls13-ticket-store-put
           store "example.test" "h2" (%client-resumption-hex "01")
           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
           :sha256 600 0)
          (multiple-value-bind (driver ignored)
              (%client-resumption-driver provider store "example.test" '("h2"))
            (declare (ignore ignored))
            (tls13-client-driver-start driver)
            (%client-resumption-check
             (handler-case
                 (progn
                   (cl-tls-kit::%driver-client-step
                    driver (encode-handshake 2 (%client-resumption-server-hello 1)))
                   nil)
               (tls13-client-driver-error (condition)
                                          (eq (tls13-client-driver-error-reason condition)
                                              :unexpected-psk-identity)))
             "ServerHello rejects an unoffered PSK identity")))
        (incf selected)
        (let* ((now 3000)
       (store (make-tls13-ticket-store :clock (lambda () now)))
       (rms (%client-resumption-hex
             "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"))
       (driver
         (cl-tls-kit::%make-tls13-client-driver
          :provider provider :ticket-store store :hostname "example.test"
          :hash :sha256 :suite #x1301 :state :connected
          :negotiated-alpn "h2" :resumption-master-secret rms)))
  (dolist (lifetime (list 0 604801))
    (tls13-client-driver-step
     driver
     (encode-handshake
      4 (make-tls13-new-session-ticket lifetime (%client-resumption-hex "0000") (%client-resumption-hex "090807") nil 3)))
    (multiple-value-bind (invalid ignored)
        (%client-resumption-driver provider store "example.test" (list "h2"))
      (declare (ignore ignored))
      (tls13-client-driver-start invalid)
      (%client-resumption-check
       (not (%client-resumption-has-psk-p invalid))
       "zero and over-seven-day tickets are discarded")))
  (tls13-client-driver-step
   driver
   (encode-handshake
    4 (make-tls13-new-session-ticket 600 (%client-resumption-hex "0000") (%client-resumption-hex "090807") nil #xfffffffd)))
  (multiple-value-bind (client sent)
      (%client-resumption-driver provider store "example.test" (list "h2"))
    (tls13-client-driver-start client)
    (multiple-value-bind (identity age binder)
        (%client-resumption-psk-fields
         (tls-extension-data
          (%client-resumption-extension
           (decode-handshake (first (car sent))) 41)))
      (declare (ignore age binder))
      (%client-resumption-check
       (and (equalp identity (%client-resumption-hex "090807"))
            (equalp
             (cl-tls-kit::%tls13-session-ticket-psk
              (cl-tls-kit::tls13-client-driver-offered-ticket client))
             (%client-resumption-hex "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3")))
       "valid NewSessionTicket stores the RFC-derived PSK and offers its identity"))))
        (progn (run-client-resumption-regression-tests provider) (format t "TLS 1.3 client resumption: selected test count: ~D; assertions: ~D~%" selected *client-resumption-assertions*))
        t)))
  )
(defun run-client-resumption-security-tests (&optional provider)
  (let ((provider (or provider
                      (and (find-package '#:crypto-kit)
                           (cl-tls-kit:make-cl-crypto-kit-provider))))
        (*client-resumption-assertions* 0)
        (selected 0))
    (unless provider
      (format t "TLS 1.3 client resumption security: SKIPPED (crypto provider unavailable)~%")
      (return-from run-client-resumption-security-tests :skipped))
    (incf selected)
    (let* ((now 1000)
           (store (make-tls13-ticket-store :clock (lambda () now)))
           (first-ticket nil))
      (loop for index from 1 to 5
            for ticket = (cl-tls-kit::%tls13-ticket-store-put
                          store "caps.example.test" "h2"
                          (make-array 1 :element-type '(unsigned-byte 8)
                                      :initial-element index)
                          (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element #x42)
                          :sha256 600 0)
            do (when (= index 1) (setf first-ticket ticket)))
      (%client-resumption-check
       (= (cl-tls-kit::%tls13-ticket-store-count store) 4)
       "ticket store caps each hostname and ALPN at four tickets")
      (%client-resumption-check
       (every #'zerop (cl-tls-kit::%tls13-session-ticket-psk first-ticket))
       "per-scope eviction zeroizes the oldest ticket PSK")
      (let ((identities nil))
        (dotimes (index 4)
          (let ((ticket (cl-tls-kit::%tls13-ticket-store-take
                         store "caps.example.test" "h2" '(:sha256))))
            (push (aref (cl-tls-kit::%tls13-session-ticket-identity ticket) 0)
                  identities)
            (cl-tls-kit::%tls13-ticket-clear-secret ticket)))
        (%client-resumption-check (equal (nreverse identities) '(2 3 4 5))
                                  "per-scope cap retains the newest tickets in order")
        (%client-resumption-check
         (null (cl-tls-kit::%tls13-ticket-store-take
                store "caps.example.test" "h2" '(:sha256)))
         "taken tickets remain one-use after retention trimming")))
    (incf selected)
    (let* ((now 1000)
           (store (make-tls13-ticket-store :clock (lambda () now)))
           (oldest nil))
      (loop for index from 1 to 65
            for hostname = (format nil "site-~D.example.test" index)
            for ticket = (cl-tls-kit::%tls13-ticket-store-put
                          store hostname "h2"
                          (make-array 1 :element-type '(unsigned-byte 8)
                                      :initial-element index)
                          (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element #x42)
                          :sha256 600 0)
            do (when (= index 1) (setf oldest ticket)))
      (%client-resumption-check
       (= (cl-tls-kit::%tls13-ticket-store-count store) 64)
       "ticket store caps total live tickets at 64")
      (%client-resumption-check
       (= (hash-table-count (cl-tls-kit::tls13-ticket-store-entries store)) 64)
       "global eviction removes empty hostname and ALPN keys")
      (%client-resumption-check
       (every #'zerop (cl-tls-kit::%tls13-session-ticket-psk oldest))
       "global eviction zeroizes the oldest ticket PSK")
      (%client-resumption-check
       (null (cl-tls-kit::%tls13-ticket-store-take
              store "site-1.example.test" "h2" '(:sha256)))
       "global cap evicts the oldest ticket")
      (let ((available 0))
        (loop for index from 2 to 65
              for hostname = (format nil "site-~D.example.test" index)
              for ticket = (cl-tls-kit::%tls13-ticket-store-take
                            store hostname "h2" '(:sha256)
                            )
              do (when ticket
                   (incf available)
                   (cl-tls-kit::%tls13-ticket-clear-secret ticket)))
        (%client-resumption-check (= available 64)
                                  "global cap keeps all 64 newest tickets available")))
    (incf selected)
    (let* ((calls 0)
           (store
             (make-tls13-ticket-store
              :clock (lambda ()
                       (prog1 (case calls (0 0) ((1 2) 999) (otherwise 1000))
                         (incf calls)))))
           (expired
             (cl-tls-kit::%tls13-ticket-store-put
              store "example.test" "h2" (%client-resumption-hex "01")
              (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element #x42)
              :sha256 1 0)))
      (multiple-value-bind (driver ignored)
          (%client-resumption-driver provider store "example.test" (list "h2"))
        (declare (ignore ignored))
        (tls13-client-driver-start driver)
        (%client-resumption-check (not (%client-resumption-has-psk-p driver))
                                  "ticket expiring after take is not offered")
        (%client-resumption-check
        (and (= calls 4)
             (every #'zerop
                    (cl-tls-kit::%tls13-session-ticket-psk expired)))
        "ticket expiring at the final binder check is zeroized")))
    (incf selected)
    (let* ((now 1000)
           (store (make-tls13-ticket-store :clock (lambda () now)))
           (stored
             (cl-tls-kit::%tls13-ticket-store-put
              store "example.test" "h2" (%client-resumption-hex "090807")
              (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element #x42)
              :sha256 600 0)))
      (multiple-value-bind (driver sent)
          (%client-resumption-driver provider store "example.test" (list "h2"))
        (setf (cl-tls-kit::tls13-client-driver-supported-groups driver)
              '(#x001d #x0017))
        (tls13-client-driver-start driver)
        (let* ((client-hello-1 (first (car sent)))
               (hrr-wire
                 (encode-handshake
                  2 (make-tls13-server-hello
                     #x0303 cl-tls-kit::*tls13-hrr-random* #() #x1301
                     (list (make-tls-extension 43 #(#x03 #x04))
                           (make-tls-extension 51
                                               (cl-tls-kit::%hs-u16 #x0017)))))))
          (progn
            (setf now 601001)
            (tls13-client-driver-step driver hrr-wire))
          (let* ((client-hello-2 (first (car sent)))
                 (hello-2 (decode-handshake client-hello-2))
                 (extensions (tls13-client-hello-extensions hello-2))
                 (psk-extension (%client-resumption-extension hello-2 41))
                 (identity-1
                   (nth-value 0
                     (%client-resumption-psk-fields
                      (tls-extension-data
                       (%client-resumption-extension
                        (decode-handshake client-hello-1) 41)))))
                 (binder-1
                   (nth-value 2
                     (%client-resumption-psk-fields
                      (tls-extension-data
                       (%client-resumption-extension
                        (decode-handshake client-hello-1) 41)))))
                 (identity-2 nil)
                 (binder-2 nil))
            (multiple-value-setq (identity-2 binder-2)
              (multiple-value-bind (identity age binder)
                  (%client-resumption-psk-fields (tls-extension-data psk-extension))
                (%client-resumption-check
                 (= age 600001)
                 "HelloRetryRequest recomputes obfuscated age after ticket expiry")
                (values identity binder)))
            (let* ((binder-length (length binder-2))
                   (truncated
                     (subseq client-hello-2 0 (- (length client-hello-2)
                                                 (+ 3 binder-length))))
                   (client-hello-hash
                     (funcall (cl-tls-kit::tls13-crypto-provider-digest provider)
                              :sha256 client-hello-1))
                   (message-hash
                     (cl-tls-kit::%cat #(254)
                                      (cl-tls-kit::%u24 (length client-hello-hash))
                                      client-hello-hash))
                   (binder-transcript
                     (concatenate '(vector (unsigned-byte 8))
                                  message-hash hrr-wire truncated))
                   (binder-hash
                     (funcall (cl-tls-kit::tls13-crypto-provider-digest provider)
                              :sha256 binder-transcript))
                   (expected-binder
                     (cl-tls-kit::tls13-psk-binder
                      provider :sha256
                      (cl-tls-kit::%tls13-session-ticket-psk stored)
                      binder-hash)))
              (%client-resumption-check
               (and (eq stored (cl-tls-kit::tls13-client-driver-offered-ticket driver))
                    (equalp identity-1 identity-2)
                    (equalp identity-2 (%client-resumption-hex "090807")))
               "HelloRetryRequest retains the selected resumption ticket")
              (%client-resumption-check
               (and (equalp binder-2 expected-binder)
                    (not (equalp binder-1 binder-2)))
               "ClientHello 2 recomputes its binder over message_hash and HRR")
              (%client-resumption-check
               (and (eq psk-extension (car (last extensions)))
                    (null (%client-resumption-extension hello-2 42)))
               "HelloRetryRequest ClientHello keeps PSK last and omits early_data"))))))
    (incf selected)
    (let* ((store (make-tls13-ticket-store))
           (stored
             (cl-tls-kit::%tls13-ticket-store-put
              store "example.test" "h2" (%client-resumption-hex "01")
              (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element #x42)
              :sha256 600 0)))
      (multiple-value-bind (driver ignored)
          (%client-resumption-driver provider store "example.test" (list "h2"))
        (declare (ignore ignored))
        (tls13-client-driver-start driver)
        (let* ((psk (cl-tls-kit::%tls13-session-ticket-psk stored))
               (failure
                 (handler-case
                     (progn
                       (tls13-client-driver-step
                        driver (encode-handshake 2 (%client-resumption-server-hello 1)))
                       nil)
                   (tls13-client-driver-error (condition)
                     (eq (tls13-client-driver-error-reason condition)
                         :unexpected-psk-identity)))))
          (%client-resumption-check failure
                                    "invalid selected identity remains a protocol error")
          (%client-resumption-check
           (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
           "fatal ServerHello error closes the retained driver")
          (%client-resumption-check
           (every #'zerop psk)
           "fatal ServerHello cleanup zeroizes the offered PSK buffer"))))
    (incf selected)
    (let* ((store (make-tls13-ticket-store))
           (stored
             (cl-tls-kit::%tls13-ticket-store-put
              store "example.test" "h2" (%client-resumption-hex "01")
              (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element #x42)
              :sha256 600 0)))
      (multiple-value-bind (driver ignored)
          (%client-resumption-driver provider store "example.test" (list "h2"))
        (declare (ignore ignored))
        (setf (getf (cl-tls-kit::tls13-client-driver-key-exchange driver) :random)
              (lambda (length)
                (declare (ignore length))
                (error "Synthetic random callback failure")))
        (let ((failed
                (handler-case (progn (tls13-client-driver-start driver) nil)
                  (error () t))))
          (%client-resumption-check failed
                                    "start propagates a callback failure before ticket transfer")
          (%client-resumption-check
           (every #'zerop (cl-tls-kit::%tls13-session-ticket-psk stored))
           "start cleanup zeroizes a locally held ticket on callback failure")
          (%client-resumption-check
           (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
           "start callback failure closes the driver"))))
    (incf selected)
    (let* ((store (make-tls13-ticket-store))
           (stored
             (cl-tls-kit::%tls13-ticket-store-put
              store "example.test" "h2" (%client-resumption-hex "01")
              (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element #x42)
              :sha256 600 0)))
      (multiple-value-bind (driver ignored)
          (%client-resumption-driver provider store "example.test" (list "h2"))
        (declare (ignore ignored))
        (setf (cl-tls-kit::tls13-client-driver-on-send driver)
              (lambda (ignored-driver ignored-wire)
                (declare (ignore ignored-driver ignored-wire))
                (error "Synthetic send callback failure")))
        (let ((failed
                (handler-case (progn (tls13-client-driver-start driver) nil)
                  (error () t))))
          (%client-resumption-check failed
                                    "start propagates an on-send callback failure")
          (%client-resumption-check
           (every #'zerop (cl-tls-kit::%tls13-session-ticket-psk stored))
           "start cleanup zeroizes an offered PSK after callback failure")
          (%client-resumption-check
           (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
           "on-send callback failure closes the driver"))))
    (incf selected)
    (let* ((store (make-tls13-ticket-store))
           (stored
             (cl-tls-kit::%tls13-ticket-store-put
              store "example.test" "h2" (%client-resumption-hex "01")
              (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element #x42)
              :sha256 600 0)))
      (multiple-value-bind (driver ignored)
          (%client-resumption-driver provider store "example.test" (list "h2"))
        (declare (ignore ignored))
        (setf (getf (cl-tls-kit::tls13-client-driver-key-exchange driver) :shared-secret)
              (lambda (group private peer)
                (declare (ignore group private peer))
                (error "Synthetic shared-secret callback failure")))
        (tls13-client-driver-start driver)
        (let ((failed
                (handler-case
                    (progn
                      (tls13-client-driver-step
                       driver (encode-handshake 2 (%client-resumption-server-hello 0)))
                      nil)
                  (error () t))))
          (%client-resumption-check failed
                                    "step propagates a shared-secret callback failure")
          (%client-resumption-check
           (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
           "step callback failure closes the retained driver")
          (%client-resumption-check
           (every #'zerop (cl-tls-kit::%tls13-session-ticket-psk stored))
           "step callback cleanup zeroizes the offered PSK"))))
    (incf selected)
    (let* ((store (make-tls13-ticket-store))
           (stored
             (cl-tls-kit::%tls13-ticket-store-put
              store "example.test" "h2" (%client-resumption-hex "01")
              (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element #x42)
              :sha256 600 0)))
      (multiple-value-bind (driver ignored)
          (%client-resumption-driver provider store "example.test" (list "h2"))
        (declare (ignore ignored))
        (setf (cl-tls-kit::tls13-client-driver-transport-read driver)
              (lambda (ignored-driver)
                (declare (ignore ignored-driver))
                (error "Synthetic transport-read callback failure")))
        (tls13-client-driver-start driver)
        (let ((failed
                (handler-case (progn (tls13-client-driver-read-record driver) nil)
                  (error () t))))
          (%client-resumption-check failed
                                    "read-record propagates a transport callback failure")
          (%client-resumption-check
           (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
           "read-record callback failure closes the retained driver")
          (%client-resumption-check
           (every #'zerop (cl-tls-kit::%tls13-session-ticket-psk stored))
           "read-record callback cleanup zeroizes the offered PSK"))))
    (incf selected)
    (let* ((rms (make-array 32 :element-type '(unsigned-byte 8)
                            :initial-element #x5a))
           (driver
             (cl-tls-kit::%make-tls13-client-driver
              :state :connected
              :resumption-master-secret rms)))
      (tls13-client-driver-close driver)
      (%client-resumption-check
       (every #'zerop rms)
       "closing zeroizes the resumption master secret buffer")
      (%client-resumption-check
       (null (cl-tls-kit::tls13-client-driver-resumption-master-secret driver))
       "closing clears the resumption master secret slot"))
    (format t "TLS 1.3 client resumption security: selected test count: ~D; assertions: ~D~%"
            selected *client-resumption-assertions*)
    t))
(defun run-client-resumption-regression-tests (provider)
  (let ((selected 0))
    (labels ((hrr-wire (suite)
               (encode-handshake
                2 (make-tls13-server-hello
                   #x0303 cl-tls-kit::*tls13-hrr-random* #() suite
                   (list (make-tls-extension 43 #(#x03 #x04))
                         (make-tls-extension 51
                                             (cl-tls-kit::%hs-u16 #x0017))))))
             (ticket-psk (length)
               (make-array length :element-type '(unsigned-byte 8)
                           :initial-element #x42)))
      (incf selected)
      (let* ((store (make-tls13-ticket-store :clock (lambda () 1000)))
             (stored
               (cl-tls-kit::%tls13-ticket-store-put
                store "hrr.example.test" "h2" (%client-resumption-hex "090807")
                (ticket-psk 48) :sha384 600 7)))
        (multiple-value-bind (driver sent)
            (%client-resumption-driver
             provider store "hrr.example.test" (list "h2")
             #(#x1301 #x1302) (list #x001d #x0017))
          (tls13-client-driver-start driver)
          (let* ((client-hello-1 (first (car sent)))
                 (hrr (hrr-wire #x1302))
                 (hrr-message (decode-handshake hrr)))
            (tls13-client-driver-step driver hrr)
            (let* ((client-hello-2 (first (car sent)))
                   (hello-2 (decode-handshake client-hello-2))
                   (psk (%client-resumption-extension hello-2 41))
                   (binder (nth-value
                            2 (%client-resumption-psk-fields
                               (tls-extension-data psk))))
                   (binder-length (length binder))
                   (truncated (subseq client-hello-2 0
                                      (- (length client-hello-2)
                                         (+ 3 binder-length))))
                   (digest (funcall (cl-tls-kit::tls13-crypto-provider-digest provider)
                                    :sha384 client-hello-1))
                   (message-hash
                     (cl-tls-kit::%cat #(254) (cl-tls-kit::%u24 (length digest))
                                      digest))
                   (transcript
                     (concatenate '(vector (unsigned-byte 8)) message-hash hrr))
                   (binder-hash
                     (funcall (cl-tls-kit::tls13-crypto-provider-digest provider)
                              :sha384
                              (concatenate '(vector (unsigned-byte 8))
                                           transcript truncated)))
                   (expected
                     (cl-tls-kit::tls13-psk-binder
                      provider :sha384
                      (cl-tls-kit::%tls13-session-ticket-psk stored)
                      binder-hash)))
              (%client-resumption-check
               (and (typep hrr-message 'tls13-hello-retry-request)
                    (= (tls13-hello-retry-request-cipher-suite hrr-message) #x1302))
               "HRR preserves the selected TLS_AES_256_GCM_SHA384 suite")
              (%client-resumption-check
               (and (= (cl-tls-kit::tls13-client-driver-suite driver) #x1302)
                    (eq (cl-tls-kit::tls13-client-driver-hash driver) :sha384)
                    (equalp (cl-tls-kit::tls13-client-driver-transcript driver)
        (concatenate '(vector (unsigned-byte 8))
                     transcript client-hello-2)))
               "SHA384 HRR rebuilds message_hash and transcript with SHA384")
              (%client-resumption-check
               (and (eq stored
                        (cl-tls-kit::tls13-client-driver-offered-ticket driver))
                    (= binder-length 48)
                    (equalp binder expected))
               "SHA384 HRR recomputes a 48-byte ticket binder over ClientHello2")))))
      (incf selected)
      (let* ((store (make-tls13-ticket-store :clock (lambda () 1000)))
             (stored
               (cl-tls-kit::%tls13-ticket-store-put
                store "mismatch.example.test" "h2" (%client-resumption-hex "01")
                (ticket-psk 32) :sha256 600 0)))
        (multiple-value-bind (driver sent)
            (%client-resumption-driver
             provider store "mismatch.example.test" (list "h2")
             #(#x1301 #x1302) (list #x001d #x0017))
          (tls13-client-driver-start driver)
          (tls13-client-driver-step driver (hrr-wire #x1302))
          (let* ((hello-2 (decode-handshake (first (car sent))))
                 (extensions (tls13-client-hello-extensions hello-2)))
            (%client-resumption-check
             (and (null (%client-resumption-extension hello-2 41))
                  (null (%client-resumption-extension hello-2 45))
                  (null (cl-tls-kit::tls13-client-driver-offered-ticket driver))
                  (every #'zerop (cl-tls-kit::%tls13-session-ticket-psk stored))
                  (eq (cl-tls-kit::tls13-client-driver-hash driver) :sha384))
             "SHA256 ticket is dropped when HRR selects a SHA384 suite")
            (%client-resumption-check
             (not (member 41 extensions :key #'tls-extension-type))
             "hash-mismatched PSK is absent from ClientHello2"))))
      (incf selected)
      (let* ((now 1000)
             (derivation-count 0)
             (resume-label (map 'vector (function char-code) "tls13 resumption"))
             (clocked-provider
               (let* ((copy (cl-tls-kit::copy-tls13-crypto-provider provider))
                      (expand
                        (cl-tls-kit::tls13-crypto-provider-hkdf-expand copy)))
                 (setf (cl-tls-kit::tls13-crypto-provider-hkdf-expand copy)
                       (lambda (hash secret info length)
                         (when (and (>= (length info) (+ 3 (length resume-label)))
                                    (= (aref info 2) (length resume-label))
                                    (equalp (subseq info 3 (+ 3 (length resume-label)))
                                            resume-label))
                           (incf derivation-count)
                           (setf now 2001))
                         (funcall expand hash secret info length)))
                 copy))
             (store (make-tls13-ticket-store :clock (lambda () now)))
             (driver
               (cl-tls-kit::%make-tls13-client-driver
                :provider clocked-provider :ticket-store store
                :hostname "receipt.example.test" :hash :sha256 :suite #x1301
                :state :connected :negotiated-alpn "h2"
                :resumption-master-secret (ticket-psk 32))))
        (tls13-client-driver-step
         driver
         (encode-handshake
          4 (make-tls13-new-session-ticket
             3 (%client-resumption-hex "0000") (%client-resumption-hex "090807")
             nil 100)))
        (let* ((key (cl-tls-kit::%tls13-ticket-key "receipt.example.test" "h2"))
               (ticket (first (gethash key
                                       (cl-tls-kit::tls13-ticket-store-entries store)))))
          (%client-resumption-check
           (and (= derivation-count 1)
                (= now 2001)
                ticket
                (= (cl-tls-kit::%tls13-session-ticket-created-at ticket) 1000))
           "NewSessionTicket stores its receipt time before PSK derivation")
          (multiple-value-bind (client sent)
              (%client-resumption-driver
               provider store "receipt.example.test" (list "h2"))
            (tls13-client-driver-start client)
            (%client-resumption-check
             (= (nth-value
                 1 (%client-resumption-psk-fields
                    (tls-extension-data
                     (%client-resumption-extension
                      (decode-handshake (first (car sent))) 41))))
                1101)
             "ticket age uses receipt time across delayed registration"))))
      (incf selected)
      (let* ((now 1000)
             (derivation-count 0)
             (resume-label (map 'vector (function char-code) "tls13 resumption"))
             (clocked-provider
               (let* ((copy (cl-tls-kit::copy-tls13-crypto-provider provider))
                      (expand
                        (cl-tls-kit::tls13-crypto-provider-hkdf-expand copy)))
                 (setf (cl-tls-kit::tls13-crypto-provider-hkdf-expand copy)
                       (lambda (hash secret info length)
                         (when (and (>= (length info) (+ 3 (length resume-label)))
                                    (= (aref info 2) (length resume-label))
                                    (equalp (subseq info 3 (+ 3 (length resume-label)))
                                            resume-label))
                           (incf derivation-count)
                           (setf now 2001))
                         (funcall expand hash secret info length)))
                 copy))
             (store (make-tls13-ticket-store :clock (lambda () now)))
             (driver
               (cl-tls-kit::%make-tls13-client-driver
                :provider clocked-provider :ticket-store store
                :hostname "expiry.example.test" :hash :sha256 :suite #x1301
                :state :connected :negotiated-alpn "h2"
                :resumption-master-secret (ticket-psk 32))))
        (tls13-client-driver-step
         driver
         (encode-handshake
          4 (make-tls13-new-session-ticket
             1 (%client-resumption-hex "0000") (%client-resumption-hex "090807")
             nil 100)))
        (%client-resumption-check
         (and (= derivation-count 1)
              (= now 2001)
              (zerop (cl-tls-kit::%tls13-ticket-store-count store)))
         "one-second ticket expires during PSK derivation from receipt time"))
      (incf selected)
      (let* ((store (make-tls13-ticket-store :clock (lambda () 1000)))
             (stored
               (cl-tls-kit::%tls13-ticket-store-put
                store "target-a.example.test" "h2" (%client-resumption-hex "01")
                (ticket-psk 32) :sha256 600 0)))
        (multiple-value-bind (driver ignored)
            (%client-resumption-driver provider store nil (list "h2"))
          (declare (ignore ignored))
          (tls13-client-driver-start driver)
          (%client-resumption-check
           (and (not (%client-resumption-has-psk-p driver))
                (= (cl-tls-kit::%tls13-ticket-store-count store) 1)
                (not (every #'zerop
                            (cl-tls-kit::%tls13-session-ticket-psk stored))))
           "nil hostname neither offers nor consumes another host ticket"))
        (let ((producer
                (cl-tls-kit::%make-tls13-client-driver
                 :provider provider :ticket-store store :hostname nil
                 :hash :sha256 :suite #x1301 :state :connected
                 :negotiated-alpn "h2"
                 :resumption-master-secret (ticket-psk 32))))
          (tls13-client-driver-step
           producer
           (encode-handshake
            4 (make-tls13-new-session-ticket
               600 (%client-resumption-hex "0000")
               (%client-resumption-hex "090807") nil 3)))
          (%client-resumption-check
           (= (cl-tls-kit::%tls13-ticket-store-count store) 1)
           "NewSessionTicket is not stored when hostname is unknown"))
        (multiple-value-bind (driver ignored)
            (%client-resumption-driver
             provider store "target-a.example.test" (list "h2"))
          (declare (ignore ignored))
          (tls13-client-driver-start driver)
          (%client-resumption-check
           (%client-resumption-has-psk-p driver)
           "known hostname can still consume its own scoped ticket")))
      (incf selected)
      (let* ((factory-symbol (quote cl-tls-kit::%make-tls-client-tcp-transport))
             (factory (symbol-function factory-symbol)))
        (unwind-protect
             (progn
               (setf (symbol-function factory-symbol)
                     (lambda (host port)
                       (declare (ignore host port))
                       (list :read nil :write nil :close nil)))
               (let ((client
                       (cl-tls-kit:make-tls-client-over-tcp
                        "facade.example.test" 443)))
                 (%client-resumption-check
                  (string= (cl-tls-kit::tls-client-hostname client)
                           "facade.example.test")
                  "legacy TCP facade defaults hostname from its destination")
                 (cl-tls-kit:tls-client-close client))
               (let ((client
                       (cl-tls-kit:make-tls-client-over-tcp
                        "facade.example.test" 443 :hostname "override.example.test")))
                 (%client-resumption-check
                  (string= (cl-tls-kit::tls-client-hostname client)
                           "override.example.test")
                  "legacy TCP facade preserves an explicit hostname override")
                 (cl-tls-kit:tls-client-close client)))
          (setf (symbol-function factory-symbol) factory)))
      (format t "TLS 1.3 client resumption regressions: selected test count: ~D; assertions: ~D~%"
              selected *client-resumption-assertions*)
      t)))
