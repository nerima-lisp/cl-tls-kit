(in-package #:cl-tls-kit/test)

(defun %server-driver-test-event (events type)
  (find type events :key (lambda (event) (getf event :type))))

(defun %server-driver-test-events (events type)
  (remove-if-not (lambda (event) (eq (getf event :type) type)) events))

(defun %server-driver-test-random ()
  (let ((counter 0))
    (lambda (length)
      (let ((bytes (make-array length :element-type '(unsigned-byte 8))))
        (dotimes (index length bytes)
          (setf (aref bytes index) (mod (incf counter) 256)))))))

(defun %server-driver-test-client (provider &key (alpn '("h2" "http/1.1"))
                                             (groups '(#x001d #x0017))
                                             (schemes #( #x0804 #x0403 #x0807))
                                             (cipher-suites #( #x1301 #x1302 #x1303 #x1304))
                                             trust-anchors (now (get-universal-time))
                                             on-certificate-verify)
  (let ((outgoing (list nil)))
    (let ((driver
            (make-tls13-client-driver
             :provider provider :hostname "server.test" :alpn alpn
             :supported-groups groups :signature-algorithms schemes
             :cipher-suites cipher-suites
             :trust-anchors trust-anchors :now now
             :verify-certificate-verify on-certificate-verify
             :on-send (lambda (ignored wire)
                        (declare (ignore ignored))
                        (push wire (car outgoing))))))
      (values driver outgoing))))

(defun %server-driver-test-client-hello (driver outgoing)
  (tls13-client-driver-start driver)
  (let ((wire (pop (car outgoing))))
    (unless wire (error "Client driver did not send a ClientHello"))
    (values wire (decode-handshake wire))))

(defun %server-driver-test-rewrite-client-hello (hello extension-type data)
  (make-tls13-client-hello
   (tls13-client-hello-legacy-version hello)
   (tls13-client-hello-random hello)
   (tls13-client-hello-session-id hello)
   (tls13-client-hello-cipher-suites hello)
   (append
    (remove extension-type (tls13-client-hello-extensions hello)
            :key #'tls-extension-type)
    (unless (eq data :remove)
      (list (make-tls-extension extension-type data))))))

(defun %server-driver-test-duplicate-extension-wire (wire extension-type)
  (let* ((body (subseq wire 4))
         (session-id-result
           (multiple-value-list
            (cl-tls-kit::%read-vector body 34 1 :maximum 32)))
         (cipher-suites-result
           (multiple-value-list
            (cl-tls-kit::%read-vector body (second session-id-result) 2 :minimum 2)))
         (compression-result
           (multiple-value-list
            (cl-tls-kit::%read-vector body (second cipher-suites-result) 1)))
         (extensions-length-position (second compression-result)))
    (multiple-value-bind (extensions-length extensions-start)
        (cl-tls-kit::%read-integer body extensions-length-position 2)
      (let ((cursor extensions-start)
            (end (+ extensions-start extensions-length))
            (duplicate nil))
        (loop while (< cursor end) do
          (multiple-value-bind (type next)
              (cl-tls-kit::%read-integer body cursor 2)
            (multiple-value-bind (length data-start)
                (cl-tls-kit::%read-integer body next 2)
              (let ((next-extension (+ data-start length)))
                (when (= type extension-type)
                  (setf duplicate (subseq body cursor next-extension)))
                (setf cursor next-extension)))))
        (unless duplicate
          (error "ClientHello has no extension ~D to duplicate" extension-type))
        (let* ((extensions
                 (cl-tls-kit::%tls13-server-cat
                  (subseq body extensions-start end) duplicate))
               (new-body
                 (cl-tls-kit::%tls13-server-cat
                  (subseq body 0 extensions-length-position)
                  (cl-tls-kit::%tls13-server-u16 (length extensions))
                  extensions)))
          (cl-tls-kit::%tls13-server-cat
           #(1) (cl-tls-kit::%tls13-server-u24 (length new-body)) new-body))))))

(defun %server-driver-test-u16-list (values)
  (cl-tls-kit::%encode-vector
   (apply #'cl-tls-kit::%cat (mapcar #'cl-tls-kit::%hs-u16 values)) 2))

(defun %server-driver-test-u32 (value)
  (vector (ldb (byte 8 24) value) (ldb (byte 8 16) value)
          (ldb (byte 8 8) value) (ldb (byte 8 0) value)))

(defun %server-driver-test-server
    (provider chain key ticket-key-store clock &key (groups '(#x001d #x0017))
              (alpn '("http/1.1" "h2"))
              (cipher-suites #( #x1301 #x1302 #x1303 #x1304))
              (max-consecutive-key-updates 32)
              (quic-transport-parameters nil quic-transport-parameters-supplied-p))
  (let ((arguments
          (list :provider provider :certificate-chain chain :private-key key
                :alpn-protocols alpn :ticket-key-store ticket-key-store
                :supported-groups groups :cipher-suites cipher-suites
                :clock clock :random (%server-driver-test-random)
                :max-consecutive-key-updates max-consecutive-key-updates)))
    (when quic-transport-parameters-supplied-p
      (setf arguments
            (append arguments
                    (list :quic-transport-parameters quic-transport-parameters))))
    (apply #'make-tls13-server-driver arguments)))

(defun %server-driver-test-state-snapshot (driver)
  (list (cl-tls-kit::tls13-server-driver-state driver)
        (cl-tls-kit::tls13-server-driver-selected-alpn driver)
        (cl-tls-kit::tls13-server-driver-selected-suite driver)
        (cl-tls-kit::tls13-server-driver-sni-hostname driver)
        (cl-tls-kit::tls13-server-driver-hash driver)
        (cl-tls-kit::tls13-server-driver-selected-group driver)
        (cl-tls-kit::tls13-server-driver-hrr-seen-p driver)
        (cl-tls-kit::tls13-server-driver-resumed-p driver)
        (copy-seq (cl-tls-kit::tls13-server-driver-transcript driver))))

(defun %server-driver-test-alert-p (events description)
  (let ((alert (%server-driver-test-event events :alert))
        (send (find-if (lambda (event)
                         (and (eq (getf event :type) :send)
                              (eq (getf event :content-type) :alert)))
                       events)))
    (and alert send
         (= (getf alert :description) description)
         (equalp (getf send :wire) (vector 2 description)))))

(defun %server-driver-test-with-key-update-derivation-counter (function)
  (let* ((symbol (find-symbol "%TLS13-SERVER-UPDATE-TRAFFIC-SECRET" :cl-tls-kit))
         (original (and symbol (fboundp symbol) (symbol-function symbol)))
         (calls 0))
    (unless original
      (error "TLS server KeyUpdate derivation function is unavailable"))
    (unwind-protect
         (progn
           (setf (symbol-function symbol)
                 (lambda (&rest arguments)
                   (incf calls)
                   (apply original arguments)))
           (funcall function (lambda () calls)))
      (setf (symbol-function symbol) original))))

(defun %server-driver-test-assert-client-hello-rejected (name driver wire expected-alert check-case)
  (multiple-value-bind (returned events)
      (tls13-server-driver-step driver wire :level :initial)
    (funcall check-case (eq returned driver)
             (format nil "~A returns the same server driver" name))
    (funcall check-case (%server-driver-test-alert-p events expected-alert)
             (format nil "~A emits fatal alert ~D (got ~S)" name expected-alert
                     (getf (%server-driver-test-event events :alert) :description)))
    (funcall check-case
             (eq (getf (%server-driver-test-event events :send) :level) :initial)
             (format nil "~A sends its fatal alert at the initial level" name))
    (funcall check-case
             (and (eq (cl-tls-kit::tls13-server-driver-state driver) :failed)
                  (zerop (length (cl-tls-kit::tls13-server-driver-transcript driver)))
                  (null (cl-tls-kit::tls13-server-driver-provider driver))
                  (null (cl-tls-kit::tls13-server-driver-key-exchange driver))
                  (null (cl-tls-kit::tls13-server-driver-private-key-share driver)))
             (format nil "~A fails closed and releases handshake state" name))
    events))

(defun %server-driver-test-memory-handshake
    (provider chain key anchor ticket-key-store now &key (groups '(#x001d #x0017))
                                                   (alpn '("h2" "http/1.1"))
                                                   quic-transport-parameters
                                                   client-quic-transport-parameters)
  (let ((client-outgoing (list nil))
        (client-certificate-verify-count 0)
        (server-alpn nil)
        (ticket-event nil)
        (hrr-count 0)
        (events-seen nil)
        (client-hello-wires nil)
        (client-quic-injected-p nil)
        (client nil)
        (server nil))
    (setf client
          (make-tls13-client-driver
           :provider provider :hostname "server.test" :alpn alpn
           :trust-anchors (list anchor) :now now
           :verify-certificate-verify
           (lambda (message)
             (declare (ignore message))
             (incf client-certificate-verify-count))
           :on-send (lambda (ignored wire)
                      (declare (ignore ignored))
                      (push wire (car client-outgoing))))
          server
          (apply #'%server-driver-test-server
                 provider chain key ticket-key-store (lambda () now)
                 (append
                  (list :groups groups :alpn
                        (if (member "http/1.1" alpn :test #'string=)
                            '("http/1.1" "h2")
                            alpn))
                  (when quic-transport-parameters
                    (list :quic-transport-parameters
                          quic-transport-parameters)))))
    (tls13-client-driver-start client)
    (loop repeat 8
          for client-wire = (pop (car client-outgoing))
          while client-wire
          do (when (= (aref client-wire 0) 1)
               (when (and client-quic-transport-parameters
                          (not client-quic-injected-p))
                 (let* ((hello (decode-handshake client-wire))
                        (quic-hello
                          (%server-driver-test-rewrite-client-hello
                           hello #x0039 client-quic-transport-parameters)))
                   (setf client-wire (encode-handshake 1 quic-hello)
                         client-quic-injected-p t
                         (cl-tls-kit::tls13-client-driver-client-hello client)
                         quic-hello
                         (cl-tls-kit::tls13-client-driver-transcript client)
                         (copy-seq client-wire))))
               (push (copy-seq client-wire) client-hello-wires))
          do (multiple-value-bind (returned events)
                 (tls13-server-driver-step
                  server client-wire
                  :level (if (= (aref client-wire 0) 20) :handshake :initial))
               (setf server returned
                     events-seen (append events-seen events))
               (dolist (event events)
                 (if (and (consp event)
                          (eq (first event) :peer-quic-transport-parameters))
                     nil
                   (case (getf event :type)
                     (:send
                      (when (eq (getf event :content-type) :alert)
                        (error "Memory handshake server emitted alert ~S"
                               (getf (%server-driver-test-event events :alert)
                                     :description)))
                      (let ((message (decode-handshake (getf event :wire))))
                        (when (typep message 'tls13-hello-retry-request)
                          (incf hrr-count))
                        (tls13-client-driver-step client (getf event :wire))))
                     (:alpn (setf server-alpn (getf event :protocol)))
                     (:ticket-issued (setf ticket-event event))
                     ((:cipher-suite :secret :handshake-complete) nil)
                     (otherwise (error "Unknown server driver event ~S"
                                       (getf event :type))))))))
    (values server client server-alpn ticket-event hrr-count
            client-certificate-verify-count events-seen (car client-outgoing)
            (nreverse client-hello-wires))))
(defun %server-driver-test-client-server-resumption-roundtrip
    (provider chain key anchor ticket-key-store now check-case &key (suite #x1301)
                                                        hello-retry-p client-cipher-suites)
  (let ((ticket-store (make-tls13-ticket-store :clock (lambda () 0))))
    (labels
        ((queue-server-record (endpoint wire)
           (setf (gethash :server-records endpoint)
                 (nconc (gethash :server-records endpoint) (list wire))))
         (process-server-events (endpoint events)
           (dolist (event events)
             (case (getf event :type)
               (:secret
                (let* ((direction (getf event :direction))
                       (level (getf event :level))
                       (states (gethash (if (eq direction :read)
                                            :read-states :write-states)
                                        endpoint)))
                  (setf (gethash (list direction level) states)
                        (cl-tls-kit::make-tls13-traffic-state
                         provider
                         (cl-tls-kit::tls13-cipher-suite-hash suite)
                         (if (= suite #x1302) :aes-256-gcm :aes-128-gcm)
                         (getf event :secret)
                         (if (= suite #x1302) 32 16)
                         12))))
               (:send
                (let* ((level (getf event :level))
                       (content-type
                         (case (getf event :content-type)
                           ((:alert 21) 21)
                           ((:application-data 23) 23)
                           (otherwise 22)))
                       (plaintext
                         (cl-tls-kit:make-tls-plaintext content-type (getf event :wire)))
                       (state (unless (eq level :initial)
                                (or (gethash (list :write level)
                                             (gethash :write-states endpoint))
                                    (error "Server traffic secret was not installed")))))
                  (queue-server-record
                   endpoint
                   (if state
                       (cl-tls-kit:encrypt-tls13-traffic-record plaintext state)
                       (cl-tls-kit::encode-tls-plaintext plaintext)))))
               (:ticket-issued (setf (gethash :ticket-issued endpoint) t))
               (:handshake-complete
                (setf (gethash :handshake-complete endpoint) t
                      (gethash :resumed endpoint) (getf event :resumed-p)))
               ((:cipher-suite :alpn) nil)
               (:alert (error "Server driver emitted fatal alert ~D"
                              (getf event :description)))
               (otherwise (error "Unknown server driver event ~S"
                                 (getf event :type))))))
         (dispatch-handshake (endpoint wire level)
           (multiple-value-bind (driver events)
               (tls13-server-driver-step (gethash :server endpoint) wire :level level)
             (setf (gethash :server endpoint) driver)
             (process-server-events endpoint events)))
         (process-client-record (endpoint wire)
           (case (aref wire 0)
             (20 nil)
             (22
              (let ((plaintext (cl-tls-kit::decode-tls-plaintext wire)))
                (dispatch-handshake endpoint
                                    (cl-tls-kit:tls-plaintext-fragment plaintext)
                                    :initial)))
             (23
              (let* ((level (if (gethash :handshake-complete endpoint)
                                :application :handshake))
                     (state (or (gethash (list :read level)
                                         (gethash :read-states endpoint))
                                (error "Client traffic secret was not installed")))
                     (plaintext (cl-tls-kit:decrypt-tls13-traffic-record wire state))
                     (content-type (cl-tls-kit:tls-plaintext-content-type plaintext))
                     (fragment (cl-tls-kit:tls-plaintext-fragment plaintext)))
                (when (= content-type 23)
                  (tls13-server-driver-note-application-data-received
                   (gethash :server endpoint)))
                (case content-type
                  (22 (dispatch-handshake endpoint fragment level))
                  (23
                   (setf (gethash :application-data endpoint)
                         (append (gethash :application-data endpoint)
                                 (list (copy-seq fragment))))
                   (queue-server-record
                    endpoint
                    (cl-tls-kit:encrypt-tls13-traffic-record
                     (cl-tls-kit:make-tls-plaintext 23 fragment)
                     (or (gethash (list :write :application)
                                  (gethash :write-states endpoint))
                         (error "Server application traffic secret is unavailable")))))
                  (otherwise (error "Unexpected client TLS content type ~D"
                                    content-type)))))
             (otherwise (error "Unexpected client TLS record type ~D"
                               (aref wire 0)))))
         (make-endpoint ()
           (let* ((endpoint (make-hash-table :test (function eq)))
                  (server (%server-driver-test-server
                           provider chain key ticket-key-store (lambda () now)
                           :groups (if hello-retry-p '(#x0017) '(#x001d))
                           :alpn '("http/1.1")
                           :cipher-suites (vector suite))))
             (setf (gethash :server endpoint) server
                   (gethash :client-records endpoint) nil
                   (gethash :server-records endpoint) nil
                   (gethash :read-states endpoint)
                   (make-hash-table :test (function equal))
                   (gethash :write-states endpoint)
                   (make-hash-table :test (function equal))
                   (gethash :application-data endpoint) nil
                   (gethash :certificate-verify-count endpoint) 0
                   (gethash :client endpoint)
                   (make-tls13-client-driver
                    :provider provider :hostname "server.test"
                    :alpn '("http/1.1")
                    :cipher-suites (or client-cipher-suites (vector suite))
                    :supported-groups (if hello-retry-p
                                          '(#x001d #x0017)
                                          '(#x001d))
                    :trust-anchors (list anchor) :now now :ticket-store ticket-store
                    :verify-certificate-verify
                    (lambda (message)
                      (declare (ignore message))
                      (incf (gethash :certificate-verify-count endpoint)))
                    :transport-write
                    (lambda (driver wire)
                      (declare (ignore driver))
                      (setf (gethash :client-records endpoint)
                            (nconc (gethash :client-records endpoint)
                                   (list (copy-seq wire)))))
                    :transport-read
                    (lambda (driver)
                      (declare (ignore driver))
                      (unless (gethash :server-records endpoint)
                        (loop while (gethash :client-records endpoint)
                              for wire = (pop (gethash :client-records endpoint))
                              do (process-client-record endpoint wire)))
                      (pop (gethash :server-records endpoint)))))
             endpoint)))
      (let* ((full (make-endpoint))
             (client (gethash :client full)))
        (tls13-client-driver-connect client)
        (funcall check-case
                 (eq (cl-tls-kit::tls13-client-driver-state client) :connected)
                 "memory client completes a full TLS handshake over TLS records")
        (funcall check-case
                 (and (eql (not (null hello-retry-p))
                           (cl-tls-kit::tls13-client-driver-hello-retry-request-received
                            client))
                      (or (not hello-retry-p)
                          (and (= (cl-tls-kit::tls13-client-driver-suite client) suite)
                               (eq (cl-tls-kit::tls13-client-driver-hash client)
                                   :sha384))))
                 "full handshake uses the expected HelloRetryRequest suite hash")
        (tls13-client-driver-read-record client)
        (funcall check-case
                 (and (gethash :ticket-issued full)
                      (gethash :handshake-complete full)
                      (not (gethash :resumed full)))
                 "full handshake delivers NewSessionTicket after client Finished")
        (funcall check-case
                 (= (cl-tls-kit::%tls13-ticket-store-count ticket-store) 1)
                 "client driver stores the received session ticket")
        (funcall check-case
                 (= (gethash :certificate-verify-count full) 1)
                 "client driver verifies CertificateVerify on the full handshake")
        (let* ((resumed (make-endpoint))
               (resumed-client (gethash :client resumed)))
          (tls13-client-driver-connect resumed-client)
          (let* ((hello (cl-tls-kit::tls13-client-driver-client-hello resumed-client))
                 (psk (find 41 (tls13-client-hello-extensions hello)
                            :key (function tls-extension-type))))
            (funcall check-case psk
                     "second ClientHello offers the stored ticket as a PSK"))
          (tls13-client-driver-read-record resumed-client)
          (funcall check-case
                   (and (tls13-client-driver-resumed-p resumed-client)
                        (gethash :handshake-complete resumed)
                        (gethash :resumed resumed))
                   "server and client complete the second handshake with PSK resumption")
          (funcall check-case
                   (and (eql (not (null hello-retry-p))
                             (cl-tls-kit::tls13-client-driver-hello-retry-request-received
                              resumed-client))
                        (or (not hello-retry-p)
                            (and (= (cl-tls-kit::tls13-client-driver-suite resumed-client)
                                    suite)
                                 (eq (cl-tls-kit::tls13-client-driver-hash resumed-client)
                                     :sha384))))
                   "resumed handshake uses the expected HelloRetryRequest suite hash")
          (funcall check-case
                   (zerop (gethash :certificate-verify-count resumed))
                   "resumed handshake omits CertificateVerify")
          (let* ((client-read-state
                   (cl-tls-kit::tls13-client-driver-application-read-state resumed-client))
                 (client-write-state
                   (cl-tls-kit::tls13-client-driver-application-write-state resumed-client))
                 (old-client-read-secret
                   (copy-seq (tls13-traffic-state-secret client-read-state)))
                 (old-client-write-secret
                   (copy-seq (tls13-traffic-state-secret client-write-state))))
            (tls13-client-driver-key-update resumed-client 1)
            (funcall check-case
                     (null (tls13-client-driver-read-record resumed-client))
                     "server replies to a client KeyUpdate request")
            (funcall check-case
                     (not (equalp old-client-read-secret
                                  (tls13-traffic-state-secret client-read-state)))
                     "client updates its read key after the server KeyUpdate")
            (funcall check-case
                     (not (equalp old-client-write-secret
                                  (tls13-traffic-state-secret client-write-state)))
                     "client updates its write key after sending KeyUpdate"))
          (let* ((payload #(99 108 105 101 110 116 45 100 97 116 97))
                 (reply nil))
            (tls13-client-driver-write resumed-client payload)
            (setf reply (tls13-client-driver-read-record resumed-client))
            (funcall check-case
                     (equalp (first (gethash :application-data resumed)) payload)
                     "server receives encrypted client application data")
            (funcall check-case
                     (and reply
                          (= (tls-plaintext-content-type reply) 23)
                          (equalp (tls-plaintext-fragment reply) payload))
                     "client receives the encrypted application-data response")
            (funcall check-case
                     (equalp
                      (tls13-traffic-state-secret
                       (gethash (list :read :application)
                                (gethash :read-states resumed)))
                      (tls13-traffic-state-secret
                       (cl-tls-kit::tls13-client-driver-application-write-state
                        resumed-client)))
                     "server installs the client write key after KeyUpdate")
            (funcall check-case
                     (equalp
                      (tls13-traffic-state-secret
                       (gethash (list :write :application)
                                (gethash :write-states resumed)))
                      (tls13-traffic-state-secret
                       (cl-tls-kit::tls13-client-driver-application-read-state
                        resumed-client)))
                     "client and server use matching application keys after KeyUpdate"))))
      t)))

(defun %server-driver-test-psk-client-hello
    (provider ticket identity age now &key corrupt-binder-p remove-psk-modes-p
                                      (cipher-suites #( #x1301 #x1302 #x1303 #x1304)))
  (multiple-value-bind (client outgoing)
      (%server-driver-test-client provider :alpn '("http/1.1")
                                  :cipher-suites cipher-suites :trust-anchors nil
                                  :now now)
    (multiple-value-bind (ignored hello)
        (%server-driver-test-client-hello client outgoing)
      (declare (ignore ignored))
      (let* ((hash (cl-tls-kit::tls13-cipher-suite-hash (getf ticket :suite)))
             (hash-length (length (cl-tls-kit::tls13-empty-hash provider hash)))
             (zero-binder (make-array hash-length :element-type '(unsigned-byte 8)
                                      :initial-element 0))
             (identity-entry
               (cl-tls-kit::%cat
                (cl-tls-kit::%encode-vector identity 2 :minimum 1)
                (%server-driver-test-u32 age)))
             (identities (cl-tls-kit::%encode-vector identity-entry 2 :minimum 7))
             (binder-entry
               (cl-tls-kit::%cat (vector hash-length) zero-binder))
             (binders (cl-tls-kit::%encode-vector binder-entry 2 :minimum 33))
             (psk-data (cl-tls-kit::%cat identities binders))
             (extensions
               (append
                (remove-if
                 (lambda (extension)
                   (member (tls-extension-type extension) '(41 45)))
                 (tls13-client-hello-extensions hello))
                (unless remove-psk-modes-p
                  (list (make-tls-extension 45 #(1 1))))
                (list (make-tls-extension 41 psk-data))))
             (psk-hello
               (make-tls13-client-hello
                (tls13-client-hello-legacy-version hello)
                (tls13-client-hello-random hello)
                (tls13-client-hello-session-id hello)
                cipher-suites
                extensions))
             (wire (encode-handshake 1 psk-hello))
             (decoded (decode-handshake wire))
             (psk-extension
               (find 41 (tls13-client-hello-extensions decoded)
                     :key #'tls-extension-type))
             (prefix-length
               (progn
                 (unless psk-extension
                   (error "Test ClientHello has no pre_shared_key extension"))
                 (cl-tls-kit::%tls13-server-psk-prefix-length wire)))
             (early-secret (cl-tls-kit:tls13-early-secret
                            provider hash (getf ticket :psk)))
             (binder-key
               (cl-tls-kit:tls13-derive-secret
                provider hash early-secret "res binder"
                (cl-tls-kit::tls13-empty-hash provider hash)))
             (finished-key (cl-tls-kit:tls13-finished-key
                            provider hash binder-key))
             (binder
               (cl-tls-kit:tls13-compute-finished-verify-data
                provider hash finished-key
                (funcall (cl-tls-kit::tls13-crypto-provider-digest provider)
                         hash (subseq wire 0 prefix-length)))))
        (unless (= (length binder) hash-length)
          (error "Test binder has an unexpected hash length"))
        (replace wire binder :start1 (- (length wire) hash-length))
        (when corrupt-binder-p
          (setf (aref wire (1- (length wire)))
                (logxor (aref wire (1- (length wire))) 1)))
        (values client wire)))))

(defun %server-driver-test-complete-resumed-handshake
    (provider server client client-hello-wire ticket-fields server-events check-case)
  (let* ((send-events (%server-driver-test-events server-events :send))
         (server-hello-wire
           (getf (find-if (lambda (event) (= (aref (getf event :wire) 0) 2))
                          send-events)
                 :wire))
         (encrypted-extensions-wire
           (getf (find-if (lambda (event) (= (aref (getf event :wire) 0) 8))
                          send-events)
                 :wire))
         (server-finished-wire
           (getf (find-if (lambda (event) (= (aref (getf event :wire) 0) 20))
                          send-events)
                 :wire))
         (server-hello (decode-handshake server-hello-wire))
         (share (decode-key-share-server-extension
                 (tls-extension-data
                  (find 51 (tls13-server-hello-extensions server-hello)
                        :key #'tls-extension-type))))
         (group (car share))
         (private (cl-tls-kit::tls13-client-driver-private-key client))
         (shared-secret
           (funcall (getf (cl-tls-kit::tls13-client-driver-key-exchange client)
                          :shared-secret)
                    group private (cdr share)))
         (suite (tls13-server-hello-cipher-suite server-hello))
         (hash (cl-tls-kit::tls13-cipher-suite-hash suite))
         (server-hello-transcript
           (cl-tls-kit::%cat client-hello-wire server-hello-wire))
         (server-hello-hash
           (funcall (cl-tls-kit::tls13-crypto-provider-digest provider)
                    hash server-hello-transcript))
         (early-secret
           (cl-tls-kit:tls13-early-secret provider hash (getf ticket-fields :psk)))
         (handshake-secret
           (cl-tls-kit:tls13-handshake-secret provider hash early-secret shared-secret))
         (client-secret
           (cl-tls-kit:tls13-traffic-secret provider hash handshake-secret
                                            :client server-hello-hash))
         (server-secret
           (cl-tls-kit:tls13-traffic-secret provider hash handshake-secret
                                            :server server-hello-hash))
         (server-finished-key
           (cl-tls-kit:tls13-finished-key provider hash server-secret))
         (client-finished-key
           (cl-tls-kit:tls13-finished-key provider hash client-secret))
         (transcript-before-server-finished
           (cl-tls-kit::%cat client-hello-wire server-hello-wire
                             encrypted-extensions-wire))
         (server-finished-hash
           (funcall (cl-tls-kit::tls13-crypto-provider-digest provider)
                    hash transcript-before-server-finished))
         (server-finished (decode-handshake server-finished-wire)))
    (funcall check-case
             (equalp (tls13-finished-verify-data server-finished)
                     (cl-tls-kit:tls13-compute-finished-verify-data
                      provider hash server-finished-key server-finished-hash))
             "resumed client verifies the server Finished")
    (funcall check-case
             (and (notany (lambda (event)
                            (member (aref (getf event :wire) 0) '(11 15)))
                          send-events)
                  (find :secret server-events :key (lambda (event) (getf event :type))))
             "resumed server flight omits Certificate and CertificateVerify")
    (let* ((transcript-through-server-finished
             (cl-tls-kit::%cat transcript-before-server-finished
                               server-finished-wire))
           (client-finished-hash
             (funcall (cl-tls-kit::tls13-crypto-provider-digest provider)
                      hash transcript-through-server-finished))
           (client-finished-wire
             (encode-handshake
              20 (make-tls13-finished
                  (cl-tls-kit:tls13-compute-finished-verify-data
                   provider hash client-finished-key client-finished-hash)))))
      (multiple-value-bind (returned events)
          (tls13-server-driver-step server client-finished-wire :level :handshake)
        (setf server returned)
        (funcall check-case
                 (and (%server-driver-test-event events :handshake-complete)
                      (getf (%server-driver-test-event events :handshake-complete)
                            :resumed-p))
                 "valid PSK handshake completes as resumed")))))

(defun %server-driver-test-with-signature-counter (function)
  (let* ((package (or (find-package "CRYPTO-KIT")
                      (find-package "CL-CRYPTO-KIT")))
         (symbol (and package (find-symbol "SIGN-MESSAGE" package)))
         (original (and symbol (fboundp symbol) (symbol-function symbol)))
         (calls 0))
    (unless original
      (error "cl-crypto-kit does not provide SIGN-MESSAGE"))
    (unwind-protect
         (progn
           (setf (symbol-function symbol)
                 (lambda (&rest arguments)
                   (incf calls)
                   (apply original arguments)))
           (funcall function (lambda () calls)))
      (setf (symbol-function symbol) original))))

(defun %server-driver-test-ticket-key-store-lifecycle
    (provider chain private-key now check-case)
  (labels ((destroyed-error-p (function)
             (handler-case
                 (progn (funcall function) nil)
               (tls13-server-driver-error (condition)
                 (eq (tls13-server-driver-error-reason condition)
                     :ticket-key-store-destroyed))))
           (random-failure-p (function)
             (handler-case
                 (progn (funcall function) nil)
               (tls13-server-driver-error (condition)
                 (eq (tls13-server-driver-error-reason condition)
                     :ticket-key-random-failed))))
           (nonzero-octets-p (bytes)
             (and (cl-tls-kit::%tls13-server-octets-p bytes)
                  (some (function plusp) bytes))))
    (let* ((store
             (make-tls13-server-ticket-key-store
              :random (%server-driver-test-random)
              :ticket-lifetime 1))
           (old-key (cl-tls-kit::tls13-server-ticket-key-store-current store))
           (old-id (cl-tls-kit::%tls13-server-ticket-key-id old-key))
           (lookup-id (copy-seq old-id))
           (old-secret (cl-tls-kit::%tls13-server-ticket-key-secret old-key)))
      (funcall check-case
               (and (nonzero-octets-p old-id)
                    (nonzero-octets-p lookup-id)
                    (nonzero-octets-p old-secret))
               "expiry test retains independent nonzero key ID and secret vectors")
      (rotate-tls13-server-ticket-key-store store :clock (lambda () now))
      (let ((decrypt-until
              (cl-tls-kit::%tls13-server-ticket-key-decrypt-until old-key)))
        (rotate-tls13-server-ticket-key-store
         store
         :clock (lambda ()
                  (+ decrypt-until
                     cl-tls-kit::+tls13-server-unix-time-offset+ 1)))
        (funcall check-case
                 (and (every (function plusp) lookup-id)
                      (null (cl-tls-kit::%tls13-server-find-ticket-key
                             store lookup-id (1+ decrypt-until))))
                 "second rotation prunes the expired key and rejects its independent ID")
        (funcall check-case
                 (and (every (function zerop) old-id)
                      (every (function zerop) old-secret)
                      (not (member old-key
                                   (cl-tls-kit::tls13-server-ticket-key-store-previous
                                    store)
                                   :test #'eq)))
                 "second rotation zeroes expired key vectors before removing the key")))
    (let* ((fail-p nil)
           (random (%server-driver-test-random))
           (store
             (make-tls13-server-ticket-key-store
              :random (lambda (length)
                        (if fail-p
                            (make-array 0 :element-type '(unsigned-byte 8))
                            (funcall random length)))))
           (current-key (cl-tls-kit::tls13-server-ticket-key-store-current store))
           (current-id (cl-tls-kit::%tls13-server-ticket-key-id current-key))
           (current-id-copy (copy-seq current-id))
           (current-secret
             (cl-tls-kit::%tls13-server-ticket-key-secret current-key))
           (current-secret-copy (copy-seq current-secret)))
      (setf fail-p t)
      (funcall check-case
               (random-failure-p
                (lambda ()
                  (rotate-tls13-server-ticket-key-store store
                                                        :clock (lambda () now))))
               "rotation rejects ticket-key random source failure")
      (funcall check-case
               (and (eq current-key
                        (cl-tls-kit::tls13-server-ticket-key-store-current store))
                    (equalp current-id current-id-copy)
                    (equalp current-secret current-secret-copy)
                    (not (member current-key
                                 (cl-tls-kit::tls13-server-ticket-key-store-previous
                                  store)
                                 :test #'eq)))
               "failed rotation preserves the current key without duplicating it"))
    (let* ((store
             (make-tls13-server-ticket-key-store
              :random (%server-driver-test-random)))
           (previous-key (cl-tls-kit::tls13-server-ticket-key-store-current store))
           (previous-id (cl-tls-kit::%tls13-server-ticket-key-id previous-key))
           (previous-secret (cl-tls-kit::%tls13-server-ticket-key-secret previous-key)))
      (rotate-tls13-server-ticket-key-store store :clock (lambda () now))
      (let* ((current-key
               (cl-tls-kit::tls13-server-ticket-key-store-current store))
             (current-id (cl-tls-kit::%tls13-server-ticket-key-id current-key))
             (current-secret (cl-tls-kit::%tls13-server-ticket-key-secret current-key)))
        (funcall check-case
                 (and (nonzero-octets-p previous-id)
                      (nonzero-octets-p previous-secret)
                      (nonzero-octets-p current-id)
                      (nonzero-octets-p current-secret))
                 "destroy test retains nonzero current and previous key vectors")
        (funcall check-case
                 (eq store (destroy-tls13-server-ticket-key-store store))
                 "ticket-key store destroy returns the store")
        (funcall check-case
                 (and (every (function zerop) previous-id)
                      (every (function zerop) previous-secret)
                      (every (function zerop) current-id)
                      (every (function zerop) current-secret)
                      (null (cl-tls-kit::tls13-server-ticket-key-store-current store))
                      (null (cl-tls-kit::tls13-server-ticket-key-store-previous store))
                      (null (cl-tls-kit::tls13-server-ticket-key-store-random store))
                      (cl-tls-kit::tls13-server-ticket-key-store-destroyed-p store))
                 "destroy wipes current and previous keys and clears store references")
        (funcall check-case
                 (eq store (destroy-tls13-server-ticket-key-store store))
                 "ticket-key store destroy is idempotent")
        (funcall check-case
                 (destroyed-error-p
                  (lambda ()
                    (rotate-tls13-server-ticket-key-store
                     store :clock (lambda () now))))
                 "destroyed ticket-key store rejects rotation")
        (funcall check-case
                 (destroyed-error-p
                  (lambda () (cl-tls-kit::%tls13-server-current-ticket-key store)))
                 "destroyed ticket-key store rejects current-key access")
        (funcall check-case
                 (destroyed-error-p
                  (lambda ()
                    (cl-tls-kit::%tls13-server-find-ticket-key
                     store previous-id now)))
                 "destroyed ticket-key store rejects key lookup")
        (funcall check-case
                 (destroyed-error-p
                  (lambda ()
                    (%server-driver-test-server
                     provider chain private-key store (lambda () now))))
                 "server driver rejects a destroyed ticket-key store")))
    (multiple-value-bind (symbol status)
        (find-symbol "DESTROY-TLS13-SERVER-TICKET-KEY-STORE" :cl-tls-kit)
      (funcall check-case
               (and symbol (eq status :external) (fboundp symbol))
               "ticket-key store destroy is exported"))))

(defun run-server-driver-tests ()
  (unless (find-package "CRYPTO-KIT")
    (format t "TLS 1.3 server driver: SKIPPED (cl-crypto-kit unavailable)~%")
    (return-from run-server-driver-tests :skipped))
  (let* ((openssl (or (uiop:getenv "OPENSSL") "openssl"))
         (directory
           (merge-pathnames
            (format nil "cl-tls-kit-server-driver-~D-~D/"
                    (get-universal-time) (random 1000000000))
            (uiop:temporary-directory)))
         (certificate (namestring (merge-pathnames "server.crt" directory)))
         (key-path (namestring (merge-pathnames "server.key" directory)))
         (provider (make-cl-crypto-kit-provider))
         (now (+ (get-universal-time) 60))
         (ticket-key-store (make-tls13-server-ticket-key-store))
         (selected 0)
         (assertions 0)
         (chain nil)
         (private-key nil)
         (anchor nil))
    (ensure-directories-exist directory)
    (unwind-protect
         (progn
           (funcall (symbol-function (find-symbol "%OPENSSL-E2E-CERTIFICATE"
                                                 :cl-tls-kit/test))
                    openssl certificate key-path "server.test" 1 :key-type :ecdsa)
           (setf chain
                 (list (cl-tls-kit:pem-block-der
                        (first (cl-tls-kit:pem-decode
                                (uiop:read-file-string certificate)))))
                 private-key
                 (funcall (symbol-function
                           (find-symbol "%OPENSSL-E2E-ECDSA-PRIVATE-KEY"
                                        :cl-tls-kit/test))
                          openssl key-path)
                 anchor (cl-tls-kit.x509:parse-certificate-der (first chain)))
           (%server-driver-test-with-signature-counter
            (lambda (signature-calls)
              (labels ((check-case (condition message)
                         (incf assertions)
                         (check condition message))
                       (new-server (&key (groups '(#x001d #x0017))
                             (cipher-suites #( #x1301 #x1302 #x1303 #x1304))
                             (max-consecutive-key-updates 32))
                         (%server-driver-test-server
                          provider chain private-key ticket-key-store
                          (lambda () now) :groups groups
                          :cipher-suites cipher-suites
                          :max-consecutive-key-updates max-consecutive-key-updates))
                       (complete-server (limit)
                         (let ((server
                                 (new-server :max-consecutive-key-updates limit)))
                           (setf (cl-tls-kit::tls13-server-driver-state server) :complete
                                 (cl-tls-kit::tls13-server-driver-hash server) :sha256
                                 (cl-tls-kit::tls13-server-driver-client-application-secret
                                  server)
                                 (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 1)
                                 (cl-tls-kit::tls13-server-driver-server-application-secret
                                  server)
                                 (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 2))
                           server)))
                (incf selected)
                (check-case
                 (= (cl-tls-kit::tls13-server-driver-max-consecutive-key-updates
                     (new-server))
                    32)
                 "KeyUpdate consecutive limit defaults to 32")
                (incf selected)
                (check-case
                 (handler-case
                     (progn (new-server :max-consecutive-key-updates -1) nil)
                   (tls13-server-driver-error (condition)
                     (eq (tls13-server-driver-error-reason condition)
                         :invalid-server-driver-configuration)))
                 "negative KeyUpdate consecutive limit is rejected")
                (%server-driver-test-with-key-update-derivation-counter
                 (lambda (derivation-calls)
                   (let ((wire (encode-handshake 24 (make-tls13-key-update 0))))
                     (let ((server (complete-server 0)))
                       (incf selected)
                       (multiple-value-bind (returned events)
                           (tls13-server-driver-step server wire :level :application)
                         (check-case
                          (and (eq returned server)
                               (%server-driver-test-alert-p events 10)
                               (eq (getf (%server-driver-test-event events :send) :level)
                                   :application))
                          "zero KeyUpdate limit rejects the first update with unexpected_message")
                         (check-case
                          (and (zerop (funcall derivation-calls))
                               (= (cl-tls-kit::tls13-server-driver-consecutive-key-updates
                                   server)
                                  1))
                          "over-limit KeyUpdate is counted and rejected before key derivation")))
                     (let ((server (complete-server 1)))
                       (incf selected)
                       (multiple-value-bind (returned events)
                           (tls13-server-driver-step server wire :level :application)
                         (check-case
                          (and (eq returned server)
                               (null (%server-driver-test-event events :alert))
                               (= (cl-tls-kit::tls13-server-driver-consecutive-key-updates
                                   server)
                                  1)
                               (= (funcall derivation-calls) 1))
                          "KeyUpdate exactly at the configured limit is accepted"))
                       (tls13-server-driver-note-application-data-received server)
                       (check-case
                        (zerop (cl-tls-kit::tls13-server-driver-consecutive-key-updates
                                server))
                        "application-data notification resets the consecutive count")
                       (incf selected)
                       (multiple-value-bind (returned events)
                           (tls13-server-driver-step server wire :level :application)
                         (check-case
                          (and (eq returned server)
                               (null (%server-driver-test-event events :alert))
                               (= (cl-tls-kit::tls13-server-driver-consecutive-key-updates
                                   server)
                                  1))
                          "KeyUpdate is accepted again after application-data notification"))
                       (let ((over-limit-server (complete-server 1)))
                         (incf selected)
                         (multiple-value-bind (returned events)
                             (tls13-server-driver-step over-limit-server wire :level :application)
                           (check-case
                            (and (eq returned over-limit-server)
                                 (null (%server-driver-test-event events :alert))
                                 (= (cl-tls-kit::tls13-server-driver-consecutive-key-updates
                                     over-limit-server)
                                    1))
                            "first KeyUpdate reaches the configured limit"))
                         (let ((calls-before (funcall derivation-calls)))
                           (multiple-value-bind (returned events)
                               (tls13-server-driver-step over-limit-server wire :level :application)
                             (check-case
                              (and (eq returned over-limit-server)
                                   (%server-driver-test-alert-p events 10)
                                   (eq (getf (%server-driver-test-event events :send) :level)
                                       :application))
                              "limit plus one KeyUpdate emits fatal unexpected_message")
                             (check-case
                              (= (funcall derivation-calls) calls-before)
                              "limit plus one KeyUpdate is rejected before key derivation"))))))))
                (%server-driver-test-with-key-update-derivation-counter
                 (lambda (derivation-calls)
                   (let* ((server (complete-server 0))
                          (wire (encode-handshake 24 (make-tls13-key-update 1)))
                          (calls-before (funcall derivation-calls)))
                     (incf selected)
                     (multiple-value-bind (returned events)
                         (tls13-server-driver-step server wire :level :application)
                       (check-case
                        (and (eq returned server)
                             (%server-driver-test-alert-p events 10)
                             (eq (getf (%server-driver-test-event events :send) :level)
                                 :application))
                        "over-limit KeyUpdate request=1 emits unexpected_message")
                       (check-case
                        (notany
                         (lambda (event)
                           (let ((wire (getf event :wire)))
                             (and (eq (getf event :type) :send)
                                  (eq (getf event :content-type) :handshake)
                                  (vectorp wire)
                                  (plusp (length wire))
                                  (= (aref wire 0) 24))))
                         events)
                        "over-limit KeyUpdate request=1 sends no response KeyUpdate")
                       (check-case
                        (= (funcall derivation-calls) calls-before)
                        "over-limit KeyUpdate request=1 performs no key derivation")))
                   (let* ((server (complete-server 1))
                          (wire #(24 0 0 1 2))
                          (count-before
                            (cl-tls-kit::tls13-server-driver-consecutive-key-updates
                             server))
                          (calls-before (funcall derivation-calls)))
                     (incf selected)
                     (multiple-value-bind (returned events)
                         (tls13-server-driver-step server wire :level :application)
                       (check-case
                        (and (eq returned server)
                             (%server-driver-test-alert-p events 50))
                        "malformed KeyUpdate emits decode_error")
                       (check-case
                        (and (= (cl-tls-kit::tls13-server-driver-consecutive-key-updates
                                 server)
                                count-before)
                             (= (funcall derivation-calls) calls-before))
                        "malformed KeyUpdate leaves the count unchanged without key derivation")))))
                (let ((client-hello nil)
                      (client-wire nil))
                  (multiple-value-bind (client outgoing)
                      (%server-driver-test-client provider :trust-anchors (list anchor)
                                                  :now now)
                    (multiple-value-bind (wire hello)
                        (%server-driver-test-client-hello client outgoing)
                      (setf client-hello hello
                            client-wire wire))
                    (let* ((marker #(71 82 83 69 67 82 69 84))
                           (marker-text "71 82 83 69 67 82 69 84")
                           (server (new-server))
                           (key (cl-tls-kit::tls13-server-ticket-key-store-current
                                 ticket-key-store))
                           (original-key-secret
                             (cl-tls-kit::%tls13-server-ticket-key-secret key)))
                      (unwind-protect
                           (progn
                             (setf (cl-tls-kit::%tls13-server-ticket-key-secret key)
                                   (copy-seq marker)
                                   (cl-tls-kit::tls13-server-driver-client-handshake-secret
                                    server)
                                   (copy-seq marker)
                                   (cl-tls-kit::tls13-client-driver-handshake-secret client)
                                   (copy-seq marker))
                             (check-case
                              (not (search marker-text (write-to-string server)))
                              "server driver printer hides handshake secrets")
                             (check-case
                              (not (search marker-text
                                           (write-to-string ticket-key-store)))
                              "ticket store printer hides ticket-key secrets")
                             (check-case
                              (not (search marker-text (write-to-string key)))
                              "ticket key printer hides its secret")
                             (check-case
                              (not (search marker-text (write-to-string client)))
                              "client driver printer hides handshake secrets"))
                        (setf (cl-tls-kit::%tls13-server-ticket-key-secret key)
                              original-key-secret)))
                    (let* ((server (new-server))
                           (short-finished
                             (encode-handshake
                              20 (make-tls13-finished
                                  (make-array 31 :element-type '(unsigned-byte 8)
                                              :initial-element 0)))))
                      (setf (cl-tls-kit::tls13-server-driver-state server)
                            :awaiting-client-finished
                            (cl-tls-kit::tls13-server-driver-hash server) :sha256
                            (cl-tls-kit::tls13-server-driver-client-finished-key server)
                            (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 1))
                      (incf selected)
                      (multiple-value-bind (returned events)
                          (tls13-server-driver-step server short-finished :level :handshake)
                        (check-case
                         (and (eq returned server)
                              (%server-driver-test-alert-p events 50))
                         "Finished with verify_data shorter than SHA-256 is rejected")))
                    (let* ((server (new-server))
                           (decoder (find-symbol "DECODE-FINISHED" :cl-tls-kit))
                           (original (symbol-function decoder))
                           (decode-calls 0)
                           (oversized
                             (make-array (+ 5 cl-tls-kit::+tls13-server-max-handshake-size+)
                                         :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
                      (setf (aref oversized 0) 20)
                      (replace oversized
                               (cl-tls-kit::%tls13-server-u24 (- (length oversized) 4))
                               :start1 1)
                      (setf (cl-tls-kit::tls13-server-driver-state server)
                            :awaiting-client-finished
                            (cl-tls-kit::tls13-server-driver-hash server) :sha256
                            (cl-tls-kit::tls13-server-driver-client-finished-key server)
                            (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 1))
                      (incf selected)
                      (unwind-protect
                           (progn
                             (setf (symbol-function decoder)
                                   (lambda (bytes)
                                     (incf decode-calls)
                                     (funcall original bytes)))
                             (multiple-value-bind (returned events)
                                 (tls13-server-driver-step server oversized :level :handshake)
                               (check-case
                                (and (eq returned server)
                                     (%server-driver-test-alert-p events 50))
                                "Finished larger than one MiB is rejected"))
                             (check-case (zerop decode-calls)
                                         "oversized Finished is rejected before decoding"))
                        (setf (symbol-function decoder) original)))
                  (let* ((duplicate-hello
                           (%server-driver-test-duplicate-extension-wire
                            client-wire 13))
                         (no-group-hello
                           (%server-driver-test-rewrite-client-hello
                            client-hello 10 (%server-driver-test-u16-list '(#x0019))))
                         (no-group-wire (encode-handshake 1 no-group-hello))
                         (no-signature-hello
                           (%server-driver-test-rewrite-client-hello
                            client-hello 13 (%server-driver-test-u16-list '(#x0804)))))
                    (let* ((decoded (decode-handshake no-group-wire))
                           (versions
                             (find 43 (tls13-client-hello-extensions decoded)
                                   :key #'tls-extension-type))
                           (groups
                             (find 10 (tls13-client-hello-extensions decoded)
                                   :key #'tls-extension-type)))
                      (check-case
                       (= (tls13-client-hello-legacy-version decoded) #x0303)
                       "unsupported-group fixture retains TLS 1.3 legacy_version")
                      (check-case (equalp (tls-extension-data versions) #(2 3 4))
                                  "unsupported-group fixture retains TLS 1.3 supported_versions")
                      (check-case
                       (equalp (tls-extension-data groups)
                               (%server-driver-test-u16-list '(#x0019)))
                       "unsupported-group fixture contains only group 0x0019"))
                    (let ((probe (new-server)))
                      (handler-case
                          (let* ((hello
                                   (cl-tls-kit::%tls13-server-parse-client-hello
                                    no-group-wire))
                                 (fields
                                   (cl-tls-kit::%tls13-server-clienthello-fields
                                    hello)))
                            (cl-tls-kit::%tls13-server-select-group
                             probe (getf fields :groups))
                            (check-case nil
                                        "unsupported-group selection should fail"))
                        (cl-tls-kit:tls13-server-driver-error (condition)
                          (check-case
                           (and (eq
                                 (cl-tls-kit:tls13-server-driver-error-reason condition)
                                 :no-common-supported-group)
                                (= (cl-tls-kit::%tls13-server-driver-error-alert
                                    condition)
                                   40))
                           (format nil "unsupported-group selection has reason ~S and alert ~D"
                                   (cl-tls-kit:tls13-server-driver-error-reason condition)
                                   (cl-tls-kit::%tls13-server-driver-error-alert
                                    condition))))))
                    (incf selected)
                    (%server-driver-test-assert-client-hello-rejected
                     "duplicate extension" (new-server) duplicate-hello 47 #'check-case)
                    (incf selected)
                    (%server-driver-test-assert-client-hello-rejected
                     "unsupported group" (new-server)
                     no-group-wire 40 #'check-case)
                    (incf selected)
                    (%server-driver-test-assert-client-hello-rejected
                     "unsupported signature scheme" (new-server)
                     (encode-handshake 1 no-signature-hello) 40 #'check-case)
                    (progn
                     (incf selected)
                     (%server-driver-test-assert-client-hello-rejected
                      "malformed supported_groups" (new-server)
                      (encode-handshake
                       1 (%server-driver-test-rewrite-client-hello
                          client-hello 10 #(0 3 #x00 #x1d #x00)))
                      50 #'check-case)
                     (incf selected)
                     (%server-driver-test-assert-client-hello-rejected
                      "missing key_share" (new-server)
                      (encode-handshake 1
                                        (%server-driver-test-rewrite-client-hello client-hello 51 :remove))
                      109 #'check-case)
                     (incf selected)
                     (%server-driver-test-assert-client-hello-rejected
                      "missing signature_algorithms" (new-server)
                      (encode-handshake 1
                                        (%server-driver-test-rewrite-client-hello client-hello 13 :remove))
                      109 #'check-case)
                     (let ((finished-wire
                             (encode-handshake
                              20 (make-tls13-finished
                                  (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 0))))
                           (client-hello-wire (encode-handshake 1 client-hello))
                           (malformed-wire
                             (make-array 3 :element-type '(unsigned-byte 8)
                                         :initial-contents '(20 0 0))))
                       (flet ((assert-state-failure (name server wire level alert)
                                (let* ((state (cl-tls-kit::tls13-server-driver-state server))
                                       (transcript
                                         (make-array 2 :element-type '(unsigned-byte 8)
                                                     :initial-contents '(8 9)))
                                       (secret
                                         (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 7)))
                                  (setf (cl-tls-kit::tls13-server-driver-transcript server) transcript)
                                  (case state
                                    (:awaiting-client-hello
                                     (setf (cl-tls-kit::tls13-server-driver-private-key-share
                                            server)
                                           secret))
                                    (:awaiting-second-client-hello
                                     (setf (cl-tls-kit::tls13-server-driver-private-key-share
                                            server)
                                           secret
                                           (cl-tls-kit::tls13-server-driver-cookie server)
                                           #(1)))
                                    (:awaiting-client-finished
                                     (setf (cl-tls-kit::tls13-server-driver-hash server)
                                           :sha256
                                           (cl-tls-kit::tls13-server-driver-client-finished-key
                                            server)
                                           secret))
                                    (:complete
                                     (setf (cl-tls-kit::tls13-server-driver-client-application-secret
                                            server)
                                           secret)))
                                  (multiple-value-bind (returned events)
                                      (tls13-server-driver-step server wire :level level)
                                    (check-case
                                     (and (eq returned server)
                                          (%server-driver-test-alert-p events alert))
                                     (format nil "~A emits fatal alert ~D" name alert))
                                    (check-case
                                     (eq (getf (%server-driver-test-event events :send) :level)
                                         level)
                                     (format nil "~A sends its alert at ~S level" name level))
                                    (check-case
                                     (and (eq (cl-tls-kit::tls13-server-driver-state server) :failed)
                                          (zerop (length (cl-tls-kit::tls13-server-driver-transcript server)))
                                          (every #'zerop transcript)
                                          (every #'zerop secret)
                                          (null (cl-tls-kit::tls13-server-driver-provider server))
                                          (null
                                           (case state
                                             ((:awaiting-client-hello
                                               :awaiting-second-client-hello)
                                              (cl-tls-kit::tls13-server-driver-private-key-share
                                               server))
                                             (:awaiting-client-finished
                                              (cl-tls-kit::tls13-server-driver-client-finished-key
                                               server))
                                             (:complete
                                              (cl-tls-kit::tls13-server-driver-client-application-secret
                                               server))))
                                          (null
                                           (cl-tls-kit::tls13-server-driver-initial-client-hello server))
                                          (null (cl-tls-kit::tls13-server-driver-cookie server)))
                                     (format nil "~A terminalizes the driver and clears secrets"
                                             name)))))) (incf selected) (assert-state-failure
                          "initial state rejects Finished" (new-server)
                          finished-wire :initial 10) (incf selected) (let ((server (new-server)))
                           (setf (cl-tls-kit::tls13-server-driver-state server)
                                 :awaiting-second-client-hello)
                           (assert-state-failure
                            "second ClientHello state rejects Finished" server
                            finished-wire :initial 10)) (incf selected) (progn
                           (let ((server (new-server)))
                             (setf (cl-tls-kit::tls13-server-driver-state server)
                                   :awaiting-client-finished)
                             (assert-state-failure
                              "Finished state rejects ClientHello" server
                              client-hello-wire :handshake 10))
                           (incf selected)
                           (let ((server (new-server)))
                             (setf (cl-tls-kit::tls13-server-driver-state server)
                                   :awaiting-client-finished)
                             (assert-state-failure
                              "Finished state rejects KeyUpdate" server
                              (encode-handshake 24 (make-tls13-key-update 0))
                              :handshake 10))) (incf selected) (let ((server (new-server)))
                           (setf (cl-tls-kit::tls13-server-driver-state server) :complete)
                           (assert-state-failure
                            "complete state rejects ClientHello" server
                            client-hello-wire :application 10)) (incf selected) (assert-state-failure
                          "short handshake frame is a decode_error" (new-server)
                          malformed-wire :initial 50)) (check-case (zerop (funcall signature-calls))
                                 "doomed ClientHellos invoke no signing operation")))))
                (let ((values (make-array 32767)))
                  (dotimes (index (1- (length values)))
                    (setf (aref values index) index))
                  (setf (aref values (1- (length values)))
                        (aref values (- (length values) 2)))
                  (incf selected)
                  (check-case
                   (not (cl-tls-kit::%tls13-server-unique-p (coerce values 'list)))
                   "long negotiation vector ending in a duplicate is rejected"))
                (multiple-value-bind (server client alpn ticket hrr-count
                                      client-cv-count events outgoing)
                    (%server-driver-test-memory-handshake
                     provider chain private-key anchor ticket-key-store now)
                  (declare (ignore events outgoing))
                  (check-case (eq (cl-tls-kit::tls13-client-driver-state client) :connected)
                              "memory client completes a full TLS 1.3 handshake")
                  (check-case (eq (cl-tls-kit::tls13-server-driver-state server) :complete)
                              "memory server completes the client Finished")
                  (check-case (equal alpn "http/1.1")
                              "server selects its preferred offered ALPN")
                  (check-case (equal (cl-tls-kit:tls13-client-driver-negotiated-alpn client)
                                     "http/1.1")
                              "client validates the EncryptedExtensions ALPN")
                  (check-case (= client-cv-count 1)
                              "cl-tls-kit client processes CertificateVerify")
                  (check-case (and ticket (getf ticket :identity)
                                   (plusp (length (getf ticket :identity))))
                              "server issues a resumable NewSessionTicket")
                  (check-case (zerop hrr-count)
                              "matching initial key share avoids HelloRetryRequest")
                  (check-case (= (funcall signature-calls) 1)
                              "a valid full handshake signs CertificateVerify once")
                  (let* ((ticket-fields
                           (cl-tls-kit::%tls13-server-open-ticket
                            server (getf ticket :identity)))
                         (resumption-client nil)
                         (resumption-wire nil)
                         (resume-server (new-server)))
                    (multiple-value-setq (resumption-client resumption-wire)
                      (%server-driver-test-psk-client-hello
                       provider ticket-fields (getf ticket :identity)
                       (getf ticket-fields :age-add) now))
                    (incf selected)
                    (let ((before (%server-driver-test-state-snapshot resume-server)))
                      (multiple-value-bind (returned events)
                          (tls13-server-driver-step
                           resume-server resumption-wire :level :initial)
                        (setf resume-server returned)
                        (%server-driver-test-complete-resumed-handshake
                         provider resume-server resumption-client resumption-wire
                         ticket-fields events #'check-case)
                        (progn
                          (check-case (= (funcall signature-calls) 1)
                                      "PSK resumption skips CertificateVerify signing")
                          (let ((missing-modes-server (new-server)))
                            (multiple-value-bind (ignored missing-modes-wire)
                                (%server-driver-test-psk-client-hello
                                 provider ticket-fields (getf ticket :identity)
                                 (getf ticket-fields :age-add) now
                                 :remove-psk-modes-p t)
                              (declare (ignore ignored))
                              (incf selected)
                              (%server-driver-test-assert-client-hello-rejected
                               "PSK missing psk_key_exchange_modes"
                               missing-modes-server missing-modes-wire 109 #'check-case)
                              (check-case (= (funcall signature-calls) 1)
                                          "PSK ClientHello without modes is rejected before signing"))))
                        (check-case (not (equalp before
                                                 (%server-driver-test-state-snapshot
                                                  resume-server)))
                                    "valid PSK ClientHello advances server state")))
                    (progn
                      (let ((hash-mismatch-server
                              (new-server :cipher-suites #( #x1302))))
                        (multiple-value-bind (ignored hash-mismatch-wire)
                            (%server-driver-test-psk-client-hello
                             provider ticket-fields (getf ticket :identity)
                             (getf ticket-fields :age-add) now
                             :cipher-suites #( #x1302))
                          (declare (ignore ignored))
                          (incf selected)
                          (multiple-value-bind (returned events)
                              (tls13-server-driver-step
                               hash-mismatch-server hash-mismatch-wire :level :initial)
                            (setf hash-mismatch-server returned)
                            (let ((sent-types
                                    (mapcar (lambda (event)
                                              (aref (getf event :wire) 0))
                                            (%server-driver-test-events events :send))))
                              (check-case
                               (and (null (%server-driver-test-event events :alert))
                                    (eq (cl-tls-kit::tls13-server-driver-state
                                         hash-mismatch-server)
                                        :awaiting-client-finished)
                                    (not (cl-tls-kit::tls13-server-driver-resumed-p
                                          hash-mismatch-server))
                                    (= (cl-tls-kit::tls13-server-driver-selected-suite
                                        hash-mismatch-server)
                                       #x1302))
                               "PSK with a different suite hash falls back to a full handshake")
                              (check-case (member 11 sent-types)
                                          "hash-mismatched PSK fallback sends Certificate")
                              (check-case (member 15 sent-types)
                                          "hash-mismatched PSK fallback sends CertificateVerify")
                              (check-case (= (funcall signature-calls) 2)
                                          "hash-mismatched PSK fallback signs once")))))
                      (let ((bad-binder-server (new-server)))
                        (multiple-value-bind (ignored bad-binder-wire)
                            (%server-driver-test-psk-client-hello
                             provider ticket-fields (getf ticket :identity)
                             (getf ticket-fields :age-add) now :corrupt-binder-p t)
                          (declare (ignore ignored))
                          (incf selected)
                          (%server-driver-test-assert-client-hello-rejected
                           "bad PSK binder" bad-binder-server bad-binder-wire 51 #'check-case)
                          (check-case (= (funcall signature-calls) 2)
                                      "invalid PSK binder is rejected before signing"))))
                    (let* ((expired-now (+ now (getf ticket-fields :lifetime) 1))
                           (expired-server
                             (%server-driver-test-server
                              provider chain private-key ticket-key-store
                              (lambda () expired-now)))
                           (expired-age
                             (+ (getf ticket-fields :age-add)
                                (* 1000 (- expired-now
                                           (getf ticket-fields :issued))))))
                      (multiple-value-bind (ignored expired-wire)
                          (%server-driver-test-psk-client-hello
                           provider ticket-fields (getf ticket :identity)
                           expired-age expired-now)
                        (declare (ignore ignored))
                        (incf selected)
                        (%server-driver-test-assert-client-hello-rejected
                         "expired PSK ticket" expired-server expired-wire 47 #'check-case)
                        (check-case (= (funcall signature-calls) 2)
                                    "expired ticket is rejected before signing")))
                    (let* ((unknown-identity (copy-seq (getf ticket :identity)))
                           (unknown-server (new-server)))
                      (setf (aref unknown-identity 0)
                            (logxor (aref unknown-identity 0) 1))
                      (multiple-value-bind (ignored unknown-wire)
                          (%server-driver-test-psk-client-hello
                           provider ticket-fields unknown-identity
                           (getf ticket-fields :age-add) now)
                        (declare (ignore ignored))
                        (incf selected)
                        (multiple-value-bind (returned events)
                            (tls13-server-driver-step
                             unknown-server unknown-wire :level :initial)
                          (setf unknown-server returned)
                          (let ((sent-types
                                  (mapcar (lambda (event)
                                            (aref (getf event :wire) 0))
                                          (%server-driver-test-events events :send))))
                            (check-case (and (null (%server-driver-test-event events :alert))
                                             (member 11 sent-types)
                                             (member 15 sent-types))
                                        "unknown PSK identity falls back to certificate authentication"))
                          (check-case
                           (and (eq (cl-tls-kit::tls13-server-driver-state unknown-server)
                                    :awaiting-client-finished)
                                (not (cl-tls-kit::tls13-server-driver-resumed-p
                                      unknown-server)))
                           "unknown PSK identity begins a full handshake")
                          (check-case (= (funcall signature-calls) 3)
                                      "unknown PSK fallback signs CertificateVerify once"))))))
                (incf selected)
                (multiple-value-bind (server client alpn ticket hrr-count
                                      client-cv-count events outgoing)
                    (%server-driver-test-memory-handshake
                     provider chain private-key anchor ticket-key-store now
                     :groups '(#x0017))
                  (declare (ignore alpn ticket events outgoing))
                  (check-case (= hrr-count 1)
                              "server requests the mutually supported P-256 share")
                  (check-case (eq (cl-tls-kit::tls13-client-driver-state client) :connected)
                              "memory client completes a HelloRetryRequest handshake")
                  (check-case (= client-cv-count 1)
                              "client verifies CertificateVerify after HelloRetryRequest")
                  (check-case
                   (and (null (cl-tls-kit::tls13-server-driver-client-handshake-secret
                               server))
                        (null (cl-tls-kit::tls13-server-driver-server-handshake-secret
                               server))
                        (null (cl-tls-kit::tls13-server-driver-client-finished-key server))
                        (null (cl-tls-kit::tls13-server-driver-master-secret server))
                        (null (cl-tls-kit::tls13-server-driver-resumption-master-secret
                               server)))
                   "server clears transient secrets after client Finished")
                  (check-case (= (funcall signature-calls) 4)
                              "HelloRetryRequest full handshake signs once"))
                (progn
                  (incf selected)
                  (%server-driver-test-client-server-resumption-roundtrip
                   provider chain private-key anchor ticket-key-store now (function check-case))
                  (check-case (= (funcall signature-calls) 5)
                              "client and server drivers resume without another signature")
                  (incf selected)
                  (%server-driver-test-client-server-resumption-roundtrip
                   provider chain private-key anchor ticket-key-store now (function check-case)
                   :suite #x1302)
                  (check-case (= (funcall signature-calls) 6)
                              "SHA-384 client and server drivers resume without another signature")
                  (incf selected)
                  (%server-driver-test-client-server-resumption-roundtrip
                   provider chain private-key anchor ticket-key-store now (function check-case)
                   :suite #x1302 :hello-retry-p t
                   :client-cipher-suites #( #x1301 #x1302))
                  (check-case (= (funcall signature-calls) 7)
                              "SHA-384 HelloRetryRequest resumption signs only the full handshake")
                  (check-case (plusp selected)
                              "server driver selected nonzero test cases"))
                (progn
  (incf selected)
  (let ((quic-assertions 0)
        (server-parameters
          (make-array 6 :element-type '(unsigned-byte 8)
                        :initial-contents '(9 0 17 128 255 54)))
        (client-parameters
          (make-array 5 :element-type '(unsigned-byte 8)
                        :initial-contents '(3 0 255 17 128))))
    (labels ((check-quic-case (condition message)
               (incf quic-assertions)
               (check-case condition
                           (format nil "QUIC transport parameter: ~A" message)))
             (wire-event (events handshake-type level)
               (find-if
                (lambda (event)
                  (let ((wire (getf event :wire)))
                    (and (eq (getf event :type) :send)
                         (eq (getf event :level) level)
                         (eq (getf event :content-type) :handshake)
                         (vectorp wire) (plusp (length wire))
                         (= (aref wire 0) handshake-type))))
                events))
             (client-parameter-data (wire)
               (let* ((hello (decode-handshake wire))
                      (extension
                        (find #x0039 (tls13-client-hello-extensions hello)
                              :key #'tls-extension-type)))
                 (and extension (tls-extension-data extension))))
             (peer-parameter-events (events)
               (remove-if-not
                (lambda (event)
                  (and (consp event)
                       (eq (first event) :peer-quic-transport-parameters)))
                events)))
      (multiple-value-bind (server client alpn ticket hrr-count client-cv-count
                            events outgoing client-hello-wires)
          (%server-driver-test-memory-handshake
           provider chain private-key anchor ticket-key-store now
           :groups '(#x0017)
           :quic-transport-parameters server-parameters
           :client-quic-transport-parameters client-parameters)
        (declare (ignore outgoing))
        (let* ((ee-event (wire-event events 8 :handshake))
               (ee-message (and ee-event
                                (decode-handshake (getf ee-event :wire))))
               (server-extension
                 (and ee-message
                      (find #x0039
                            (cl-tls-kit::tls13-encrypted-extensions-extensions
                             ee-message)
                            :key #'tls-extension-type)))
               (ticket-wire-event (wire-event events 4 :application))
               (ticket-message (and ticket-wire-event
                                    (decode-handshake
                                     (getf ticket-wire-event :wire))))
               (peer-events (peer-parameter-events events))
               (handshake-complete
                 (%server-driver-test-event events :handshake-complete)))
          (check-quic-case (= hrr-count 1)
                           "direct client/server handshake exercises HelloRetryRequest")
          (check-quic-case (and (equal alpn "http/1.1")
                                (equal
                                 (cl-tls-kit:tls13-client-driver-negotiated-alpn client)
                                 "http/1.1"))
                           "ALPN remains negotiated through the QUIC handshake")
          (check-quic-case (= client-cv-count 1)
                           "client verifies CertificateVerify in the QUIC handshake")
          (progn
            (check-quic-case
             (and (eq (cl-tls-kit::tls13-client-driver-state client) :connected)
                  (eq (cl-tls-kit::tls13-server-driver-state server) :complete)
                  handshake-complete)
             "server verifies the real client Finished with QUIC parameters in the transcript")
            (check-quic-case
             (let ((peer-index
                     (and peer-events
                          (position (car (last peer-events)) events)))
                   (complete-index
                     (and handshake-complete
                          (position handshake-complete events))))
               (and peer-index complete-index (< peer-index complete-index)))
             "last peer QUIC parameter event precedes handshake completion"))
          (check-quic-case
           (and (= (length client-hello-wires) 2)
                (equalp (client-parameter-data (first client-hello-wires))
                        client-parameters))
           "ClientHello1 carries the exact peer QUIC parameter bytes")
          (check-quic-case
           (and (= (length client-hello-wires) 2)
                (equalp (client-parameter-data (second client-hello-wires))
                        (client-parameter-data (first client-hello-wires))))
           "HelloRetryRequest ClientHello2 preserves ClientHello1 QUIC parameter bytes")
          (check-quic-case
           (and (= (length peer-events) 2)
                (every (lambda (event)
                         (equalp event
                                 (list :peer-quic-transport-parameters
                                       client-parameters)))
                       peer-events))
           "each accepted ClientHello emits the exact peer QUIC parameter event")
          (check-quic-case
           (and server-extension
                (equalp (tls-extension-data server-extension) server-parameters))
           "EncryptedExtensions contains the exact opaque server QUIC parameter bytes")
          (check-quic-case
           (and ticket (getf ticket :identity) ticket-message
                (null (find 42
                            (cl-tls-kit::tls13-new-session-ticket-extensions
                             ticket-message)
                            :key #'tls-extension-type)))
           "NewSessionTicket is issued after Finished without early_data")
          (let ((duplicate-wire
                  (%server-driver-test-duplicate-extension-wire
                   (first client-hello-wires) #x0039)))
            (incf selected)
            (%server-driver-test-assert-client-hello-rejected
             "duplicate QUIC transport-parameters extension"
             (%server-driver-test-server provider chain private-key ticket-key-store
                                         (lambda () now)
                                         :quic-transport-parameters server-parameters)
             duplicate-wire 47 #'check-quic-case))))
      (multiple-value-bind (server client alpn ticket hrr-count client-cv-count
                            events outgoing client-hello-wires)
          (%server-driver-test-memory-handshake
           provider chain private-key anchor ticket-key-store now)
        (declare (ignore alpn ticket hrr-count client-cv-count outgoing
                         client-hello-wires))
        (let* ((ee-event (wire-event events 8 :handshake))
               (ee-message (and ee-event
                                (decode-handshake (getf ee-event :wire))))
               (server-extension
                 (and ee-message
                      (find #x0039
                            (cl-tls-kit::tls13-encrypted-extensions-extensions
                             ee-message)
                            :key #'tls-extension-type)))
               (peer-events (peer-parameter-events events)))
          (check-quic-case
           (and (eq (cl-tls-kit::tls13-client-driver-state client) :connected)
                (eq (cl-tls-kit::tls13-server-driver-state server) :complete))
           "omitted server keyword retains the TLS-over-TCP handshake")
          (check-quic-case (null server-extension)
                           "omitted server keyword sends no QUIC EncryptedExtensions")
          (check-quic-case (null peer-events)
                           "omitted server keyword emits no peer QUIC parameter event")
          (let ((assertions-before quic-assertions))
            (multiple-value-bind (client outgoing)
                (%server-driver-test-client
                 provider :trust-anchors (list anchor) :now now)
              (multiple-value-bind (wire)
                  (%server-driver-test-client-hello client outgoing)
                (let* ((tcp-wire
                         (encode-handshake
                          1 (%server-driver-test-rewrite-client-hello
                             (decode-handshake wire) #x0039 client-parameters)))
                       (tcp-server
                         (%server-driver-test-server
                          provider chain private-key ticket-key-store
                          (lambda () now))))
                  (incf selected)
                  (let ((events
                          (%server-driver-test-assert-client-hello-rejected
                           "QUIC transport parameters received on TCP"
                           tcp-server tcp-wire 110 (function check-quic-case))))
                    (check-quic-case
                     (null (peer-parameter-events events))
                     "TCP rejection emits no peer QUIC parameter event")))))
            (format t "TLS 1.3 server rejects QUIC transport parameters over TCP: assertions: ~D~%"
                    (- quic-assertions assertions-before)))))
      (multiple-value-bind (client outgoing)
          (%server-driver-test-client provider :trust-anchors (list anchor) :now now)
        (multiple-value-bind (wire hello)
            (%server-driver-test-client-hello client outgoing)
          (declare (ignore hello))
          (incf selected)
          (%server-driver-test-assert-client-hello-rejected
           "QUIC parameters without ClientHello extension"
           (%server-driver-test-server provider chain private-key ticket-key-store
                                       (lambda () now)
                                       :quic-transport-parameters server-parameters)
           wire 109 #'check-quic-case)))
      (let* ((invalid #(71 82 83 69 67 82 69 84))
             (marker-text "71 82 83 69 67 82 69 84")
             (condition
               (handler-case
                   (progn
                     (%server-driver-test-server
                      provider chain private-key ticket-key-store (lambda () now)
                      :quic-transport-parameters invalid)
                     nil)
                 (tls13-server-driver-error (condition) condition))))
        (incf selected)
        (check-quic-case
         (and condition
              (eq (tls13-server-driver-error-reason condition)
                  :invalid-server-driver-configuration)
              (not (search marker-text (write-to-string condition))))
         "constructor rejects invalid bytes without printing input bytes"))
      (let* ((marker #(71 82 83 69 67 82 69 84))
             (marker-text "71 82 83 69 67 82 69 84")
             (oversized
               (make-array #x10000 :element-type '(unsigned-byte 8)
                                    :initial-element 200)))
        (replace oversized marker)
        (let ((condition
                (handler-case
                    (progn
                      (%server-driver-test-server
                       provider chain private-key ticket-key-store (lambda () now)
                       :quic-transport-parameters oversized)
                      nil)
                  (tls13-server-driver-error (condition) condition))))
          (incf selected)
          (check-quic-case
           (and condition
                (eq (tls13-server-driver-error-reason condition)
                    :invalid-server-driver-configuration)
                (not (search marker-text (write-to-string condition))))
           "constructor rejects oversized bytes without printing input bytes")))
      (flet
          ((check-changed-second-client-hello ()
             (let ((first-parameters #(3 0 255 17 128))
                   (changed-parameters #(3 0 255 17 129)))
               (multiple-value-bind (client outgoing)
                   (%server-driver-test-client
                    provider :groups '(#x001d #x0017)
                    :trust-anchors (list anchor) :now now)
                 (multiple-value-bind (ignored-wire hello)
                     (%server-driver-test-client-hello client outgoing)
                   (declare (ignore ignored-wire))
                   (let* ((client-hello
                            (%server-driver-test-rewrite-client-hello
                             hello #x0039 first-parameters))
                          (wire (encode-handshake 1 client-hello))
                          (server
                            (%server-driver-test-server
                             provider chain private-key ticket-key-store
                             (lambda () now) :groups (list #x0017)
                             :quic-transport-parameters server-parameters)))
                     (setf (cl-tls-kit::tls13-client-driver-client-hello client)
                           client-hello
                           (cl-tls-kit::tls13-client-driver-transcript client)
                           (copy-seq wire))
                     (multiple-value-bind (returned events)
                         (tls13-server-driver-step server wire :level :initial)
                       (setf server returned)
                       (let ((hrr-event
                               (find-if
                                (lambda (event)
                                  (and (eq (getf event :type) :send)
                                       (eq (getf event :content-type) :handshake)
                                       (typep (decode-handshake (getf event :wire))
                                              'tls13-hello-retry-request)))
                                events)))
                         (check-quic-case
                          (and (eq returned server) hrr-event)
                          "ClientHello with QUIC parameters receives HelloRetryRequest")
                         (tls13-client-driver-step client (getf hrr-event :wire))
                         (let* ((second-wire (pop (car outgoing)))
                                (second-hello (decode-handshake second-wire))
                                (changed-hello
                                  (%server-driver-test-rewrite-client-hello
                                   second-hello #x0039 changed-parameters))
                                (changed-wire (encode-handshake 1 changed-hello)))
                           (%server-driver-test-assert-client-hello-rejected
                            "changed QUIC parameters in second ClientHello"
                            server changed-wire 47 #'check-quic-case)))))))))
           (check-explicit-nil-quic-parameters ()
             (let ((condition
                     (handler-case
                         (progn
                           (%server-driver-test-server
                            provider chain private-key ticket-key-store (lambda () now)
                            :quic-transport-parameters nil)
                           nil)
                       (tls13-server-driver-error (condition) condition))))
               (check-quic-case
                (and condition
                     (eq (tls13-server-driver-error-reason condition)
                         :invalid-server-driver-configuration))
                "constructor rejects explicitly supplied NIL QUIC parameters")))
           (check-encrypted-extensions-size-limit ()
             (let* ((marker #(71 82 83 69 67 82 69 84))
                    (marker-text "71 82 83 69 67 82 69 84")
                    (server-parameters
                      (make-array #xffff :element-type '(unsigned-byte 8)
                                         :initial-element 200)))
               (replace server-parameters marker)
               (multiple-value-bind (client outgoing)
                   (%server-driver-test-client
                    provider :trust-anchors (list anchor) :now now)
                 (multiple-value-bind (ignored-wire hello)
                     (%server-driver-test-client-hello client outgoing)
                   (declare (ignore ignored-wire))
                   (let* ((wire
                            (encode-handshake
                             1 (%server-driver-test-rewrite-client-hello
                                hello #x0039 #(3 1 4))))
                          (server
                            (%server-driver-test-server
                             provider chain private-key ticket-key-store
                             (lambda () now)
                             :quic-transport-parameters server-parameters))
                          (before (%server-driver-test-state-snapshot server)))
                     (multiple-value-bind (returned events)
                         (tls13-server-driver-step server wire :level :initial)
                       (check-quic-case
                        (and (eq returned server)
                             (%server-driver-test-alert-p events 80)
                             (eq (getf (%server-driver-test-event events :send) :level)
                                 :initial)
                             (and (not (equalp before (%server-driver-test-state-snapshot server)))
                                  (eq (cl-tls-kit::tls13-server-driver-state server) :failed)
                                  (zerop (length (cl-tls-kit::tls13-server-driver-transcript server)))))
                        "u16-sized QUIC payload with oversized EncryptedExtensions fails closed")
                       (check-quic-case
                        (not (search marker-text (write-to-string events)))
                        "oversized EncryptedExtensions output does not print parameter bytes"))))))))
        (incf selected)
        (check-changed-second-client-hello)
        (incf selected)
        (check-explicit-nil-quic-parameters)
        (incf selected)
        (check-encrypted-extensions-size-limit)
        (check-case (plusp quic-assertions)
                    "QUIC transport-parameter test group ran nonzero assertions"))
      (format t "TLS 1.3 server driver QUIC transport parameters: assertions: ~D~%"
              quic-assertions)))
  (incf selected)
  (let* ((server (new-server))
       (client-handshake-secret
         (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
       (server-handshake-secret
         (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
       (client-finished-key
         (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
       (master-secret
         (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
       (resumption-master-secret
         (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
       (client-application-secret
         (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
       (server-application-secret
         (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
       (transcript
         (make-array 2 :element-type '(unsigned-byte 8)
                     :initial-contents #(8 9)))
       (flight-prefix
         (make-array 2 :element-type '(unsigned-byte 8)
                     :initial-contents #(10 11)))
       (key-share (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element 12))
       (identity-private-key
         (cl-tls-kit::tls13-server-driver-private-key server))
       (identity-private-key-bytes
         (and (cl-tls-kit::%tls13-server-octets-p identity-private-key)
              (copy-seq identity-private-key)))
       (finished
         (encode-handshake
          20 (make-tls13-finished
              (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element 0)))))
  (check-case
   (= (length (remove-duplicates
               (list client-handshake-secret server-handshake-secret
                     client-finished-key master-secret resumption-master-secret
                     client-application-secret server-application-secret)
               :test #'eq))
      7)
   "server cleanup test uses independent secret vectors")
  (setf (cl-tls-kit::tls13-server-driver-state server) :awaiting-client-finished
        (cl-tls-kit::tls13-server-driver-hash server) :sha256
        (cl-tls-kit::tls13-server-driver-client-handshake-secret server)
        client-handshake-secret
        (cl-tls-kit::tls13-server-driver-server-handshake-secret server)
        server-handshake-secret
        (cl-tls-kit::tls13-server-driver-client-finished-key server)
        client-finished-key
        (cl-tls-kit::tls13-server-driver-master-secret server) master-secret
        (cl-tls-kit::tls13-server-driver-resumption-master-secret server)
        resumption-master-secret
        (cl-tls-kit::tls13-server-driver-client-application-secret server)
        client-application-secret
        (cl-tls-kit::tls13-server-driver-server-application-secret server)
        server-application-secret
        (cl-tls-kit::tls13-server-driver-transcript server) transcript
        (cl-tls-kit::tls13-server-driver-server-flight-prefix server) flight-prefix
        (cl-tls-kit::tls13-server-driver-private-key-share server) key-share
        (cl-tls-kit::tls13-server-driver-initial-client-hello server)
        :client-hello
        (cl-tls-kit::tls13-server-driver-cookie server) :cookie
        (cl-tls-kit::tls13-server-driver-sni-callback server)
        (lambda (hostname) (declare (ignore hostname)))
        (cl-tls-kit::tls13-server-driver-clock server)
        (lambda () now))
  (check-case (and identity-private-key (eq identity-private-key private-key))
              "server driver starts with the shared identity private key")
  (multiple-value-bind (returned events)
      (tls13-server-driver-step server finished :level :handshake)
    (check-case
     (and (eq returned server)
          (%server-driver-test-alert-p events 51)
          (eq (getf (%server-driver-test-event events :send) :level) :handshake)
          (eq (cl-tls-kit::tls13-server-driver-state server) :failed)
          (every #'zerop client-handshake-secret)
          (every #'zerop server-handshake-secret)
          (every #'zerop client-finished-key)
          (every #'zerop master-secret)
          (every #'zerop resumption-master-secret)
          (every #'zerop client-application-secret)
          (every #'zerop server-application-secret)
          (every #'zerop transcript)
          (every #'zerop flight-prefix)
          (every #'zerop key-share)
          (every #'null
                 (list
                   (cl-tls-kit::tls13-server-driver-client-handshake-secret server)
                   (cl-tls-kit::tls13-server-driver-server-handshake-secret server)
                   (cl-tls-kit::tls13-server-driver-client-finished-key server)
                   (cl-tls-kit::tls13-server-driver-master-secret server)
                   (cl-tls-kit::tls13-server-driver-resumption-master-secret server)
                   (cl-tls-kit::tls13-server-driver-client-application-secret server)
                   (cl-tls-kit::tls13-server-driver-server-application-secret server)
                   (cl-tls-kit::tls13-server-driver-server-flight-prefix server)
                   (cl-tls-kit::tls13-server-driver-private-key-share server)
                   (cl-tls-kit::tls13-server-driver-provider server)
                   (cl-tls-kit::tls13-server-driver-sni-callback server)
                   (cl-tls-kit::tls13-server-driver-clock server)
                   (cl-tls-kit::tls13-server-driver-random server)
                   (cl-tls-kit::tls13-server-driver-key-exchange server)
                   (cl-tls-kit::tls13-server-driver-private-key server)
                   (cl-tls-kit::tls13-server-driver-initial-client-hello server)
                   (cl-tls-kit::tls13-server-driver-cookie server)
                   (cl-tls-kit::tls13-server-driver-ticket-key-store server)))
          (eq identity-private-key private-key)
          (or (null identity-private-key-bytes)
              (equalp identity-private-key-bytes identity-private-key)))
     "invalid Client Finished terminalizes the server, clears secrets and drops callback and key references"))
  (multiple-value-bind (returned events)
      (tls13-server-driver-step server finished :level :handshake)
    (check-case
     (and (eq returned server)
          (%server-driver-test-alert-p events 10)
          (eq (cl-tls-kit::tls13-server-driver-state server) :failed)
          (null (cl-tls-kit::tls13-server-driver-client-finished-key server)))
     "server driver rejects input after fatal Finished failure")))
  (progn
                  (incf selected)
                  (%server-driver-test-ticket-key-store-lifecycle
                   provider chain private-key now (function check-case))
                  (check-case
                   (plusp assertions)
                   "server driver executed nonzero assertions")))
                (format t "TLS 1.3 server driver: selected test count: ~D; assertions: ~D~%"
                        selected assertions)
                t)))))
      (when (probe-file certificate) (ignore-errors (delete-file certificate)))
      (when (probe-file key-path) (ignore-errors (delete-file key-path)))
      (when (probe-file directory)
        (ignore-errors (uiop:delete-directory-tree directory :validate t))))
    (check (not (probe-file directory))
           "server driver certificate directory is removed after tests")
    t))
