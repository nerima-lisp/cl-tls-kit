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
  ticket-store offered-ticket resumed-p resumption-master-secret
  client-hello private-key selected-group last-sent-key-share-group
  hello-retry-request-received hash suite state
  certificate-chain peer-certificate trust-anchors now verify-signature
  (transcript (make-array 0 :element-type '(unsigned-byte 8)))
  early-secret handshake-secret master-secret handshake-traffic-secret
  client-finished-key server-finished-key
  handshake-read-state handshake-write-state
  application-read-state application-write-state
  compatibility-ccs-flight (compatibility-ccs-count 0)
  (pending-handshake (make-array 0 :element-type '(unsigned-byte 8)))
  close-notify-received)

;; Certificate chains and their per-certificate extensions fit within this
;; policy limit while fragmented input cannot consume the uint24 wire maximum.
(defconstant +tls13-max-handshake-body-length+ (* 1024 1024))
(progn
  (progn
  (defconstant +tls13-ticket-max-lifetime+ 604800)
  (defconstant +tls13-ticket-max-per-key+ 4)
  (defconstant +tls13-ticket-max-total+ 64))
  (defstruct (%tls13-session-ticket
              (:constructor %make-tls13-session-ticket
                  (hostname alpn identity psk hash lifetime age-add created-at order)))
    hostname alpn identity psk hash lifetime age-add created-at order)
  (defmethod print-object ((ticket %tls13-session-ticket) stream)
    (print-unreadable-object (ticket stream :type t)))
  (defstruct (tls13-ticket-store
              (:constructor %make-tls13-ticket-store (clock mutex)))
    (clock nil :read-only t)
    (mutex nil :read-only t)
    (entries (make-hash-table :test (function equal)))
    (next-order 0))
  (defmethod print-object ((store tls13-ticket-store) stream)
    (print-unreadable-object (store stream :type t)))
  (defmethod print-object ((driver tls13-client-driver) stream)
    (print-unreadable-object (driver stream :type t)))
  (defun %tls13-ticket-now-ms ()
    (floor (* 1000 (get-internal-real-time)) internal-time-units-per-second))
  (defun make-tls13-ticket-store (&key (clock (function %tls13-ticket-now-ms)))
    "Create a thread-safe in-memory ticket store.

CLOCK returns monotonic milliseconds. Tickets expire after their advertised
lifetime, measured from the time the NewSessionTicket message is received.
The client does not store tickets whose advertised lifetimes exceed seven
days, the TLS 1.3 maximum. Expiry is checked against the receipt time when a
ticket is stored and again when selected for ClientHello1. If the server
requests a HelloRetryRequest, the driver retains that ticket for ClientHello2
even if it expires in between.

The store matches tickets by normalized server hostname and negotiated ALPN
protocol (or no ALPN). The client does not store or offer tickets when the
server hostname is unknown. It keeps at most four tickets per hostname and
ALPN match and 64 total. When a limit is reached, it evicts the oldest ticket.

Pass the same store as :TICKET-STORE to each client driver. Drivers store
NewSessionTicket messages automatically when the server hostname is known.
When a driver starts a connection, it removes one matching ticket from the
store and does not put it back."
    (unless (functionp clock)
      (error "Ticket-store clock must be callable"))
    (%make-tls13-ticket-store clock
                              (bordeaux-threads:make-lock "TLS 1.3 ticket store")))
  (defun %tls13-ticket-key (hostname alpn)
    (list (and hostname (normalize-hostname hostname))
          (and alpn (copy-seq alpn))))
  (defun %tls13-ticket-expired-p (ticket now)
    (>= (- now (%tls13-session-ticket-created-at ticket))
        (* 1000 (%tls13-session-ticket-lifetime ticket))))
  (defun %tls13-ticket-store-call (store function)
    (bordeaux-threads:with-lock-held ((tls13-ticket-store-mutex store))
      (funcall function)))
  (progn
  (defun %tls13-ticket-clear-secret (ticket)
    (fill (%tls13-session-ticket-psk ticket) 0)
    ticket)
  (defun %tls13-ticket-store-count (store)
    (loop for tickets being the hash-values of (tls13-ticket-store-entries store)
          sum (length tickets)))
  (defun %tls13-ticket-store-trim-key (store key)
    (let* ((entries (tls13-ticket-store-entries store))
           (tickets (gethash key entries))
           (excess (- (length tickets) +tls13-ticket-max-per-key+)))
      (when (plusp excess)
        (dolist (ticket (subseq tickets 0 excess))
          (%tls13-ticket-clear-secret ticket))
        (setf (gethash key entries) (nthcdr excess tickets)))))
  (defun %tls13-ticket-store-oldest (store)
    (let ((oldest-key nil)
          (oldest-ticket nil))
      (maphash
       (lambda (key tickets)
         (dolist (ticket tickets)
           (when (or (null oldest-ticket)
                     (< (%tls13-session-ticket-order ticket)
                        (%tls13-session-ticket-order oldest-ticket)))
             (setf oldest-key key
                   oldest-ticket ticket))))
       (tls13-ticket-store-entries store))
      (values oldest-key oldest-ticket)))
  (defun %tls13-ticket-store-trim-total (store)
    (let ((entries (tls13-ticket-store-entries store)))
      (loop while (> (%tls13-ticket-store-count store) +tls13-ticket-max-total+)
            do (multiple-value-bind (key oldest)
                   (%tls13-ticket-store-oldest store)
                 (let ((remaining (remove oldest (gethash key entries) :count 1)))
                   (%tls13-ticket-clear-secret oldest)
                   (if remaining
                       (setf (gethash key entries) remaining)
                       (remhash key entries)))))))
  (defun %tls13-ticket-store-prune (store now)
    (let ((entries (tls13-ticket-store-entries store)))
      (dolist (key (loop for key being the hash-keys of entries collect key))
        (let ((live (remove-if (lambda (ticket)
                                 (let ((expired (%tls13-ticket-expired-p ticket now)))
                                   (when expired (%tls13-ticket-clear-secret ticket))
                                   expired))
                               (gethash key entries))))
          (if live
              (setf (gethash key entries) live)
              (remhash key entries)))))))
  (defun %tls13-ticket-store-put
    (store hostname alpn identity psk hash lifetime age-add &optional stored-at)
  (unless (and (tls13-ticket-store-p store)
               (%octets-p identity) (<= 1 (length identity) #xffff)
               (%octets-p psk) (member hash (list :sha256 :sha384))
               (= (length psk) (if (eq hash :sha384) 48 32))
               (integerp lifetime) (<= 1 lifetime +tls13-ticket-max-lifetime+)
               (typep age-add '(integer 0 #xffffffff))
               (or (null stored-at) (typep stored-at '(integer 0 *))))
    (error "Invalid TLS 1.3 ticket"))
  (when hostname
    (let* ((key (%tls13-ticket-key hostname alpn))
           (ticket nil))
      (%tls13-ticket-store-call
       store
       (lambda ()
         (let* ((now (funcall (tls13-ticket-store-clock store)))
                (created-at (or stored-at now))
                (candidate
                  (%make-tls13-session-ticket
                   (first key) (second key) (copy-seq identity) (copy-seq psk)
                   hash lifetime age-add created-at
                   (incf (tls13-ticket-store-next-order store)))))
           (%tls13-ticket-store-prune store now)
           (if (%tls13-ticket-expired-p candidate now)
               (%tls13-ticket-clear-secret candidate)
             (progn
               (setf ticket candidate
                     (gethash key (tls13-ticket-store-entries store))
                     (append (gethash key (tls13-ticket-store-entries store))
                             (list ticket)))
               (%tls13-ticket-store-trim-key store key)
               (%tls13-ticket-store-trim-total store))))))
      ticket)))
  (defun %tls13-ticket-store-take (store hostname alpn hashes)
  (when (and store hostname)
    (let ((key (%tls13-ticket-key hostname alpn)))
      (%tls13-ticket-store-call
       store
       (lambda ()
         (let* ((now (funcall (tls13-ticket-store-clock store)))
                (entries (tls13-ticket-store-entries store)))
           (%tls13-ticket-store-prune store now)
           (let* ((tickets (gethash key entries))
                  (ticket (find-if
                           (lambda (candidate)
                             (member (%tls13-session-ticket-hash candidate) hashes))
                           tickets)))
             (when ticket
               (let ((remaining (remove ticket tickets :count 1)))
                 (if remaining
                     (setf (gethash key entries) remaining)
                   (remhash key entries)))
               ticket)))))))))

(progn
  (defvar *driver-transport-failure* nil)
  (defun %driver-fail (reason)
    (error 'tls13-client-driver-error :reason reason))
  (defun %driver-close-transport (driver &optional sensitive-error-p)
    (let ((ticket (tls13-client-driver-offered-ticket driver))
          (state (tls13-client-driver-state driver)))
      (when (or (not sensitive-error-p)
                (and ticket
                     (some #'plusp (%tls13-session-ticket-psk ticket)))
                (member state '(:awaiting-server-hello
                                :awaiting-encrypted-extensions
                                :awaiting-certificate
                                :awaiting-certificate-verify
                                :awaiting-finished)))
        (%driver-clear-offered-ticket-secret driver)
        (unless (eq state :closed)
          (setf (tls13-client-driver-state driver) :closed)
          (when (tls13-client-driver-resumption-master-secret driver)
            (fill (tls13-client-driver-resumption-master-secret driver) 0)
            (setf (tls13-client-driver-resumption-master-secret driver) nil))
          (when (tls13-client-driver-transport-close driver)
            (handler-case
                (progn
                  (funcall (tls13-client-driver-transport-close driver) driver)
                  nil)
              (error (condition) condition))))))))

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
      (setf *driver-transport-failure* nil)
      (handler-case
          (handler-bind ((error (lambda (condition)
                                  (setf *driver-transport-failure* condition))))
            (funcall (tls13-client-driver-transport-write driver) driver wire))
        (error (condition)
          (when (eq condition *driver-transport-failure*)
            (%driver-close-transport driver))
          (error condition))))
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
(defun %driver-handle-fatal-condition (driver condition)
  (let* ((state (tls13-client-driver-state driver))
         (reason (and (typep condition 'tls13-client-driver-error)
                      (tls13-client-driver-error-reason condition)))
         (reason-key (if (consp reason) (first reason) reason))
         (peer-alert (eq reason-key :peer-alert))
         (no-alert-failure
          (or
            (typep condition (quote tls-sequence-overflow))
            (eq (type-of condition) (quote tls-record-error))
            (member reason-key (quote (:eof :close-notify-during-handshake)))))
         (description
          (typecase condition
            (tls13-client-driver-error
             (case reason-key
               ((:unexpected-hrr :unexpected-message :unexpected-record) 10)
               (:missing-server-key-share 109)
               (:unsupported-extension 110)
               ((:unrequested-key-share-group :hrr-unsupported-group
  :hrr-repeated-group
  :hrr-cipher-suite-mismatch :unoffered-cipher-suite :downgrade-sentinel
  :invalid-key-share :unexpected-psk-identity :invalid-psk-identity
  :psk-hash-mismatch :resumed-alpn-mismatch) 47)
               (:unexpected-alpn 120)
               ((:invalid-server-certificate :missing-server-certificate
                                             :certificate-verification-failed) 42)
               (:certificate-verify-failed 51)
               (:finished-mismatch 51)
               ((:decode-error :transcript-too-long) 50)
               (:missing-key-exchange-function 80)
               (otherwise
                (when (and (member state
                                   '(:awaiting-server-hello
                                     :awaiting-encrypted-extensions
                                     :awaiting-certificate
                                     :awaiting-certificate-verify
                                     :awaiting-finished))
                           (not (member reason-key
                                        '(:eof :missing-transport-reader
                                               :missing-transport-writer
                                               :not-connected :invalid-key-update
                                               :already-started :not-started
                                               :missing-key-exchange-generator
                                               :close-notify-during-handshake
                                               :peer-alert))))
                  80))))
            (tls13-negotiation-error
             (case (tls13-negotiation-error-field condition)
               ((:legacy-version :supported-version) 70)
               (otherwise 47)))
            (tls13-decode-error 50)
            (tls-record-overflow 22)
            (tls-aead-error 20)
            (tls-invalid-record 10)
            (tls-sequence-overflow nil)
            (tls-record-error nil))))
    (when (and (not (eq state :closed))
               (not (eq condition *driver-transport-failure*))
               (or no-alert-failure
                   (and (not (eq state :new))
                        (or peer-alert description))))
      (unless (or peer-alert no-alert-failure)
        (let* ((write-state
                (cond
                 ((eq state :connected)
                  (tls13-client-driver-application-write-state driver))
                 ((member state '(:awaiting-server-hello
                                  :awaiting-encrypted-extensions
                                  :awaiting-certificate
                                  :awaiting-certificate-verify
                                  :awaiting-finished))
                  (tls13-client-driver-handshake-write-state driver))))
               (plaintext-alert-p
                (and (eq state :awaiting-server-hello)
                     (null write-state))))
          (when (or write-state plaintext-alert-p)
            (handler-case
                (%driver-write-record
                 driver
                 (make-tls-plaintext +tls-content-type-alert+
                                     (vector 2 description))
                 write-state)
              (error () nil)))))
      (%driver-close-transport driver))))

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
(progn
  (defun %driver-take-session-ticket (driver)
    (let* ((store (tls13-client-driver-ticket-store driver))
           (hostname (tls13-client-driver-hostname driver))
           (protocols (tls13-client-driver-alpn driver))
           (hashes (remove-duplicates
                    (map 'list #'tls13-cipher-suite-hash
                         (tls13-client-driver-cipher-suites driver))))
           (protocols (if (and (listp protocols) protocols)
                          protocols
                        (list nil))))
      (loop for protocol in protocols
            for ticket = (%tls13-ticket-store-take
                          store hostname protocol hashes)
            when ticket return ticket)))
  (defun %driver-client-hello-with-psk-binder (driver hello ticket &optional allow-expired-p)
    (let* ((store (tls13-client-driver-ticket-store driver))
           (now (funcall (tls13-ticket-store-clock store))))
      (flet ((without-psk (client-hello)
                          (make-tls13-client-hello
                           (tls13-client-hello-legacy-version client-hello)
                           (tls13-client-hello-random client-hello)
                           (tls13-client-hello-session-id client-hello)
                           (tls13-client-hello-cipher-suites client-hello)
                           (remove-if (lambda (extension)
                                        (member (tls-extension-type extension) '(41 45)))
                                      (tls13-client-hello-extensions client-hello)))))
        (when (and (not allow-expired-p) (%tls13-ticket-expired-p ticket now)) (progn (%tls13-ticket-clear-secret ticket) (return-from %driver-client-hello-with-psk-binder (values (without-psk hello) nil))))
        (let* ((hash (%tls13-session-ticket-hash ticket))
               (psk (%tls13-session-ticket-psk ticket))
               (binder-length (length psk))
               (age
 (mod (+ (max 0 (- now (%tls13-session-ticket-created-at ticket)))
         (%tls13-session-ticket-age-add ticket))
      (expt 2 32)))
               (identity-entry
                (%cat (%encode-vector (%tls13-session-ticket-identity ticket) 2 :minimum 1)
                      (%u32 age)))
               (identities (%encode-vector identity-entry 2 :minimum 7))
               (binder-entry
                (%cat (%hs-u8 binder-length)
                      (make-array binder-length
                                  :element-type '(unsigned-byte 8)
                                  :initial-element 0)))
               (binders (%encode-vector binder-entry 2 :minimum (1+ binder-length)))
               (extension-data (%cat identities binders))
               (extensions
                (append (remove-if (lambda (extension)
                                     (= (tls-extension-type extension) 41))
                                   (tls13-client-hello-extensions hello))
                        (list (make-tls-extension 41 extension-data))))
               (provisional
                (make-tls13-client-hello
                 (tls13-client-hello-legacy-version hello)
                 (tls13-client-hello-random hello)
                 (tls13-client-hello-session-id hello)
                 (tls13-client-hello-cipher-suites hello)
                 extensions))
               (wire (encode-handshake 1 provisional))
               (truncated (subseq wire 0 (- (length wire) (+ 3 binder-length))))
               (transcript
                (concatenate '(vector (unsigned-byte 8))
                             (tls13-client-driver-transcript driver) truncated))
               (digest (funcall (tls13-crypto-provider-digest
                                 (tls13-client-driver-provider driver))
                                hash transcript))
               (binder (tls13-psk-binder
                        (tls13-client-driver-provider driver) hash psk digest))
               (complete-data
                (concatenate '(vector (unsigned-byte 8))
                             (subseq extension-data 0 (- (length extension-data)
                                                         binder-length))
                             binder))
               (complete
                (make-tls13-client-hello
                 (tls13-client-hello-legacy-version hello)
                 (tls13-client-hello-random hello)
                 (tls13-client-hello-session-id hello)
                 (tls13-client-hello-cipher-suites hello)
                 (append (remove-if (lambda (extension)
                                      (= (tls-extension-type extension) 41))
                                    (tls13-client-hello-extensions hello))
                         (list (make-tls-extension 41 complete-data))))))
          (if (and (not allow-expired-p)
                   (%tls13-ticket-expired-p
                    ticket (funcall (tls13-ticket-store-clock store))))
              (progn
  (%tls13-ticket-clear-secret ticket)
  (values (without-psk hello) nil))
            (values complete ticket))))))
  (progn
  (defun %driver-store-session-ticket (driver message)
  (let* ((store (tls13-client-driver-ticket-store driver))
         (hostname (tls13-client-driver-hostname driver))
         (received-at
           (and store hostname
                (funcall (tls13-ticket-store-clock store))))
         (master (tls13-client-driver-resumption-master-secret driver))
         (lifetime (tls13-new-session-ticket-lifetime-age message)))
    (when (and store hostname master
               (<= 1 lifetime +tls13-ticket-max-lifetime+))
      (let ((psk (tls13-resumption-psk
                  (tls13-client-driver-provider driver)
                  (tls13-client-driver-hash driver) master
                  (tls13-new-session-ticket-ticket-nonce message))))
        (unwind-protect
             (%tls13-ticket-store-put
              store hostname
              (tls13-client-driver-negotiated-alpn driver)
              (tls13-new-session-ticket-ticket message)
              psk
              (tls13-client-driver-hash driver) lifetime
              (tls13-new-session-ticket-ticket-age-add message)
              received-at)
          (fill psk 0))))
    driver))
  (defun %driver-server-selected-psk-p (driver hello)
    (let ((extensions
           (remove-if-not (lambda (extension)
                            (= (tls-extension-type extension) 41))
                          (tls13-server-hello-extensions hello))))
      (when extensions
        (unless (= (length extensions) 1)
          (%driver-fail :invalid-psk-identity))
        (let ((ticket (tls13-client-driver-offered-ticket driver))
              (data (tls-extension-data (first extensions))))
          (unless ticket (%driver-fail :unexpected-psk-identity))
          (unless (= (length data) 2) (%driver-fail :invalid-psk-identity))
          (unless (zerop (+ (ash (aref data 0) 8) (aref data 1)))
            (%driver-fail :unexpected-psk-identity))
          (unless (eq (tls13-cipher-suite-hash
                       (tls13-server-hello-cipher-suite hello))
                      (%tls13-session-ticket-hash ticket))
            (%driver-fail :psk-hash-mismatch))
          t))))
  (defun %driver-clear-offered-ticket-secret (driver)
    (let ((ticket (tls13-client-driver-offered-ticket driver)))
      (when ticket
        (fill (%tls13-session-ticket-psk ticket) 0))))
  (defun %driver-install-resumption-master-secret (driver)
  (when (tls13-client-driver-ticket-store driver)
    (let* ((provider (tls13-client-driver-provider driver))
           (hash (tls13-client-driver-hash driver)))
      (setf (tls13-client-driver-resumption-master-secret driver)
            (tls13-resumption-secret
             provider hash (tls13-client-driver-master-secret driver)
             (%driver-digest driver (tls13-client-driver-transcript driver)))))))))
(defun %driver-default-key-exchange ()
  (labels ((operation (name)
             (let ((package (find-package (quote #:crypto-kit))))
               (unless package
                 (%driver-fail :missing-key-exchange-function))
               (let ((symbol (find-symbol name package)))
                 (unless (and symbol (fboundp symbol))
                   (%driver-fail :missing-key-exchange-function))
                 (symbol-function symbol))))
           (crypto-error-p (condition)
             (let* ((package (find-package (quote #:crypto-kit)))
                    (symbol (and package (find-symbol "CRYPTO-ERROR" package))))
               (and symbol (typep condition symbol))))
           (crypto-error-message (condition)
             (let* ((package (find-package (quote #:crypto-kit)))
                    (symbol (and package
                                 (find-symbol "CRYPTO-ERROR-MESSAGE" package))))
               (when (and symbol (fboundp symbol))
                 (funcall (symbol-function symbol) condition))))
           (p256-peer-point-error-p (condition)
             (and (crypto-error-p condition)
                  (member (crypto-error-message condition)
                          '("Invalid uncompressed EC point encoding"
                            "EC point is not on curve")
                          :test #'string=)))
           (p256-shared-secret (private public)
             (let ((ecdh (operation "P256-ECDH")))
               (handler-case
                   (funcall ecdh private public)
                 (error (condition)
                   (if (p256-peer-point-error-p condition)
                       (%driver-fail :invalid-key-share)
                       (error condition)))))))
    (list
     :generate
     (lambda (group)
       (case group
         (#x001d
          (let* ((private (funcall (operation "RANDOM-OCTETS") 32))
                 (public (funcall (operation "X25519-BASE") private)))
            (values private public)))
         (#x0017
          (funcall (operation "P256-GENERATE-KEYPAIR")))
         (otherwise
          (%driver-fail :missing-key-exchange-generator))))
     :shared-secret
     (lambda (group private public)
       (case group
         (#x001d
          (unless (= (length public) 32)
            (%driver-fail :invalid-key-share))
          (multiple-value-bind (secret all-zero)
              (funcall (operation "X25519") private public)
            (when all-zero (%driver-fail :invalid-key-share))
            secret))
         (#x0017
          (unless (and (= (length public) 65) (= (aref public 0) 4))
            (%driver-fail :invalid-key-share))
          (p256-shared-secret private public))
         (otherwise
          (%driver-fail :missing-key-exchange-function)))))))

(defun make-tls13-client-driver
    (&key provider key-exchange on-send verify-certificate-verify
          transport-read transport-write transport-close transport hostname alpn
          ticket-store trust-anchors (now (get-universal-time)) verify-signature
          (cipher-suites #( #x1301 #x1302 #x1303))
          (supported-groups '(#x001d #x0017))
          (signature-algorithms #( #x0804 #x0805 #x0806 #x0403 #x0503)))
  "The driver owns handshake message sequencing and transcript/key-schedule
progression. PROVIDER remains required, including when KEY-EXCHANGE is
omitted, and supplies hash, HKDF, HMAC, and AEAD primitives. By default,
CL-CRYPTO-KIT handles the X25519 (#x001d) or P-256 (#x0017) key share selected
during the handshake. ALPN, when supplied, is a non-empty list of protocol
strings in preference order. Each must encode to 1 to 255 ASCII octets. Ticket
lookup tries the offered protocols in order. Stored tickets use the server-
selected protocol, or no ALPN when none is selected. A resumed connection must
select the ALPN value stored with its ticket.

A supplied KEY-EXCHANGE plist replaces the built-in key-share functions. It
must contain callable function designators for :GENERATE and :SHARED-SECRET.
:GENERATE is called as (GROUP), where GROUP is a 16-bit TLS named-group ID, and
returns PRIVATE-KEY and PUBLIC-SHARE as multiple values. PRIVATE-KEY is opaque
to the driver; the value returned for a GROUP is passed unchanged to the
:SHARED-SECRET call for that GROUP. PUBLIC-SHARE is a vector of octets in the
TLS encoding for GROUP. The built-in handlers support X25519 (#x001d), with its
32-octet RFC 7748 encoding, and P-256 (#x0017), with a 65-octet SEC1 uncompressed
point beginning with #x04. Custom callbacks may implement other groups in
SUPPORTED-GROUPS. The driver does not validate group coverage at construction,
so callbacks must handle every listed group.

:SHARED-SECRET is called as (GROUP PRIVATE-KEY PEER-PUBLIC-SHARE); the peer
share is a vector of octets in the TLS encoding for that GROUP. It returns the
raw shared-secret bytes for GROUP as an octet vector for the TLS 1.3 key
schedule. Custom callbacks must validate peer shares. The built-in handlers
reject all-zero X25519 secrets and malformed P-256 points. Errors signaled by
custom callbacks propagate; the driver does not reclassify arbitrary callback
errors as invalid peer shares.

SUPPORTED-GROUPS controls the offered groups and their preference order. By
default, X25519 is first and P-256 second; the driver sends an initial share
for the first group. For a HelloRetryRequest asking for a different offered
group, :GENERATE is called again for that group. The driver rejects requests
for unoffered groups, a retry of the initial group, and a second HelloRetryRequest."
  (progn
    (unless (typep provider 'tls13-crypto-provider) (%driver-fail :provider))
    (when (and ticket-store (not (typep ticket-store 'tls13-ticket-store)))
      (%driver-fail :ticket-store)))
  (let* ((offered-suites (coerce
                          (remove-if-not
                           (lambda (suite)
                             (member suite '(#x1301 #x1302 #x1303 #x1304)))
                           (coerce cipher-suites 'list))
                          'vector))
         (suite (and (plusp (length offered-suites))
                     (aref offered-suites 0))))
    (unless suite (%driver-fail :unsupported-cipher-suite))
    (let ((driver (%make-tls13-client-driver
                   :provider provider
                   :key-exchange (or key-exchange (%driver-default-key-exchange))
                   :on-send on-send
                   :transport-read (or transport-read (getf transport :read))
                   :transport-write (or transport-write (getf transport :write))
                   :transport-close (or transport-close (getf transport :close))
                   :verify-certificate-verify verify-certificate-verify
                   :hostname hostname :alpn alpn :ticket-store ticket-store
                   :cipher-suites offered-suites :supported-groups supported-groups
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
  (handler-case
      (let ((ticket nil)
            (ticket-transferred nil))
        (unwind-protect
             (let* ((group (first (tls13-client-driver-supported-groups driver)))
                    (share (%driver-key-share driver group))
                    (random (or (and (listp (tls13-client-driver-key-exchange driver))
                                     (getf (tls13-client-driver-key-exchange driver) :random))
                                #'%tls-client-csprng-octets)))
               (setf ticket (%driver-take-session-ticket driver))
               (let* ((extensions
                        (append
                         (when (tls13-client-driver-hostname driver)
                           (list (make-tls-extension
                                  0 (encode-sni-extension
                                     (tls13-client-driver-hostname driver)))))
                         (when (tls13-client-driver-alpn driver)
                           (list (make-tls-extension
                                  16 (encode-alpn-extension
                                      (tls13-client-driver-alpn driver)))))
                         (list (make-tls-extension 43 #(2 3 4))
                               (make-tls-extension
                                10 (%encode-vector
                                    (apply #'%cat
                                           (mapcar #'%hs-u16
                                                   (tls13-client-driver-supported-groups driver)))
                                    2))
                               (make-tls-extension
                                13 (%encode-vector
                                    (apply #'%cat
                                           (map 'list #'%hs-u16
                                                (tls13-client-driver-signature-algorithms driver)))
                                    2))
                               (when ticket (make-tls-extension 45 #(1 1)))
                               (make-tls-extension
                                51 (encode-key-share-extension (list share))))))
                      (client (make-tls13-client-hello
                               #x0303
                               (funcall random 32)
                               (funcall random 32)
                               (tls13-client-driver-cipher-suites driver)
                               (remove nil extensions))))
                 (when ticket
                   (multiple-value-setq (client ticket)
                     (%driver-client-hello-with-psk-binder driver client ticket)))
                 (setf (tls13-client-driver-client-hello driver) client
                       (tls13-client-driver-offered-ticket driver) ticket
                       (tls13-client-driver-state driver) :awaiting-server-hello
                       ticket-transferred t)
                 (%driver-send driver 1 client)
                 (setf (tls13-client-driver-last-sent-key-share-group driver) group)
                 driver))
          (unless ticket-transferred
            (when ticket (%tls13-ticket-clear-secret ticket)))))
    (error (condition)
      (%driver-close-transport driver)
      (error condition))))

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
          (let ((pem (load-trust-store-pem))
                (anchors nil))
            (dolist (block (pem-decode pem))
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

(defun %driver-client-step (driver wire)
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
      (return-from %driver-client-step driver))
    (when (and (eq (tls13-client-driver-state driver) :connected)
               (typep message 'tls13-new-session-ticket))
      (%driver-store-session-ticket driver message)
      (return-from %driver-client-step driver))
    (when (and (= type 2) (typep message 'tls13-hello-retry-request))
  (unless (eq (tls13-client-driver-state driver) :awaiting-server-hello)
    (%driver-fail :unexpected-hrr))
  (when (tls13-client-driver-hello-retry-request-received driver)
    (%driver-fail :unexpected-hrr))
  (let* ((suite (tls13-hello-retry-request-cipher-suite message))
         (hash (tls13-cipher-suite-hash suite))
         (group (tls13-hello-retry-request-selected-group message))
         (initial-group (tls13-client-driver-selected-group driver)))
    (unless (find suite (tls13-client-driver-cipher-suites driver))
      (%driver-fail :unoffered-cipher-suite))
    (setf (tls13-client-driver-suite driver) suite
          (tls13-client-driver-hash driver) hash
          (tls13-client-driver-transcript driver)
          (concatenate '(vector (unsigned-byte 8))
                       (%driver-message-hash driver)
                       bytes))
    (unless (member group (tls13-client-driver-supported-groups driver))
      (%driver-fail :hrr-unsupported-group))
    (when (= group initial-group)
      (%driver-fail :hrr-repeated-group))
    (let* ((share (%driver-key-share driver group))
           (ticket (tls13-client-driver-offered-ticket driver))
           (hello (tls13-client-driver-client-hello driver))
           (cookie (find 44 (tls13-hello-retry-request-extensions message)
                         :key #'tls-extension-type)))
      (setf (tls13-client-driver-client-hello driver)
            (make-tls13-client-hello
             (tls13-client-hello-legacy-version hello)
             (tls13-client-hello-random hello)
             (tls13-client-hello-session-id hello)
             (tls13-client-hello-cipher-suites hello)
             (append
              (list (make-tls-extension
                     51 (encode-key-share-extension (list share))))
              (when cookie
                (list (make-tls-extension 44 (tls-extension-data cookie))))
              (remove-if (lambda (extension)
                           (member (tls-extension-type extension) '(44 51)))
                         (tls13-client-hello-extensions hello)))))
      (when ticket
        (if (eq hash (%tls13-session-ticket-hash ticket))
            (setf (tls13-client-driver-client-hello driver)
                  (%driver-client-hello-with-psk-binder
                   driver (tls13-client-driver-client-hello driver) ticket t))
          (progn
            (setf (tls13-client-driver-client-hello driver)
                  (let ((retry-hello
                          (tls13-client-driver-client-hello driver)))
                    (make-tls13-client-hello
                     (tls13-client-hello-legacy-version retry-hello)
                     (tls13-client-hello-random retry-hello)
                     (tls13-client-hello-session-id retry-hello)
                     (tls13-client-hello-cipher-suites retry-hello)
                     (remove-if
                      (lambda (extension)
                        (member (tls-extension-type extension) '(41 45)))
                      (tls13-client-hello-extensions retry-hello)))))
            (%driver-clear-offered-ticket-secret driver)
            (setf (tls13-client-driver-offered-ticket driver) nil))))
      (setf (tls13-client-driver-compatibility-ccs-flight driver)
            :hello-retry-request
            (tls13-client-driver-compatibility-ccs-count driver) 0)
      (%driver-send driver 1 (tls13-client-driver-client-hello driver))
      (setf (tls13-client-driver-last-sent-key-share-group driver) group
            (tls13-client-driver-hello-retry-request-received driver) t)
      (return-from %driver-client-step driver))))
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
       (when (and (tls13-client-driver-hello-retry-request-received driver)
           (/= (tls13-server-hello-cipher-suite message)
               (tls13-client-driver-suite driver)))
  (%driver-fail :hrr-cipher-suite-mismatch))
       (let ((server-share (%driver-server-key-share message)))
         (unless (member (car server-share)
                         (tls13-client-driver-supported-groups driver))
           (%driver-fail :unrequested-key-share-group))
         (unless (eql (car server-share)
                      (tls13-client-driver-last-sent-key-share-group driver))
           (%driver-fail :unrequested-key-share-group)))
       (setf (tls13-client-driver-suite driver)
             (tls13-server-hello-cipher-suite message)
             (tls13-client-driver-hash driver)
             (tls13-cipher-suite-hash (tls13-server-hello-cipher-suite message)))
       (let ((ticket (tls13-client-driver-offered-ticket driver))
             (selected (%driver-server-selected-psk-p driver message)))
         (setf (tls13-client-driver-resumed-p driver) (not (null selected))
               (tls13-client-driver-early-secret driver)
               (tls13-early-secret
                (tls13-client-driver-provider driver)
                (tls13-client-driver-hash driver)
                (and selected ticket (%tls13-session-ticket-psk ticket))))
         (%driver-clear-offered-ticket-secret driver))
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
       (setf (tls13-client-driver-compatibility-ccs-flight driver) :server-hello
             (tls13-client-driver-compatibility-ccs-count driver) 0
             (tls13-client-driver-state driver) :awaiting-encrypted-extensions))
      (tls13-encrypted-extensions
 (when (find 42 (tls13-encrypted-extensions-extensions message)
             :key #'tls-extension-type)
   (%driver-fail :unsupported-extension))
 (let ((extension
         (find +tls13-extension-application-layer-protocol-negotiation+
               (tls13-encrypted-extensions-extensions message)
               :key #'tls-extension-type)))
   (when extension
     (let ((protocols (decode-alpn-extension (tls-extension-data extension))))
       (unless (= (length protocols) 1)
         (%driver-fail :unexpected-alpn))
       (unless (member (first protocols) (tls13-client-driver-alpn driver)
                       :test #'string=)
         (%driver-fail :unexpected-alpn))
       (setf (tls13-client-driver-negotiated-alpn driver)
             (first protocols)))))
 (when (and (tls13-client-driver-resumed-p driver)
            (not (equal (tls13-client-driver-negotiated-alpn driver)
                        (%tls13-session-ticket-alpn
                         (tls13-client-driver-offered-ticket driver)))))
   (%driver-fail :resumed-alpn-mismatch))
 (setf (tls13-client-driver-state driver)
       (if (tls13-client-driver-resumed-p driver)
           :awaiting-finished
         :awaiting-certificate)))
      (tls13-certificate
       (when (tls13-client-driver-resumed-p driver)
         (%driver-fail :unexpected-message))
       (let ((chain (%driver-certificate-chain message)))
         (setf (tls13-client-driver-certificate-chain driver) chain
               (tls13-client-driver-peer-certificate driver) (first chain))
         (%driver-verify-certificate-chain driver chain))
       (setf (tls13-client-driver-state driver) :awaiting-certificate-verify))
      (tls13-certificate-verify
       (when (tls13-client-driver-resumed-p driver)
         (%driver-fail :unexpected-message))
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
       (unless (eq (tls13-client-driver-state driver) :awaiting-finished)
         (%driver-fail :unexpected-message))
       (unless (tls13-verify-finished
                (tls13-compute-finished-verify-data
                 (tls13-client-driver-provider driver)
                 (tls13-client-driver-hash driver)
                 (tls13-client-driver-server-finished-key driver)
                 (%driver-digest driver prior-transcript))
                (tls13-finished-verify-data message))
         (%driver-fail :finished-mismatch))
       (let* ((provider (tls13-client-driver-provider driver))
              (hash (tls13-client-driver-hash driver))
              (master (tls13-master-secret
                       provider hash (tls13-client-driver-handshake-secret driver)))
              (transcript-hash (%driver-digest driver
                                               (tls13-client-driver-transcript driver)))
              (server-secret
               (tls13-traffic-secret provider hash master :server transcript-hash
                                     :phase :application))
              (client-secret
               (tls13-traffic-secret provider hash master :client transcript-hash
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
       (%driver-install-resumption-master-secret driver)
       (setf (tls13-client-driver-state driver) :connected))
      (otherwise (%driver-fail :unexpected-message)))
    driver))

(defun %driver-read-record (driver)
  (unless (tls13-client-driver-transport-read driver)
    (%driver-fail :missing-transport-reader))
  (setf *driver-transport-failure* nil)
  (handler-bind ((error (lambda (condition)
                          (setf *driver-transport-failure* condition))))
    (funcall (tls13-client-driver-transport-read driver) driver)))

(defun %driver-decrypt-record (driver wire)
  (let ((state (if (eq (tls13-client-driver-state driver) :connected)
                   (tls13-client-driver-application-read-state driver)
                   (tls13-client-driver-handshake-read-state driver))))
    (if state
        (decrypt-tls13-traffic-record wire state)
        (decode-tls-plaintext wire))))

(defun %driver-feed-handshake (driver bytes)
  (let ((pending (tls13-client-driver-pending-handshake driver)))
    (setf (tls13-client-driver-pending-handshake driver)
          (concatenate '(vector (unsigned-byte 8)) pending bytes)))
  (loop for pending = (tls13-client-driver-pending-handshake driver)
        while (>= (length pending) 4)
        for length = (+ (ash (aref pending 1) 16)
                        (ash (aref pending 2) 8)
                        (aref pending 3))
        do (when (> length +tls13-max-handshake-body-length+)
             (%driver-fail :decode-error))
        if (< (length pending) (+ 4 length))
          do (progn
               (when (> (length pending) (+ 4 +tls13-max-handshake-body-length+))
                 (%driver-fail :decode-error))
               (return))
        else
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
                   (%driver-client-step driver message-wire)))))

(defun %driver-client-read-record (driver &optional allow-would-block-p)
  "Read one TLS record, processing handshake/control records and close_notify."
  (let ((wire (%driver-read-record driver)))
    (when (and allow-would-block-p (eq wire :would-block))
      (return-from %driver-client-read-record :would-block))
    (unless wire (%driver-fail :eof))
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
      (unless (and (member (tls13-client-driver-compatibility-ccs-flight driver)
                           '(:server-hello :hello-retry-request))
                   (zerop (tls13-client-driver-compatibility-ccs-count driver)))
        (%driver-fail :unexpected-message))
      (incf (tls13-client-driver-compatibility-ccs-count driver))
      (return-from %driver-client-read-record nil))
    (let ((plaintext (if (and (eq (tls13-client-driver-state driver) :awaiting-server-hello)
                              (not (tls13-client-driver-handshake-read-state driver)))
                         (decode-tls-plaintext wire)
                         (%driver-decrypt-record driver wire))))
      (cond
        ((= (tls-plaintext-content-type plaintext)
            +tls-content-type-change-cipher-spec+)
         (%driver-fail :unexpected-message))
        ((tls-close-notify-p plaintext)
         (setf (tls13-client-driver-close-notify-received driver) t)
         (if (eq (tls13-client-driver-state driver) :connected)
             (progn
               (tls13-client-driver-close driver)
               nil)
             (%driver-fail :close-notify-during-handshake)))
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
  (let ((*driver-transport-failure* nil))
    (let* ((octets (%record-octets fragment))
           (state (tls13-client-driver-application-write-state driver))
           (limit +tls-plaintext-limit+)
           (wires nil))
      (loop for start from 0 below (max 1 (length octets)) by limit
            for end = (min (length octets) (+ start limit))
            do (push (%driver-write-record
                      driver
                      (make-tls-plaintext +tls-content-type-application-data+
                                          (subseq octets start end))
                      state)
                     wires))
      (apply #'%cat (nreverse wires)))))

(defun tls13-client-driver-close (driver)
  "Send one encrypted close_notify and close the underlying transport."
  (unless (eq (tls13-client-driver-state driver) :closed)
    (let ((write-failure nil))
      (unwind-protect
           (when (eq (tls13-client-driver-state driver) :connected)
             (handler-case
                 (%driver-write-record
                  driver (make-tls-plaintext +tls-content-type-alert+ #(1 0))
                  (tls13-client-driver-application-write-state driver))
               (error (condition)
                 (setf write-failure condition)
                 (error condition))))
        (let ((close-failure (%driver-close-transport driver)))
          (when (and close-failure (not write-failure))
            (error close-failure))))))
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
         (if (member :hostname args)
             args
           (append args (list :hostname host)))))
(defun tls13-client-driver-step (driver wire)
  (let ((*driver-transport-failure* nil))
    (handler-case
        (%driver-client-step driver wire)
      (tls13-client-driver-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (tls13-negotiation-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (tls13-decode-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (error (condition)
        (%driver-close-transport driver t)
        (error condition)))))
(defun tls13-client-driver-read-record (driver)
  (let ((*driver-transport-failure* nil))
    (handler-case
        (%driver-client-read-record driver)
      (tls13-client-driver-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (tls13-negotiation-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (tls13-decode-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (tls-record-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (error (condition)
        (%driver-close-transport driver t)
        (error condition)))))

(defun tls13-client-driver-read-application-data (driver)
  "Read application data, returning (values :DATA octets), :WOULD-BLOCK, or :EOF.
A transport reader must retain partial record bytes when returning :WOULD-BLOCK."
  (when (tls13-client-driver-close-notify-received driver)
    (return-from tls13-client-driver-read-application-data :eof))
  (unless (eq (tls13-client-driver-state driver) :connected)
    (%driver-fail :not-connected))
  (let ((*driver-transport-failure* nil))
    (handler-case
        (loop for record = (%driver-client-read-record driver t)
              do (cond
                   ((eq record :would-block)
                    (return :would-block))
                   ((null record)
                    (when (tls13-client-driver-close-notify-received driver)
                      (return :eof)))
                   (t
                    (return (values :data
                                    (tls-plaintext-fragment record))))))
      (tls13-client-driver-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (tls13-negotiation-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (tls13-decode-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (tls-record-error (condition)
        (%driver-handle-fatal-condition driver condition)
        (error condition))
      (error (condition)
        (%driver-close-transport driver t)
        (error condition)))))

(export '(tls13-client-driver tls13-client-driver-p
  make-tls13-client-driver tls13-client-driver-start tls13-client-driver-step
  tls13-client-driver-connect tls13-client-driver-read-record
  tls13-client-driver-read-application-data
  tls13-client-driver-write tls13-client-driver-close
  tls13-client-driver-key-update make-tls13-client-driver-over-tcp
  tls13-client-driver-negotiated-alpn tls13-client-driver-error
  tls13-client-driver-error-reason make-tls13-ticket-store
  tls13-ticket-store tls13-ticket-store-p tls13-client-driver-resumed-p))
