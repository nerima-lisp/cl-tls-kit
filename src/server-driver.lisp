(in-package #:cl-tls-kit)

(define-condition tls13-server-driver-error (error)
  ((reason :initarg :reason :reader tls13-server-driver-error-reason)
   (alert :initarg :alert :reader %tls13-server-driver-error-alert))
  (:report (lambda (condition stream)
             (format stream "TLS 1.3 server driver error: ~A"
                     (tls13-server-driver-error-reason condition)))))

(defstruct (tls13-server-ticket-key-store
            (:constructor %make-tls13-server-ticket-key-store))
  current previous random ticket-lifetime lock)

(defstruct (%tls13-server-ticket-key (:constructor %make-tls13-server-ticket-key))
  id secret decrypt-until)

(defstruct (tls13-server-driver (:constructor %make-tls13-server-driver))
  provider certificate-chain private-key alpn-protocols sni-callback
  ticket-key-store supported-groups cipher-suites clock random key-exchange
  (state :awaiting-client-hello)
  selected-alpn selected-suite sni-hostname hash selected-group private-key-share
  initial-client-hello cookie hrr-seen-p resumed-p
  (transcript (make-array 0 :element-type (quote (unsigned-byte 8))))
  server-flight-prefix
  client-handshake-secret server-handshake-secret client-finished-key
  master-secret resumption-master-secret
  client-application-secret server-application-secret)

(defconstant +tls13-server-max-handshake-size+ (* 1024 1024))
(defconstant +tls13-server-ticket-aead+ :aes-256-gcm)
(defconstant +tls13-server-ticket-max-lifetime+ 604800)
(defconstant +tls13-server-ticket-age-tolerance-ms+ 10000)
(defconstant +tls13-server-unix-time-offset+ 2208988800)

(defparameter *tls13-server-crypto-lock*
  (let* ((package (find-package "SB-THREAD"))
         (maker (and package (find-symbol "MAKE-MUTEX" package))))
    (when (and maker (fboundp maker))
      (funcall (symbol-function maker) :name "cl-tls-kit TLS server crypto init"))))
(defparameter *tls13-server-p256-initialized-p* nil)

(defun %tls13-server-with-lock (lock function)
  (let* ((package (find-package "SB-THREAD"))
         (grab (and package (find-symbol "GRAB-MUTEX" package)))
         (release (and package (find-symbol "RELEASE-MUTEX" package))))
    (if (and lock grab release (fboundp grab) (fboundp release))
        (progn
          (funcall (symbol-function grab) lock)
          (unwind-protect (funcall function)
            (funcall (symbol-function release) lock)))
        (funcall function))))

(defun %tls13-server-fail (reason alert)
  (error 'tls13-server-driver-error :reason reason :alert alert))

(defun %tls13-server-octets-p (value)
  (and (vectorp value)
       (subtypep (array-element-type value) '(unsigned-byte 8))))

(defun %tls13-server-octets (value reason alert)
  (unless (%tls13-server-octets-p value)
    (%tls13-server-fail reason alert))
  value)

(defun %tls13-server-u8 (value)
  (vector (ldb (byte 8 0) value)))

(defun %tls13-server-u16 (value)
  (vector (ldb (byte 8 8) value) (ldb (byte 8 0) value)))

(defun %tls13-server-u24 (value)
  (vector (ldb (byte 8 16) value) (ldb (byte 8 8) value)
          (ldb (byte 8 0) value)))

(defun %tls13-server-u32 (value)
  (vector (ldb (byte 8 24) value) (ldb (byte 8 16) value)
          (ldb (byte 8 8) value) (ldb (byte 8 0) value)))

(defun %tls13-server-u64 (value)
  (concatenate '(vector (unsigned-byte 8))
               (%tls13-server-u32 (ldb (byte 32 32) value))
               (%tls13-server-u32 (ldb (byte 32 0) value))))

(defun %tls13-server-read-u16 (bytes position)
  (nth-value 0 (%read-integer bytes position 2)))

(defun %tls13-server-read-u24 (bytes position)
  (nth-value 0 (%read-integer bytes position 3)))

(defun %tls13-server-read-u32 (bytes position)
  (nth-value 0 (%read-integer bytes position 4)))

(defun %tls13-server-read-u64 (bytes position)
  (nth-value 0 (%read-integer bytes position 8)))

(defun %tls13-server-cat (&rest vectors)
  (apply #'%cat vectors))

(defun %tls13-server-message (type body)
  (when (> (length body) #xffffff)
    (%tls13-server-fail :handshake-message-too-large 50))
  (%tls13-server-cat (vector type) (%tls13-server-u24 (length body)) body))

(defun %tls13-server-extension (extensions type)
  (find type extensions :key #'tls-extension-type))

(defun %tls13-server-extension-data (extensions type &optional required)
  (let ((extension (%tls13-server-extension extensions type)))
    (when (and required (null extension))
      (%tls13-server-fail :missing-extension 47))
    (and extension (tls-extension-data extension))))

(defun %tls13-server-vector-u16 (bytes &optional (alert 50))
  (unless (and (%tls13-server-octets-p bytes) (>= (length bytes) 2))
    (%tls13-server-fail :malformed-vector alert))
  (let ((length (%tls13-server-read-u16 bytes 0)))
    (unless (and (plusp length) (evenp length) (= length (- (length bytes) 2)))
      (%tls13-server-fail :malformed-vector alert))
    (loop for position from 2 below (length bytes) by 2
          collect (%tls13-server-read-u16 bytes position))))

(defun %tls13-server-extensions-wire (extensions)
  (%encode-extensions extensions))

(defun %tls13-server-digest (driver bytes)
  (funcall (tls13-crypto-provider-digest (tls13-server-driver-provider driver))
           (tls13-server-driver-hash driver) bytes))

(defun %tls13-server-digest-hash (driver hash bytes)
  (funcall (tls13-crypto-provider-digest (tls13-server-driver-provider driver))
           hash bytes))

(defun %tls13-server-add-transcript (driver wire)
  (setf (tls13-server-driver-transcript driver)
        (%tls13-server-cat (tls13-server-driver-transcript driver) wire)))

(defun %tls13-server-random (driver length)
  (let ((bytes (funcall (tls13-server-driver-random driver) length)))
    (unless (and (%tls13-server-octets-p bytes) (= (length bytes) length))
      (%tls13-server-fail :random-source-failed 80))
    bytes))

(defun %tls13-server-crypto-operation (name)
  (let* ((package (or (find-package "CRYPTO-KIT")
                      (find-package "CL-CRYPTO-KIT")))
         (symbol (and package (find-symbol name package))))
    (unless (and symbol (fboundp symbol))
      (%tls13-server-fail :crypto-provider-unavailable 80))
    (symbol-function symbol)))

(defun %tls13-server-eager-p256-initialization ()
  (%tls13-server-with-lock
   *tls13-server-crypto-lock*
   (lambda ()
     (unless *tls13-server-p256-initialized-p*
       (let* ((package (or (find-package "CRYPTO-KIT")
                           (find-package "CL-CRYPTO-KIT")))
              (curve-symbol (and package (find-symbol "+P256+" package)))
              (field-symbol (and package (find-symbol "%EC-FIELD-CONTEXT" package)))
              (order-symbol (and package (find-symbol "%EC-ORDER-CONTEXT" package))))
         (unless (and curve-symbol field-symbol order-symbol
                      (boundp curve-symbol) (fboundp field-symbol)
                      (fboundp order-symbol))
           (%tls13-server-fail :crypto-provider-unavailable 80))
         (let ((curve (symbol-value curve-symbol)))
           (funcall (symbol-function field-symbol) curve)
           (funcall (symbol-function order-symbol) curve))
         (setf *tls13-server-p256-initialized-p* t))))))

(defun %tls13-server-default-random (length)
  (funcall (%tls13-server-crypto-operation "RANDOM-OCTETS") length))

(defun %tls13-server-key-exchange-default (random)
  (labels ((operation (name) (%tls13-server-crypto-operation name)))
    (list
     :generate
     (lambda (group)
       (case group
         (#x001d
          (let ((private (funcall random 32)))
            (unless (and (%tls13-server-octets-p private) (= (length private) 32))
              (%tls13-server-fail :key-exchange-failed 80))
            (values private (funcall (operation "X25519-BASE") private))))
         (#x0017 (funcall (operation "P256-GENERATE-KEYPAIR")))
         (otherwise (%tls13-server-fail :key-exchange-unavailable 80))))
     :shared-secret
     (lambda (group private peer)
       (case group
         (#x001d
          (unless (= (length peer) 32)
            (%tls13-server-fail :invalid-key-share 47))
          (multiple-value-bind (secret all-zero)
              (funcall (operation "X25519") private peer)
            (when all-zero (%tls13-server-fail :invalid-key-share 47))
            secret))
         (#x0017
          (unless (and (= (length peer) 65) (= (aref peer 0) 4))
            (%tls13-server-fail :invalid-key-share 47))
          (funcall (operation "P256-ECDH") private peer))
         (otherwise (%tls13-server-fail :key-exchange-unavailable 80)))))))

(defun %tls13-server-key-exchange-operation (driver name)
  (let ((exchange (tls13-server-driver-key-exchange driver)))
    (unless (and (listp exchange) (functionp (getf exchange name)))
      (%tls13-server-fail :key-exchange-unavailable 80))
    (getf exchange name)))

(eval-when (:load-toplevel :execute)
  (when (or (find-package "CRYPTO-KIT") (find-package "CL-CRYPTO-KIT"))
    (%tls13-server-eager-p256-initialization)))

(defun %tls13-server-make-mutex (name)
  (let* ((package (find-package "SB-THREAD"))
         (maker (and package (find-symbol "MAKE-MUTEX" package))))
    (when (and maker (fboundp maker))
      (funcall (symbol-function maker) :name name))))

(defun %tls13-server-store-random (store length)
  (let ((bytes (funcall (tls13-server-ticket-key-store-random store) length)))
    (unless (and (%tls13-server-octets-p bytes) (= (length bytes) length))
      (%tls13-server-fail :ticket-key-random-failed 80))
    (copy-seq bytes)))

(defun %tls13-server-new-ticket-key (store)
  (let ((existing
          (mapcar #'%tls13-server-ticket-key-id (remove nil (cons (tls13-server-ticket-key-store-current store) (tls13-server-ticket-key-store-previous store))))))
    (loop repeat 8
          for material = (%tls13-server-store-random store 36)
          for id = (subseq material 0 4)
          unless (member id existing :test #'equalp)
            return (%make-tls13-server-ticket-key
                    :id id :secret (subseq material 4) :decrypt-until nil)
          finally (%tls13-server-fail :ticket-key-id-collision 80))))

(defun make-tls13-server-ticket-key-store
    (&key (random #'%tls13-server-default-random)
          (ticket-lifetime 86400))
  "Create a ticket-key store that multiple TLS server drivers can share.

RANDOM is called with a byte count and must return that many cryptographically
random octets. TICKET-LIFETIME is the maximum ticket lifetime in seconds."
  (unless (and (functionp random)
               (integerp ticket-lifetime)
               (<= 1 ticket-lifetime +tls13-server-ticket-max-lifetime+))
    (%tls13-server-fail :invalid-ticket-key-store-configuration 80))
  (let ((store (%make-tls13-server-ticket-key-store
                :random random :ticket-lifetime ticket-lifetime
                :previous nil :lock (%tls13-server-make-mutex
                                     "cl-tls-kit TLS ticket keys"))))
    (setf (tls13-server-ticket-key-store-current store)
          (%tls13-server-new-ticket-key store))
    store))

(defun %tls13-server-store-expire-previous (store now)
  (setf (tls13-server-ticket-key-store-previous store)
        (remove-if (lambda (key)
                     (and (%tls13-server-ticket-key-decrypt-until key)
                          (> now (%tls13-server-ticket-key-decrypt-until key))))
                   (tls13-server-ticket-key-store-previous store))))

(defun rotate-tls13-server-ticket-key-store
    (store &key (clock #'get-universal-time))
  "Rotate STORE's encryption key and retain old decrypt keys for ticket lifetime."
  (unless (and (typep store 'tls13-server-ticket-key-store)
               (functionp clock))
    (%tls13-server-fail :invalid-ticket-key-store 80))
  (%tls13-server-with-lock
   (tls13-server-ticket-key-store-lock store)
   (lambda ()
     (let* ((now (- (funcall clock) +tls13-server-unix-time-offset+))
            (old (tls13-server-ticket-key-store-current store)))
       (%tls13-server-store-expire-previous store now)
       (setf (%tls13-server-ticket-key-decrypt-until old)
             (+ now (tls13-server-ticket-key-store-ticket-lifetime store))
             (tls13-server-ticket-key-store-previous store)
             (cons old (tls13-server-ticket-key-store-previous store))
             (tls13-server-ticket-key-store-current store)
             (%tls13-server-new-ticket-key store)))))
  store)

(defun %tls13-server-current-ticket-key (store)
  (%tls13-server-with-lock
   (tls13-server-ticket-key-store-lock store)
   (lambda ()
     (let ((key (tls13-server-ticket-key-store-current store)))
       (values (copy-seq (%tls13-server-ticket-key-id key))
               (copy-seq (%tls13-server-ticket-key-secret key)))))))

(defun %tls13-server-find-ticket-key (store id now)
  (%tls13-server-with-lock
   (tls13-server-ticket-key-store-lock store)
   (lambda ()
     (let ((key (or (and (equalp id
                               (%tls13-server-ticket-key-id
                                (tls13-server-ticket-key-store-current store)))
                         (tls13-server-ticket-key-store-current store))
                    (find-if (lambda (candidate)
                               (and (equalp id (%tls13-server-ticket-key-id candidate))
                                    (or (null (%tls13-server-ticket-key-decrypt-until candidate))
                                        (<= now (%tls13-server-ticket-key-decrypt-until candidate)))))
                             (tls13-server-ticket-key-store-previous store)))))
       (and key (copy-seq (%tls13-server-ticket-key-secret key)))))))

(defun %tls13-server-clock-unix (driver)
  (- (funcall (tls13-server-driver-clock driver))
     +tls13-server-unix-time-offset+))

(defun %tls13-server-ticket-payload
    (issued lifetime age-add suite alpn hostname psk)
  (let* ((alpn-bytes (if alpn (map '(vector (unsigned-byte 8)) #'char-code alpn) #()))
         (hostname-bytes (if hostname
                             (map '(vector (unsigned-byte 8)) #'char-code hostname)
                             #()))
         (psk (%tls13-server-octets psk :invalid-ticket 80)))
    (%tls13-server-cat
     (vector 1) (%tls13-server-u64 issued) (%tls13-server-u32 lifetime)
     (%tls13-server-u32 age-add) (%tls13-server-u16 suite)
     (%encode-vector alpn-bytes 1) (%encode-vector hostname-bytes 1)
     (%encode-vector psk 1))))

(defun %tls13-server-octets-string (bytes)
  (unless (%tls13-server-octets-p bytes)
    (%tls13-server-fail :malformed-ticket 47))
  (map 'string #'code-char bytes))

(defun %tls13-server-decode-ticket-payload (driver bytes)
  (unless (and (%tls13-server-octets-p bytes) (>= (length bytes) 22)
               (= (aref bytes 0) 1))
    (%tls13-server-fail :malformed-ticket 47))
  (let* ((issued (%tls13-server-read-u64 bytes 1))
         (lifetime (%tls13-server-read-u32 bytes 9))
         (age-add (%tls13-server-read-u32 bytes 13))
         (suite (%tls13-server-read-u16 bytes 17)))
    (multiple-value-bind (alpn-bytes p1) (%read-vector bytes 19 1 :maximum 255)
      (multiple-value-bind (hostname-bytes p2) (%read-vector bytes p1 1 :maximum 255)
        (multiple-value-bind (psk p3) (%read-vector bytes p2 1 :minimum 32 :maximum 48)
          (%finish bytes p3)
          (unless (and (<= 1 lifetime +tls13-server-ticket-max-lifetime+)
                       (tls13-cipher-suite-name suite)
                       (= (length psk) (%tls13-hash-length
                                        (tls13-server-driver-provider driver)
                                        (tls13-cipher-suite-hash suite))))
            (%tls13-server-fail :malformed-ticket 47))
          (list :issued issued :lifetime lifetime :age-add age-add
                :suite suite :alpn (unless (zerop (length alpn-bytes))
                                     (%tls13-server-octets-string alpn-bytes))
                :hostname (unless (zerop (length hostname-bytes))
                            (%tls13-server-octets-string hostname-bytes))
                :psk (copy-seq psk)))))))

(defun %tls13-server-default-suites ()
  #( #x1301 #x1302 #x1303 #x1304))

(defun %tls13-server-default-groups ()
  '(#x001d #x0017))

(defun %tls13-server-valid-alpn-list (protocols)
  (unless (or (null protocols) (and (listp protocols) (every #'stringp protocols)))
    (%tls13-server-fail :invalid-alpn-configuration 80))
  (dolist (protocol protocols)
    (let ((octets (handler-case (%tls13-server-octets
                                (%tls13-extension-string-octets protocol "ALPN")
                                :invalid-alpn-configuration 80)
                    (error () (%tls13-server-fail :invalid-alpn-configuration 80)))))
      (unless (and (<= 1 (length octets) 255)
                   (not (find #\Null protocol)))
        (%tls13-server-fail :invalid-alpn-configuration 80))))
  (when (/= (length protocols) (length (remove-duplicates protocols :test #'string=)))
    (%tls13-server-fail :duplicate-alpn-protocol 80))
  (copy-list protocols))

(defun %tls13-server-validate-options (provider groups suites)
  (unless (typep provider 'tls13-crypto-provider)
    (%tls13-server-fail :invalid-crypto-provider 80))
  (unless (and (listp groups) groups
               (every (lambda (group) (member group '(#x001d #x0017))) groups)
               (= (length groups) (length (remove-duplicates groups))))
    (%tls13-server-fail :invalid-supported-groups 80))
  (unless (and (vectorp suites) (plusp (length suites))
               (every (lambda (suite) (member suite '(#x1301 #x1302 #x1303 #x1304))) suites)
               (= (length suites) (length (remove-duplicates (coerce suites 'list)))))
    (%tls13-server-fail :invalid-cipher-suites 80)))

(defun make-tls13-server-driver
    (&key provider certificate-chain private-key alpn-protocols sni-callback
          ticket-key-store (supported-groups (%tls13-server-default-groups))
          (cipher-suites (%tls13-server-default-suites))
          (clock (function get-universal-time))
          (random (function %tls13-server-default-random)))
  "Create a socket-independent TLS 1.3 server handshake driver."
  (unless (and (functionp clock) (functionp random)
               (or (null sni-callback) (functionp sni-callback)))
    (%tls13-server-fail :invalid-server-driver-configuration 80))
  (%tls13-server-validate-options provider supported-groups cipher-suites)
  (%tls13-server-eager-p256-initialization)
  (let* ((chain (%tls13-server-validate-credential certificate-chain private-key))
         (store (or ticket-key-store (make-tls13-server-ticket-key-store)))
         (exchange (%tls13-server-key-exchange-default random)))
    (unless (typep store (quote tls13-server-ticket-key-store))
      (%tls13-server-fail :invalid-server-driver-configuration 80))
    (%make-tls13-server-driver
     :provider provider :certificate-chain chain :private-key private-key
     :alpn-protocols (%tls13-server-valid-alpn-list alpn-protocols)
     :sni-callback sni-callback :ticket-key-store store
     :supported-groups (copy-list supported-groups)
     :cipher-suites (copy-seq cipher-suites) :clock clock :random random
     :key-exchange exchange)))

(defun %tls13-server-validate-credential (chain private-key)
  (unless (and (listp chain) chain (every #'%tls13-server-octets-p chain))
    (%tls13-server-fail :invalid-certificate-chain 80))
  (let* ((package (or (find-package "CRYPTO-KIT")
                      (find-package "CL-CRYPTO-KIT")))
         (public-operation (and package (find-symbol "PRIVATE-KEY-PUBLIC-KEY" package)))
         (public (and public-operation (fboundp public-operation)
                      (handler-case
                          (funcall (symbol-function public-operation) private-key)
                        (error () nil))))
         (public-type (and package (find-symbol "EC-PUBLIC-KEY" package)))
         (ed-type (and package (find-symbol "ED25519-PUBLIC-KEY" package))))
    (unless public (%tls13-server-fail :invalid-private-key 80))
    (let* ((leaf (handler-case (cl-tls-kit.x509:parse-certificate-der (first chain))
                   (error () (%tls13-server-fail :invalid-leaf-certificate 80))))
           (certificate-key (cl-tls-kit.x509:x509-certificate-public-key leaf))
           (key-type (cl-tls-kit.x509:x509-public-key-type certificate-key)))
      (dolist (der (rest chain))
        (handler-case (cl-tls-kit.x509:parse-certificate-der der)
          (error () (%tls13-server-fail :invalid-certificate-chain 80))))
      (cond
        ((and public-type (typep public public-type) (eq key-type :ec)
              (string= (cl-tls-kit.x509:x509-ec-public-key-curve certificate-key)
                       "1.2.840.10045.3.1.7"))
         (let ((point-symbol (find-symbol "EC-PUBLIC-KEY-POINT" package)))
           (unless (and point-symbol (fboundp point-symbol)
                        (equalp (funcall (symbol-function point-symbol) public)
                                (cl-tls-kit.x509:x509-ec-public-key-point certificate-key)))
             (%tls13-server-fail :certificate-private-key-mismatch 80))))
        ((and ed-type (typep public ed-type) (eq key-type :ed25519))
         (let ((point-symbol (find-symbol "ED25519-PUBLIC-KEY-OCTETS" package)))
           (unless (and point-symbol (fboundp point-symbol)
                        (equalp (funcall (symbol-function point-symbol) public)
                                (cl-tls-kit.x509:x509-ed25519-public-key-point certificate-key)))
             (%tls13-server-fail :certificate-private-key-mismatch 80))))
        (t (%tls13-server-fail :unsupported-server-credential 80))))
  (mapcar #'copy-seq chain)))

(defun %tls13-server-signature-scheme (private-key)
  (let* ((package (find-package (symbol-package (type-of private-key))))
         (ec-type (and package (find-symbol "EC-PRIVATE-KEY" package)))
         (ed-type (and package (find-symbol "ED25519-PRIVATE-KEY" package))))
    (cond ((and ec-type (typep private-key ec-type)) #x0403)
          ((and ed-type (typep private-key ed-type)) #x0807)
          (t nil))))

(defun %tls13-server-select-credential (driver hostname)
  (multiple-value-bind (chain private-key)
      (if (tls13-server-driver-sni-callback driver)
          (funcall (tls13-server-driver-sni-callback driver) hostname)
          (values nil nil))
    (unless chain
      (setf chain (tls13-server-driver-certificate-chain driver)
            private-key (tls13-server-driver-private-key driver)))
    (values (%tls13-server-validate-credential chain private-key) private-key)))

(defun %tls13-server-unique-p (values) (let ((seen (make-hash-table :test (function equalp)))) (dolist (value values t) (when (gethash value seen) (return-from %tls13-server-unique-p nil)) (setf (gethash value seen) t))))

(defun %tls13-server-extension-u16-list (extension &optional (alert 47))
  (unless extension (%tls13-server-fail :missing-extension alert))
  (%tls13-server-vector-u16 (tls-extension-data extension) 50))

(defun %tls13-server-extension-u8-list (extension &optional (alert 47))
  (unless extension (%tls13-server-fail :missing-extension alert))
  (unless (%tls13-server-octets-p (tls-extension-data extension))
    (%tls13-server-fail :malformed-extension 50))
  (let* ((data (tls-extension-data extension))
         (length (and (plusp (length data)) (aref data 0))))
    (unless (and length (plusp length) (= length (1- (length data))))
      (%tls13-server-fail :malformed-extension 50))
    (coerce (subseq data 1) 'list)))

(defun %tls13-server-supported-versions (extension)
  (unless extension (%tls13-server-fail :tls13-not-supported 70))
  (let ((data (tls-extension-data extension)))
    (unless (and (%tls13-server-octets-p data)
                 (>= (length data) 3)
                 (= (aref data 0) (1- (length data)))
                 (evenp (aref data 0)))
      (%tls13-server-fail :malformed-extension 50))
    (loop for position from 1 below (length data) by 2
          collect (%tls13-server-read-u16 data position))))

(defun %tls13-server-clienthello-fields (hello)
  (let* ((extensions (tls13-client-hello-extensions hello))
         (versions-extension (%tls13-server-extension extensions 43))
         (versions (%tls13-server-supported-versions versions-extension)))
    (unless (member #x0304 versions)
      (%tls13-server-fail :tls13-not-supported 70))
    (let* ((groups (%tls13-server-extension-u16-list
                    (%tls13-server-extension extensions 10) 109))
           (schemes (%tls13-server-extension-u16-list
                     (%tls13-server-extension extensions 13) 109))
           (key-share-extension
             (or (%tls13-server-extension extensions 51)
                 (%tls13-server-fail :missing-extension 109)))
           (shares (decode-key-share-extension
                    (tls-extension-data key-share-extension)))
           (alpn-extension (%tls13-server-extension extensions 16))
           (alpn (and alpn-extension
                      (decode-alpn-extension (tls-extension-data alpn-extension))))
           (sni-extension (%tls13-server-extension extensions 0))
           (hostname (and sni-extension
                          (decode-sni-extension (tls-extension-data sni-extension))))
           (modes-extension (%tls13-server-extension extensions 45))
           (modes (and modes-extension
                       (%tls13-server-extension-u8-list modes-extension))))
      (when (and (%tls13-server-extension extensions 41)
                 (null modes-extension))
        (%tls13-server-fail :missing-extension 109))
      (unless (and (%tls13-server-unique-p groups)
                   (%tls13-server-unique-p schemes)
                   (%tls13-server-unique-p (mapcar #'car shares)))
        (%tls13-server-fail :duplicate-negotiation-value 47))
      (list :extensions extensions :groups groups :schemes schemes
            :shares shares :alpn alpn :hostname hostname :modes modes))))

(defun %tls13-server-select-alpn (driver offered)
  (cond ((null offered) nil)
        ((loop for protocol in (tls13-server-driver-alpn-protocols driver)
               when (member protocol offered :test #'string=) return protocol))
        (t (%tls13-server-fail :no-application-protocol 120))))

(defun %tls13-server-select-suite (driver hello)
  (or (loop for suite across (tls13-server-driver-cipher-suites driver)
            when (find suite (tls13-client-hello-cipher-suites hello)) return suite)
      (%tls13-server-fail :no-common-cipher-suite 40)))

(defun %tls13-server-select-group (driver offered-groups)
  (or (find-if (lambda (group) (member group offered-groups))
               (tls13-server-driver-supported-groups driver))
      (%tls13-server-fail :no-common-supported-group 40)))

(defun %tls13-server-select-signature (driver key schemes)
  (declare (ignore driver))
  (let ((scheme (%tls13-server-signature-scheme key)))
    (unless (and scheme (member scheme schemes))
      (%tls13-server-fail :no-common-signature-scheme 40))
    scheme))

(defun %tls13-server-cookie-value (extension)
  (unless extension (%tls13-server-fail :missing-hrr-cookie 47))
  (multiple-value-bind (cookie end)
      (%read-vector (tls-extension-data extension) 0 2 :minimum 1)
    (%finish (tls-extension-data extension) end)
    cookie))

(defun %tls13-server-psk-fields (extension)
  (when extension
    (let ((bytes (tls-extension-data extension)))
      (multiple-value-bind (identities p1) (%read-vector bytes 0 2 :minimum 7)
        (let ((cursor 0) (parsed-identities '()))
          (loop while (< cursor (length identities)) do
            (multiple-value-bind (identity p2) (%read-vector identities cursor 2 :minimum 1)
              (multiple-value-bind (age p3) (%read-integer identities p2 4)
                (push (list :identity identity :age age) parsed-identities)
                (setf cursor p3))))
          (multiple-value-bind (binders p2) (%read-vector bytes p1 2 :minimum 33)
            (let ((cursor 0) (parsed-binders '()))
              (loop while (< cursor (length binders)) do
                (multiple-value-bind (binder p3) (%read-vector binders cursor 1 :minimum 32)
                  (push binder parsed-binders)
                  (setf cursor p3)))
              (%finish bytes p2)
              (unless (= (length parsed-identities) (length parsed-binders))
                (%tls13-server-fail :psk-identity-binder-count-mismatch 47))
              (unless (= (length parsed-identities) 1)
                (%tls13-server-fail :multiple-psk-identities-unsupported 47))
              (list :identity (getf (first parsed-identities) :identity)
                    :age (getf (first parsed-identities) :age)
                    :binder (first parsed-binders)
                    :identities-end p1)))))))) (defun %tls13-server-psk-prefix-length (wire)
  (let* ((hello (%tls13-server-parse-client-hello wire))
         (extensions (tls13-client-hello-extensions hello))
         (psk-extension (%tls13-server-extension extensions 41)))
    (unless psk-extension
      (%tls13-server-fail :missing-psk-extension 47))
    (let* ((psk-fields (%tls13-server-psk-fields psk-extension))
           (extensions-before-psk
             (loop for extension in extensions
                   while (not (eq extension psk-extension))
                   sum (+ 4 (length (tls-extension-data extension)))))
           (session-id-length
             (length (tls13-client-hello-session-id hello)))
           (cipher-suite-count
             (length (tls13-client-hello-cipher-suites hello))))
      (+ 4 2 32
         1 session-id-length
         2 (* 2 cipher-suite-count)
         2 2
         extensions-before-psk
         4
         (getf psk-fields :identities-end)))))

(defun %tls13-server-open-ticket (driver identity)
  (unless (and (%tls13-server-octets-p identity) (<= (length identity) 65536))
    (%tls13-server-fail :malformed-ticket 47))
  (when (< (length identity) 4)
    (return-from %tls13-server-open-ticket nil))
  (let* ((store (tls13-server-driver-ticket-key-store driver))
         (key-id (subseq identity 0 4))
         (now (%tls13-server-clock-unix driver))
         (key (%tls13-server-find-ticket-key store key-id now)))
    (unless key (return-from %tls13-server-open-ticket nil))
    (when (< (length identity) 32)
      (%tls13-server-fail :malformed-ticket 47))
    (let* ((nonce (subseq identity 4 16))
           (ciphertext (subseq identity 16))
           (aad (%tls13-server-cat #(99 108 45 116 108 115 45 107 105 116 45 116 105 99 107 101 116 45 118 49)
                                  key-id))
           (payload (handler-case
                        (tls13-aead-open (tls13-server-driver-provider driver)
                                         +tls13-server-ticket-aead+ key nonce ciphertext aad)
                      (error () nil))))
      (unless payload (return-from %tls13-server-open-ticket nil))
      (let* ((fields (%tls13-server-decode-ticket-payload driver payload))
             (issued (getf fields :issued))
             (lifetime (getf fields :lifetime)))
        (unless (and (<= issued now) (< (- now issued) lifetime))
          (%tls13-server-fail :expired-ticket 47))
        fields))))

(defun %tls13-server-validate-ticket-age (driver psk-fields ticket)
  (let* ((now (%tls13-server-clock-unix driver))
         (issued (getf ticket :issued))
         (actual-age (* 1000 (- now issued)))
         (obfuscated (getf psk-fields :age))
         (expected-age (mod (- obfuscated (getf ticket :age-add)) #x100000000)))
    (unless (and (<= 0 actual-age)
                 (<= (abs (- expected-age actual-age))
                     +tls13-server-ticket-age-tolerance-ms+))
      (%tls13-server-fail :invalid-ticket-age 47))))

(defun %tls13-server-validate-psk
    (driver hello wire transcript-prefix suite fields selected-alpn)
  (let ((extension (%tls13-server-extension (tls13-client-hello-extensions hello) 41)))
    (when (and (%tls13-server-extension (tls13-client-hello-extensions hello) 42)
               (plusp (length (tls-extension-data
                               (%tls13-server-extension
                                (tls13-client-hello-extensions hello) 42)))))
      (%tls13-server-fail :malformed-early-data-extension 50))
    (when (and (%tls13-server-extension (tls13-client-hello-extensions hello) 42)
               (null extension))
      (%tls13-server-fail :early-data-without-psk 47))
    (when extension
      (unless (and (member 1 (getf fields :modes))
                   (tls13-server-driver-ticket-key-store driver))
        (%tls13-server-fail :psk-dhe-ke-not-offered 40))
      (let* ((psk-fields (%tls13-server-psk-fields extension))
             (ticket (%tls13-server-open-ticket driver (getf psk-fields :identity)))
             (ticket-suite (and ticket (getf ticket :suite))))
        (when ticket
          (unless (eq (tls13-cipher-suite-hash suite)
                      (tls13-cipher-suite-hash ticket-suite))
            (%tls13-server-fail :psk-hash-mismatch 47))
          (%tls13-server-validate-ticket-age driver psk-fields ticket)
          (unless (equal (getf ticket :alpn) selected-alpn)
            (%tls13-server-fail :psk-alpn-mismatch 47))
          (unless (equal (getf ticket :hostname) (getf fields :hostname))
            (%tls13-server-fail :psk-server-name-mismatch 47))
          (let* ((hash (tls13-cipher-suite-hash ticket-suite))
                 (early-secret (tls13-early-secret (tls13-server-driver-provider driver)
                                                   hash (getf ticket :psk)))
                 (binder-key (tls13-derive-secret
                              (tls13-server-driver-provider driver) hash early-secret
                              "res binder"
                              (tls13-empty-hash (tls13-server-driver-provider driver) hash)))
                 (finished-key (tls13-finished-key (tls13-server-driver-provider driver)
                                                   hash binder-key))
                 (prefix-length (%tls13-server-psk-prefix-length wire))
                 (binder-transcript
                   (%tls13-server-cat transcript-prefix (subseq wire 0 prefix-length)))
                 (expected (tls13-compute-finished-verify-data
                            (tls13-server-driver-provider driver) hash finished-key
                            (%tls13-server-digest-hash driver hash binder-transcript))))
            (unless (tls13-provider-constant-time-equal-p
                     (tls13-server-driver-provider driver) expected
                     (getf psk-fields :binder))
              (%tls13-server-fail :psk-binder-mismatch 51)))
          (setf (getf ticket :age) (getf psk-fields :age)
                (getf ticket :identity) (copy-seq (getf psk-fields :identity)))
          ticket)))))

(defun %tls13-server-error-alert (condition)
  (typecase condition
    (tls13-server-driver-error (%tls13-server-driver-error-alert condition))
    (tls13-error
     (if (search "duplicate extension" (tls13-error-message condition)) 47 50))
    (otherwise 80)))

(defun %tls13-server-alert-events (description &optional (level :initial))
  (list (list :type :send :level level :content-type :alert
              :wire (vector 2 description))
        (list :type :alert :description description)))

(defun %tls13-server-parse-client-hello (wire)
  (unless (and (%tls13-server-octets-p wire)
               (<= 4 (length wire) +tls13-server-max-handshake-size+)
               (= (aref wire 0) 1)
               (= (%tls13-server-read-u24 wire 1) (- (length wire) 4)))
    (%tls13-server-fail :malformed-client-hello 50))
  (handler-case
      (let ((hello (decode-client-hello (subseq wire 4))))
        (unless (= (tls13-client-hello-legacy-version hello) #x0303)
          (%tls13-server-fail :invalid-legacy-version 70))
        hello)
    (tls13-server-driver-error (condition) (error condition))
    (tls13-error (condition)
      (%tls13-server-fail
       (if (search "duplicate extension" (tls13-error-message condition))
           :duplicate-extension :malformed-client-hello)
       (if (search "duplicate extension" (tls13-error-message condition)) 47 50)))
    (error () (%tls13-server-fail :malformed-client-hello 50))))

(defun %tls13-server-extension-alist (extensions)
  (mapcar (lambda (extension)
            (cons (tls-extension-type extension)
                  (copy-seq (tls-extension-data extension))))
          extensions))

(defun %tls13-server-check-second-client-hello (driver hello fields wire)
  (declare (ignore wire))
  (let* ((first-hello (tls13-server-driver-initial-client-hello driver))
         (first-fields (%tls13-server-clienthello-fields first-hello))
         (cookie-extension (%tls13-server-extension (getf fields :extensions) 44))
         (cookie (%tls13-server-cookie-value cookie-extension))
         (first-extensions (%tls13-server-extension-alist
                            (tls13-client-hello-extensions first-hello)))
         (second-extensions (%tls13-server-extension-alist
                             (tls13-client-hello-extensions hello))))
    (unless (and (= (tls13-client-hello-legacy-version hello)
                    (tls13-client-hello-legacy-version first-hello))
                 (equalp (tls13-client-hello-random hello)
                         (tls13-client-hello-random first-hello))
                 (equalp (tls13-client-hello-session-id hello)
                         (tls13-client-hello-session-id first-hello))
                 (equalp (tls13-client-hello-cipher-suites hello)
                         (tls13-client-hello-cipher-suites first-hello))
                 (equalp cookie (tls13-server-driver-cookie driver))
                 (not (%tls13-server-extension (getf fields :extensions) 42)))
      (%tls13-server-fail :invalid-second-client-hello 47))
    (let ((mutable '(21 41 42 44 51)))
      (dolist (entry first-extensions)
        (unless (or (member (car entry) mutable)
                    (equalp entry (assoc (car entry) second-extensions)))
          (%tls13-server-fail :inconsistent-second-client-hello 47)))
      (dolist (entry second-extensions)
        (unless (or (member (car entry) mutable)
                    (assoc (car entry) first-extensions))
          (%tls13-server-fail :inconsistent-second-client-hello 47))))
    (let ((first-psk (%tls13-server-extension (getf first-fields :extensions) 41))
          (second-psk (%tls13-server-extension (getf fields :extensions) 41)))
      (when (not (eq (null first-psk) (null second-psk)))
        (%tls13-server-fail :inconsistent-second-client-hello 47))
      (when first-psk
        (let ((first-data (%tls13-server-psk-fields first-psk))
              (second-data (%tls13-server-psk-fields second-psk)))
          (unless (and (equalp (getf first-data :identity) (getf second-data :identity))
                       (= (getf first-data :age) (getf second-data :age)))
            (%tls13-server-fail :inconsistent-second-client-hello 47)))))
    t))

(defun %tls13-server-key-share-size-valid-p (group share)
  (case group
    (#x001d (= (length share) 32))
    (#x0017 (and (= (length share) 65) (= (aref share 0) 4)))
    (otherwise nil)))

(defun %tls13-server-share-secret (driver group private peer)
  (unless (%tls13-server-key-share-size-valid-p group peer)
    (%tls13-server-fail :invalid-key-share 47))
  (handler-case
      (let ((secret (funcall (%tls13-server-key-exchange-operation driver :shared-secret)
                             group private peer)))
        (unless (and (%tls13-server-octets-p secret)
                     (= (length secret) 32)
                     (some (lambda (octet) (plusp octet)) secret))
          (%tls13-server-fail :invalid-key-share 47))
        secret)
    (tls13-server-driver-error (condition) (error condition))
    (error () (%tls13-server-fail :invalid-key-share 47))))

(defun %tls13-server-generate-share (driver group)
  (handler-case
      (multiple-value-bind (private public)
          (funcall (%tls13-server-key-exchange-operation driver :generate) group)
        (unless (and (%tls13-server-octets-p public)
                     (%tls13-server-key-share-size-valid-p group public)
                     (some (lambda (octet) (plusp octet)) public))
          (%tls13-server-fail :invalid-server-key-share 80))
        (values private public))
    (tls13-server-driver-error (condition) (error condition))
    (error () (%tls13-server-fail :key-exchange-failed 80))))

(defun %tls13-server-ticket-aad (key-id)
  (%tls13-server-cat #(99 108 45 116 108 115 45 107 105 116 45 116 105 99 107
                       101 116 45 118 49)
                     key-id))

(defun %tls13-server-seal-ticket (driver payload)
  (multiple-value-bind (key-id key)
      (%tls13-server-current-ticket-key (tls13-server-driver-ticket-key-store driver))
    (let* ((nonce (%tls13-server-random driver 12))
           (ciphertext (tls13-aead-seal (tls13-server-driver-provider driver)
                                        +tls13-server-ticket-aead+ key nonce payload
                                        (%tls13-server-ticket-aad key-id))))
      (%tls13-server-cat key-id nonce ciphertext))))

(defun %tls13-server-issue-ticket (driver resumption-master-secret)
  (let* ((store (tls13-server-driver-ticket-key-store driver))
         (issued (%tls13-server-clock-unix driver))
         (lifetime (tls13-server-ticket-key-store-ticket-lifetime store))
         (age-add (%tls13-server-read-u32 (%tls13-server-random driver 4) 0))
         (nonce (%tls13-server-random driver 8))
         (psk (tls13-resumption-psk
               (tls13-server-driver-provider driver)
               (tls13-server-driver-hash driver)
               resumption-master-secret nonce))
         (payload (%tls13-server-ticket-payload
                   issued lifetime age-add (tls13-server-driver-selected-suite driver)
                   (tls13-server-driver-selected-alpn driver)
                   (tls13-server-driver-sni-hostname driver) psk))
         (identity (%tls13-server-seal-ticket driver payload))
         (message (encode-handshake
                   4 (make-tls13-new-session-ticket lifetime nonce identity nil age-add))))
    (values message
            (list :type :ticket-issued :identity (copy-seq identity)
                  :lifetime lifetime))))

(defun %tls13-server-send-event (level wire &optional (content-type :handshake))
  (list :type :send :level level :content-type content-type :wire wire))

(defun %tls13-server-secret-event (direction level secret)
  (list :type :secret :direction direction :level level :secret (copy-seq secret)))

(defun %tls13-server-alert-level (driver)
  (if (eq (tls13-server-driver-state driver) :awaiting-client-finished)
      :handshake
      :initial))

(defun %tls13-server-handshake-transcript (prefix &rest messages)
  (apply #'%tls13-server-cat prefix messages))
(progn
  (defun %tls13-server-finish-flight (driver transcript-before-finished)
    (let* ((provider (tls13-server-driver-provider driver))
           (hash (tls13-server-driver-hash driver))
           (server-finished-key
             (tls13-finished-key
              provider hash (tls13-server-driver-server-handshake-secret driver)))
           (server-finished-data
             (tls13-compute-finished-verify-data
              provider hash server-finished-key
              (%tls13-server-digest-hash driver hash transcript-before-finished)))
           (server-finished-wire
             (encode-handshake 20 (make-tls13-finished server-finished-data)))
           (transcript-through-finished
             (%tls13-server-handshake-transcript transcript-before-finished
                                                 server-finished-wire))
           (application-transcript-hash
             (%tls13-server-digest-hash driver hash transcript-through-finished))
           (client-application-secret
             (tls13-traffic-secret
              provider hash (tls13-server-driver-master-secret driver) :client
              application-transcript-hash :phase :application))
           (server-application-secret
             (tls13-traffic-secret
              provider hash (tls13-server-driver-master-secret driver) :server
              application-transcript-hash :phase :application)))
      (setf (tls13-server-driver-transcript driver) transcript-through-finished
            (tls13-server-driver-client-application-secret driver)
            client-application-secret
            (tls13-server-driver-server-application-secret driver)
            server-application-secret)
      server-finished-wire)))

(defun %tls13-server-build-flight (driver hello hello-fields hello-wire transcript-prefix
                                   suite group share alpn credential-chain credential-key
                                   signature-scheme ticket)
  (multiple-value-bind (server-private server-share)
      (%tls13-server-generate-share driver group)
    (let* ((dhe (%tls13-server-share-secret driver group server-private share))
           (hash (tls13-cipher-suite-hash suite))
           (psk (and ticket (getf ticket :psk)))
           (provider (tls13-server-driver-provider driver))
           (early-secret
             (unwind-protect
                  (tls13-early-secret provider hash psk)
               (when psk (fill psk 0))))
           (handshake-secret (tls13-handshake-secret provider hash early-secret dhe))
           (server-random (%tls13-server-random driver 32))
           (server-hello-extensions
             (append
              (list (make-tls-extension 51
                                        (encode-key-share-server-extension group server-share))
                    (make-tls-extension 43 #(3 4)))
              (when ticket (list (make-tls-extension 41 #(0 0))))))
           (server-hello (make-tls13-server-hello
                          #x0303 server-random
                          (tls13-client-hello-session-id hello) suite
                          server-hello-extensions))
           (server-hello-wire (encode-handshake 2 server-hello))
           (transcript-through-server-hello
             (%tls13-server-handshake-transcript transcript-prefix hello-wire
                                                 server-hello-wire))
           (transcript-hash (%tls13-server-digest-hash driver hash
                                                      transcript-through-server-hello))
           (client-handshake-secret (tls13-traffic-secret
                                     provider hash handshake-secret :client transcript-hash))
           (server-handshake-secret (tls13-traffic-secret
                                     provider hash handshake-secret :server transcript-hash))
           (encrypted-extensions-wire
             (encode-handshake
              8 (make-tls13-encrypted-extensions
                 (append
                  (list
                   (make-tls-extension
                    10
                    (%encode-vector
                     (apply #'%cat
                            (mapcar #'%tls13-server-u16
                                    (tls13-server-driver-supported-groups driver)))
                     2)))
                  (when alpn
                    (list (make-tls-extension
                           16 (encode-alpn-extension (list alpn)))))))))
           (certificate-wire
             (and (null ticket)
                  (encode-handshake
                   11 (make-tls13-certificate
                       #() (mapcar (lambda (der)
                                    (make-tls13-certificate-entry der nil))
                                  credential-chain)))))
           (transcript-through-certificate
             (%tls13-server-handshake-transcript transcript-through-server-hello
                                                 encrypted-extensions-wire
                                                 (or certificate-wire #())))
           (certificate-verify-wire
             (when certificate-wire
               (let* ((signature-input (tls13-certificate-verify-signature-input
                                        :server
                                        (%tls13-server-digest-hash
                                         driver hash transcript-through-certificate)))
                      (scheme-name (if (= signature-scheme #x0403)
                                       :ecdsa-p256-sha256 :ed25519))
                      (signature
                        (handler-case
                            (funcall (%tls13-server-crypto-operation "SIGN-MESSAGE")
                                     scheme-name credential-key signature-input)
                          (error () (%tls13-server-fail :certificate-verify-signing-failed 80)))))
                 (encode-handshake
                  15 (make-tls13-certificate-verify signature-scheme signature)))))
           (transcript-before-finished
             (%tls13-server-handshake-transcript transcript-through-certificate
                                                 (or certificate-verify-wire #())))
           (server-finished-wire
             (progn
               (setf (tls13-server-driver-hash driver) hash
                     (tls13-server-driver-server-handshake-secret driver)
                     server-handshake-secret
                     (tls13-server-driver-master-secret driver)
                     (tls13-master-secret provider hash handshake-secret)
                     (tls13-server-driver-server-flight-prefix driver)
                     transcript-through-server-hello)
               (%tls13-server-finish-flight driver transcript-before-finished)))
           (client-finished-key (tls13-finished-key
                                 provider hash client-handshake-secret))
           (events (append
                    (list (list :type :cipher-suite :suite suite)
                          (%tls13-server-send-event :initial server-hello-wire)
                          (%tls13-server-secret-event :read :handshake
                                                      client-handshake-secret)
                          (%tls13-server-secret-event :write :handshake
                                                      server-handshake-secret))
                    (when alpn (list (list :type :alpn :protocol alpn)))
                    (list (%tls13-server-send-event :handshake encrypted-extensions-wire))
                    (when certificate-wire
                      (list (%tls13-server-send-event :handshake certificate-wire)
                            (%tls13-server-send-event :handshake certificate-verify-wire)))
                    (list (%tls13-server-send-event :handshake server-finished-wire)))))
      (setf (tls13-server-driver-selected-suite driver) suite
            (tls13-server-driver-hash driver) hash
            (tls13-server-driver-selected-group driver) group
            (tls13-server-driver-selected-alpn driver) alpn
            (tls13-server-driver-sni-hostname driver) (getf hello-fields :hostname)
            (tls13-server-driver-resumed-p driver) (not (null ticket))
            (tls13-server-driver-client-handshake-secret driver) client-handshake-secret
            (tls13-server-driver-server-handshake-secret driver) server-handshake-secret
            (tls13-server-driver-client-finished-key driver) client-finished-key
            (tls13-server-driver-resumption-master-secret driver) nil
            (tls13-server-driver-state driver) :awaiting-client-finished)
      events)))

(defun %tls13-server-retry-request (driver hello wire suite group)
  (let* ((cookie (%tls13-server-random driver 32))
         (cookie-data (%tls13-server-cat (%tls13-server-u16 (length cookie)) cookie))
         (hrr-wire
           (encode-handshake
            2 (make-tls13-server-hello
               #x0303 *tls13-hrr-random*
               (tls13-client-hello-session-id hello) suite
               (list (make-tls-extension 43 #(3 4))
                     (make-tls-extension 51 (%tls13-server-u16 group))
                     (make-tls-extension 44 cookie-data)))))
         (hash (tls13-cipher-suite-hash suite))
         (hash-of-first (%tls13-server-digest-hash driver hash wire))
         (message-hash (%tls13-server-message #xfe hash-of-first))
         (transcript (%tls13-server-cat message-hash hrr-wire)))
    (setf (tls13-server-driver-initial-client-hello driver) hello
          (tls13-server-driver-cookie driver) cookie
          (tls13-server-driver-hrr-seen-p driver) t
          (tls13-server-driver-selected-suite driver) suite
          (tls13-server-driver-hash driver) hash
          (tls13-server-driver-selected-group driver) group
          (tls13-server-driver-transcript driver) transcript
          (tls13-server-driver-state driver) :awaiting-second-client-hello)
    (list (%tls13-server-send-event :initial hrr-wire))))

(defun %tls13-server-process-client-hello (driver wire)
  (let* ((hello (%tls13-server-parse-client-hello wire))
         (fields (%tls13-server-clienthello-fields hello))
         (second-p (eq (tls13-server-driver-state driver) :awaiting-second-client-hello))
         (transcript-prefix (if second-p (tls13-server-driver-transcript driver) #()))
         (suite (%tls13-server-select-suite driver hello))
         (group (%tls13-server-select-group driver (getf fields :groups)))
         (alpn (%tls13-server-select-alpn driver (getf fields :alpn)))
         (psk (%tls13-server-validate-psk driver hello wire transcript-prefix suite
                                          fields alpn))
         (cookie-extension (%tls13-server-extension (getf fields :extensions) 44))
         (share-pair (find group (getf fields :shares) :key #'car)))
    (unless (= (tls13-client-hello-legacy-version hello) #x0303)
      (%tls13-server-fail :invalid-legacy-version 70))
    (when second-p
      (%tls13-server-check-second-client-hello driver hello fields wire)
      (unless (and share-pair (= group (tls13-server-driver-selected-group driver)))
        (%tls13-server-fail :invalid-retry-key-share 47)))
    (when (and (not second-p) cookie-extension)
      (%tls13-server-fail :unexpected-cookie-extension 47))
    (unless share-pair
      (return-from %tls13-server-process-client-hello
        (%tls13-server-retry-request driver hello wire suite group)))
    (let* ((scheme (unless psk
                     (multiple-value-bind (chain key)
                         (%tls13-server-select-credential driver (getf fields :hostname))
                       (setf (getf fields :selected-chain) chain
                             (getf fields :selected-key) key)
                       (%tls13-server-select-signature driver key (getf fields :schemes)))))
           (chain (getf fields :selected-chain))
           (key (getf fields :selected-key)))
      (%tls13-server-build-flight driver hello fields wire transcript-prefix suite group
                                   (cdr share-pair) alpn chain key scheme psk))))

(defun %tls13-server-process-finished (driver wire)
  (unless (and (%tls13-server-octets-p wire) (>= (length wire) 4)
               (= (aref wire 0) 20)
               (= (%tls13-server-read-u24 wire 1) (- (length wire) 4)))
    (%tls13-server-fail :malformed-finished 50))
  (let* ((finished (handler-case (decode-finished (subseq wire 4))
                     (error () (%tls13-server-fail :malformed-finished 50))))
         (expected (tls13-compute-finished-verify-data
                    (tls13-server-driver-provider driver)
                    (tls13-server-driver-hash driver)
                    (tls13-server-driver-client-finished-key driver)
                    (%tls13-server-digest driver
                                          (tls13-server-driver-transcript driver)))))
    (unless (tls13-provider-constant-time-equal-p
             (tls13-server-driver-provider driver) expected
             (tls13-finished-verify-data finished))
      (%tls13-server-fail :client-finished-mismatch 51))
    (let* ((transcript (%tls13-server-cat (tls13-server-driver-transcript driver) wire))
           (resumption-master
             (tls13-resumption-secret
              (tls13-server-driver-provider driver)
              (tls13-server-driver-hash driver)
              (tls13-server-driver-master-secret driver)
              (%tls13-server-digest driver transcript))))
      (multiple-value-bind (ticket-wire metadata)
          (%tls13-server-issue-ticket driver resumption-master)
        (setf (tls13-server-driver-transcript driver) transcript
              (tls13-server-driver-resumption-master-secret driver) resumption-master
              (tls13-server-driver-state driver) :complete)
        (append
         (list (%tls13-server-secret-event
                :read :application
                (tls13-server-driver-client-application-secret driver))
               (%tls13-server-secret-event
                :write :application
                (tls13-server-driver-server-application-secret driver))
               (%tls13-server-send-event :application ticket-wire)
               metadata
               (list :type :handshake-complete
                     :resumed-p (not (null (tls13-server-driver-resumed-p driver))))))))))

(defun tls13-server-driver-step (driver wire &key level)
  "Consume one complete handshake message and return DRIVER and output events.

WIRE is raw TLS handshake framing, with the four-byte handshake header. LEVEL
is :INITIAL for ClientHello and :HANDSHAKE for the client's Finished."
  (unless (typep driver 'tls13-server-driver)
    (%tls13-server-fail :invalid-server-driver 80))
  (handler-case
      (values
       driver
       (cond
         ((member (tls13-server-driver-state driver)
                  '(:awaiting-client-hello :awaiting-second-client-hello))
          (unless (eq level :initial)
            (%tls13-server-fail :unexpected-encryption-level 10))
          (%tls13-server-process-client-hello driver wire))
         ((eq (tls13-server-driver-state driver) :awaiting-client-finished)
          (unless (eq level :handshake)
            (%tls13-server-fail :unexpected-encryption-level 10))
          (%tls13-server-process-finished driver wire))
         (t (%tls13-server-fail :unexpected-handshake-message 10))))
    (tls13-server-driver-error (condition)
      (values driver (%tls13-server-alert-events
                      (%tls13-server-driver-error-alert condition)
                      (%tls13-server-alert-level driver))))
    (tls13-error (condition)
      (values driver (%tls13-server-alert-events
                      (%tls13-server-error-alert condition)
                      (%tls13-server-alert-level driver))))
    (error (condition)
      (declare (ignore condition))
      (values driver (%tls13-server-alert-events
                      80 (%tls13-server-alert-level driver))))))
