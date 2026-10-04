(in-package #:cl-tls-kit)

;;; TLS 1.3 handshake wire codec.  This file deliberately does not depend on
;;; the crypto layer: hashes, signatures, and certificate validation belong to
;;; callers.  All parsers consume exactly one bounded vector and reject
;;; truncation, trailing bytes, duplicate extensions, and non-canonical
;;; vector lengths.

(define-condition tls13-error (error)
  ((message :initarg :message :reader tls13-error-message))
  (:report (lambda (condition stream)
             (format stream "TLS 1.3 error: ~A" (tls13-error-message condition)))))
(define-condition tls13-decode-error (tls13-error) ())
(define-condition tls13-state-error (tls13-error) ())

(defun %tls13-fail (message &optional (condition 'tls13-decode-error))
  (error condition :message message))

(defun %tls13-octets (value)
  (unless (and (vectorp value) (every (lambda (x) (typep x '(unsigned-byte 8))) value))
    (%tls13-fail "expected an (unsigned-byte 8) vector"))
  value)

(defun %hs-u8 (n)
  (unless (typep n '(integer 0 255)) (%tls13-fail "octet out of range"))
  (vector n))
(defun %hs-u16 (n)
  (unless (typep n '(integer 0 65535)) (%tls13-fail "uint16 out of range"))
  (vector (ldb (byte 8 8) n) (ldb (byte 8 0) n)))
(defun %u24 (n)
  (unless (typep n '(integer 0 16777215)) (%tls13-fail "uint24 out of range"))
  (vector (ldb (byte 8 16) n) (ldb (byte 8 8) n) (ldb (byte 8 0) n)))
(defun %u32 (n)
  (unless (typep n '(integer 0 4294967295)) (%tls13-fail "uint32 out of range"))
  (vector (ldb (byte 8 24) n) (ldb (byte 8 16) n)
          (ldb (byte 8 8) n) (ldb (byte 8 0) n)))
(defun %cat (&rest vectors)
  (apply #'concatenate '(vector (unsigned-byte 8)) vectors))
(defun %read-integer (bytes pos width)
  (when (> (+ pos width) (length bytes)) (%tls13-fail "truncated integer"))
  (let ((n 0))
    (dotimes (i width (values n (+ pos width)))
      (setf n (+ (ash n 8) (aref bytes (+ pos i)))))))
(defun %bounded (bytes pos length)
  (when (or (< length 0) (> (+ pos length) (length bytes)))
    (%tls13-fail "truncated vector"))
  (values (subseq bytes pos (+ pos length)) (+ pos length)))
(defun %read-vector (bytes pos width &key (minimum 0) (maximum nil))
  (multiple-value-bind (length next) (%read-integer bytes pos width)
    (when (< length minimum) (%tls13-fail "vector shorter than its minimum"))
    (when (and maximum (> length maximum)) (%tls13-fail "vector exceeds its maximum"))
    (%bounded bytes next length)))
(defun %encode-vector (bytes width &key (minimum 0) (maximum nil))
  (%tls13-octets bytes)
  (let ((length (length bytes)))
    (when (< length minimum) (%tls13-fail "vector shorter than its minimum"))
    (when (and maximum (> length maximum)) (%tls13-fail "vector exceeds its maximum"))
    (%cat (ecase width (1 (%hs-u8 length)) (2 (%hs-u16 length)) (3 (%u24 length))) bytes)))
(defun %finish (bytes pos)
  (unless (= pos (length bytes)) (%tls13-fail "trailing bytes"))
  bytes)

;;; TLS 1.3 cipher suites (RFC 8446, section 9.1).  The hash names are
;;; provider-neutral keywords; selecting or implementing the primitive is left
;;; to the caller.
(defconstant +tls13-cipher-suite-aes-128-gcm-sha256+ #x1301)
(defconstant +tls13-cipher-suite-aes-256-gcm-sha384+ #x1302)
(defconstant +tls13-cipher-suite-chacha20-poly1305-sha256+ #x1303)
(defconstant +tls13-cipher-suite-aes-128-ccm-sha256+ #x1304)
(defconstant +tls13-cipher-suite-aes-128-gcm-sha256-name+ :aes-128-gcm-sha256)
(defconstant +tls13-cipher-suite-aes-256-gcm-sha384-name+ :aes-256-gcm-sha384)
(defconstant +tls13-cipher-suite-chacha20-poly1305-sha256-name+ :chacha20-poly1305-sha256)
(defconstant +tls13-cipher-suite-aes-128-ccm-sha256-name+ :aes-128-ccm-sha256)
(defconstant +tls13-cipher-suite-aes-128-gcm-sha256-hash+ :sha256)
(defconstant +tls13-cipher-suite-aes-256-gcm-sha384-hash+ :sha384)
(defconstant +tls13-cipher-suite-chacha20-poly1305-sha256-hash+ :sha256)
(defconstant +tls13-cipher-suite-aes-128-ccm-sha256-hash+ :sha256)
(defconstant +tls13-cipher-suite-aes-128-gcm-sha256-key-length+ 16)
(defconstant +tls13-cipher-suite-aes-256-gcm-sha384-key-length+ 32)
(defconstant +tls13-cipher-suite-chacha20-poly1305-sha256-key-length+ 32)
(defconstant +tls13-cipher-suite-aes-128-ccm-sha256-key-length+ 16)

(defun tls13-cipher-suite-name (suite)
  (case suite
    (#x1301 +tls13-cipher-suite-aes-128-gcm-sha256-name+)
    (#x1302 +tls13-cipher-suite-aes-256-gcm-sha384-name+)
    (#x1303 +tls13-cipher-suite-chacha20-poly1305-sha256-name+)
    (#x1304 +tls13-cipher-suite-aes-128-ccm-sha256-name+)))
(defun tls13-cipher-suite-hash (suite)
  (case suite
    (#x1301 +tls13-cipher-suite-aes-128-gcm-sha256-hash+)
    (#x1302 +tls13-cipher-suite-aes-256-gcm-sha384-hash+)
    (#x1303 +tls13-cipher-suite-chacha20-poly1305-sha256-hash+)
    (#x1304 +tls13-cipher-suite-aes-128-ccm-sha256-hash+)))
(defun tls13-cipher-suite-key-length (suite)
  (case suite
    (#x1301 +tls13-cipher-suite-aes-128-gcm-sha256-key-length+)
    (#x1302 +tls13-cipher-suite-aes-256-gcm-sha384-key-length+)
    (#x1303 +tls13-cipher-suite-chacha20-poly1305-sha256-key-length+)
    (#x1304 +tls13-cipher-suite-aes-128-ccm-sha256-key-length+)))

(defconstant +tls13-extension-server-name+ 0)
(defconstant +tls13-extension-application-layer-protocol-negotiation+ 16)
(defconstant +tls13-extension-supported-groups+ 10)
(defconstant +tls13-extension-signature-algorithms+ 13)
(defconstant +tls13-extension-supported-versions+ 43)
(defconstant +tls13-extension-key-share+ 51)

(defun %tls13-extension-string-octets (value label)
  (unless (stringp value) (%tls13-fail (format nil "~A must be a string" label)))
  (let ((octets (make-array (length value) :element-type '(unsigned-byte 8))))
    (dotimes (i (length value) octets)
      (let ((code (char-code (char value i))))
        (unless (<= code 127)
          (%tls13-fail (format nil "~A must contain ASCII characters" label)))
        (setf (aref octets i) code)))))
(defun %tls13-octets-string (octets)
  (coerce (map 'list #'code-char octets) 'string))

(defun encode-sni-extension (hostname)
  "Encode one DNS host_name entry for the server_name extension."
  (let ((name (%tls13-extension-string-octets (normalize-hostname hostname) "SNI hostname")))
    (when (zerop (length name)) (%tls13-fail "SNI hostname cannot be empty"))
    (%cat (%hs-u16 (+ 3 (length name))) #(0)
          (%hs-u16 (length name)) name)))
(defun decode-sni-extension (bytes)
  "Decode a server_name extension and return its single DNS host name."
  (let ((bytes (%tls13-octets bytes)))
    (multiple-value-bind (names end) (%read-vector bytes 0 2 :minimum 3)
      (multiple-value-bind (name-type p1) (%read-integer names 0 1)
        (unless (= name-type 0) (%tls13-fail "SNI name is not host_name"))
        (multiple-value-bind (name p2) (%read-vector names p1 2 :minimum 1)
          (%finish names p2)
          (%finish bytes end)
          (%tls13-octets-string name))))))

(defun encode-alpn-extension (protocols)
  "Encode an ALPN extension from a non-empty list of protocol strings."
  (unless (and (listp protocols) protocols)
    (%tls13-fail "ALPN protocols must be a non-empty list"))
  (let ((names (mapcar (lambda (protocol)
                         (let ((octets (%tls13-extension-string-octets protocol "ALPN protocol")))
                           (when (or (zerop (length octets)) (> (length octets) 255))
                             (%tls13-fail "ALPN protocol length is out of range"))
                           (%cat (%hs-u8 (length octets)) octets)))
                       protocols)))
    (%encode-vector (apply #'%cat names) 2 :minimum 2)))

(defun decode-alpn-extension (bytes)
  "Decode an ALPN extension and return protocol names in wire order."
  (let ((bytes (%tls13-octets bytes)))
    (multiple-value-bind (names end) (%read-vector bytes 0 2 :minimum 2)
      (let ((cursor 0) (protocols '()))
        (loop while (< cursor (length names)) do
          (multiple-value-bind (protocol next) (%read-vector names cursor 1 :minimum 1)
            (push (%tls13-octets-string protocol) protocols)
            (setf cursor next)))
        (%finish bytes end)
        (nreverse protocols)))))

(defun make-tls13-client-hello-extensions (hostname alpn protocols
                                            &key (supported-groups #(29))
                                              (signature-algorithms #(2052)))
  "Build the SNI, ALPN, and key negotiation extensions for a ClientHello."
  (declare (ignore protocols))
  (let ((extensions
          (list
           (make-tls-extension +tls13-extension-supported-versions+ #(2 3 4))
           (make-tls-extension +tls13-extension-supported-groups+
                               (%encode-vector
                                (apply #'%cat (map 'list #'%hs-u16 supported-groups)) 2))
           (make-tls-extension +tls13-extension-signature-algorithms+
                               (%encode-vector
                                (apply #'%cat (map 'list #'%hs-u16 signature-algorithms)) 2))
           (make-tls-extension +tls13-extension-key-share+
                               (encode-key-share-extension
                                (list (cons 29 (make-array 32
                                                             :element-type '(unsigned-byte 8)
                                                             :initial-element 0))))))))
    (when hostname
      (push (make-tls-extension +tls13-extension-server-name+
                                (encode-sni-extension hostname)) extensions))
    (when alpn
      (push (make-tls-extension +tls13-extension-application-layer-protocol-negotiation+
                                (encode-alpn-extension alpn)) extensions))
    (nreverse extensions)))

(export '(+tls13-cipher-suite-aes-128-gcm-sha256+
          +tls13-cipher-suite-aes-256-gcm-sha384+
          +tls13-cipher-suite-chacha20-poly1305-sha256+
          +tls13-cipher-suite-aes-128-ccm-sha256+
          +tls13-cipher-suite-aes-128-gcm-sha256-name+
          +tls13-cipher-suite-aes-256-gcm-sha384-name+
          +tls13-cipher-suite-chacha20-poly1305-sha256-name+
          +tls13-cipher-suite-aes-128-ccm-sha256-name+
          +tls13-cipher-suite-aes-128-gcm-sha256-hash+
          +tls13-cipher-suite-aes-256-gcm-sha384-hash+
          +tls13-cipher-suite-chacha20-poly1305-sha256-hash+
          +tls13-cipher-suite-aes-128-ccm-sha256-hash+
          +tls13-cipher-suite-aes-128-gcm-sha256-key-length+
          +tls13-cipher-suite-aes-256-gcm-sha384-key-length+
          +tls13-cipher-suite-chacha20-poly1305-sha256-key-length+
          +tls13-cipher-suite-aes-128-ccm-sha256-key-length+
          tls13-cipher-suite-name tls13-cipher-suite-hash
          tls13-cipher-suite-key-length
          +tls13-extension-server-name+
          +tls13-extension-application-layer-protocol-negotiation+
          +tls13-extension-supported-groups+
          +tls13-extension-signature-algorithms+
          +tls13-extension-supported-versions+
          +tls13-extension-key-share+
          encode-sni-extension decode-sni-extension
          encode-alpn-extension decode-alpn-extension))

(defstruct (tls-extension (:constructor make-tls-extension (type data)))
  (type 0) (data #()))

(defun encode-key-share-extension (shares)
  "Encode TLS 1.3 key_share entries.  SHARE is ((GROUP . KEY-EXCHANGE) ...)."
  (unless (and (listp shares) shares) (%tls13-fail "key_share must not be empty"))
  (%encode-vector
   (apply #'%cat
          (mapcar (lambda (share)
                    (let ((group (car share)) (key (cdr share)))
                      (unless (typep group '(integer 0 65535))
                        (%tls13-fail "key_share group is out of range"))
                      (%cat (%hs-u16 group) (%encode-vector (%tls13-octets key) 2))))
                  shares)) 2))

(defun decode-key-share-extension (bytes)
  "Decode a ClientHello key_share vector into ((GROUP . KEY-EXCHANGE) ...)."
  (multiple-value-bind (raw end) (%read-vector (%tls13-octets bytes) 0 2)
    (%finish bytes end)
    (let ((cursor 0) (result '()))
      (loop while (< cursor (length raw)) do
        (multiple-value-bind (group p1) (%read-integer raw cursor 2)
          (multiple-value-bind (key p2) (%read-vector raw p1 2 :minimum 1)
            (push (cons group key) result)
            (setf cursor p2))))
      (nreverse result))))

(defun encode-key-share-server-extension (group key-exchange)
  (%cat (%hs-u16 group) (%encode-vector (%tls13-octets key-exchange) 2)))

(defun decode-key-share-server-extension (bytes)
  (let ((bytes (%tls13-octets bytes)))
    (multiple-value-bind (group p1) (%read-integer bytes 0 2)
      (multiple-value-bind (key p2) (%read-vector bytes p1 2 :minimum 1)
        (%finish bytes p2)
        (cons group key)))))
(defun %extension (type data)
  (unless (typep type '(integer 0 65535)) (%tls13-fail "extension type out of range"))
  (make-tls-extension type (%tls13-octets data)))
(defun %encode-extensions (extensions)
  (let ((seen '()) (body '()) (last-type nil))
    (dolist (extension extensions)
      (unless (typep extension 'tls-extension) (%tls13-fail "invalid extension"))
      (let ((type (tls-extension-type extension)))
        (when (member type seen) (%tls13-fail "duplicate extension"))
        (push type seen)
        (when (and last-type (= last-type 41)) (%tls13-fail "pre_shared_key must be last"))
        (setf last-type type)
        (push (%cat (%hs-u16 type) (%encode-vector (tls-extension-data extension) 2)) body)))
    (%encode-vector (apply #'%cat (nreverse body)) 2)))
(defun %decode-extensions (bytes pos)
  (multiple-value-bind (raw next) (%read-vector bytes pos 2)
    (let ((cursor 0) (out '()) (seen '()))
      (loop while (< cursor (length raw)) do
        (multiple-value-bind (type after-type) (%read-integer raw cursor 2)
          (multiple-value-bind (data after-data) (%read-vector raw after-type 2)
            (when (member type seen) (%tls13-fail "duplicate extension"))
            (push type seen)
            (push (make-tls-extension type data) out)
            (setf cursor after-data))))
      (when (and (member 41 seen) (/= 41 (tls-extension-type (car out))))
        (%tls13-fail "pre_shared_key must be the last extension"))
      (values (nreverse out) next))))

(defstruct (tls13-client-hello (:constructor make-tls13-client-hello
                                  (legacy-version random session-id cipher-suites extensions)))
  legacy-version random session-id cipher-suites extensions)
(defstruct (tls13-server-hello (:constructor make-tls13-server-hello
                                  (legacy-version random session-id cipher-suite extensions)))
  legacy-version random session-id cipher-suite extensions)
(defstruct (tls13-hello-retry-request (:constructor make-tls13-hello-retry-request
                                         (legacy-version selected-group extensions)))
  legacy-version selected-group extensions)
(defstruct (tls13-encrypted-extensions (:constructor make-tls13-encrypted-extensions (extensions))) extensions)
(defstruct (tls13-certificate-entry (:constructor make-tls13-certificate-entry (certificate extensions)))
  certificate extensions)
(defstruct (tls13-certificate (:constructor make-tls13-certificate (request-context entries)))
  request-context entries)
(defstruct (tls13-certificate-verify (:constructor make-tls13-certificate-verify (algorithm signature)))
  algorithm signature)
(defstruct (tls13-finished (:constructor make-tls13-finished (verify-data))) verify-data)
(defstruct (tls13-new-session-ticket (:constructor make-tls13-new-session-ticket
                                         (lifetime-age ticket-nonce ticket extensions
                                          &optional (ticket-age-add 0))))
  lifetime-age ticket-age-add ticket-nonce ticket extensions)
(defstruct (tls13-key-update (:constructor make-tls13-key-update (request))) request)
(defstruct (tls13-certificate-request (:constructor make-tls13-certificate-request
                                         (request-context extensions)))
  request-context extensions)

(defparameter *tls13-hrr-random*
  #(#xcf #x21 #xad #x74 #xe5 #x9a #x61 #x11 #xbe #x1d #x8c #x02 #x1e #x65 #xb8 #x91
    #xc2 #xa2 #x11 #x16 #x7a #xbb #x8c #x5e #x07 #x9e #x09 #xe2 #xc8 #xa8 #x33 #x9c))

(defun %valid-random (random)
  (unless (= (length (%tls13-octets random)) 32) (%tls13-fail "random must be 32 octets"))
  random)
(defun %valid-session-id (id) (%tls13-octets id) (when (> (length id) 32) (%tls13-fail "session id too long")) id)
(defun %cipher-suites (suites)
  (unless (and (vectorp suites) (plusp (length suites))) (%tls13-fail "cipher suite vector is malformed"))
  (every (lambda (x) (typep x '(integer 0 65535))) suites) suites)
(defun %encode-cipher-suites (suites)
  (%encode-vector (apply #'%cat (map 'list #'%hs-u16 suites)) 2 :minimum 2))
(defun %decode-cipher-suites (bytes pos)
  (multiple-value-bind (raw next) (%read-vector bytes pos 2 :minimum 2)
    (when (oddp (length raw)) (%tls13-fail "cipher suites length is not even"))
    (let ((out (make-array (/ (length raw) 2))) (cursor 0))
      (dotimes (i (length out) (values out next))
        (setf (aref out i) (nth-value 0 (%read-integer raw cursor 2)))
        (incf cursor 2)))))

(defun encode-client-hello (hello)
  (let* ((body (%cat (%hs-u16 (tls13-client-hello-legacy-version hello))
                     (%valid-random (tls13-client-hello-random hello))
                     (%encode-vector (%valid-session-id (tls13-client-hello-session-id hello)) 1)
                     (%encode-cipher-suites (%cipher-suites (tls13-client-hello-cipher-suites hello)))
                    (%encode-vector #(0) 1)))
         (extensions (%encode-extensions (tls13-client-hello-extensions hello))))
    (%cat body extensions)))
(defun decode-client-hello (bytes)
  (let ((bytes (%tls13-octets bytes)))
    (multiple-value-bind (version p1) (%read-integer bytes 0 2)
      (multiple-value-bind (random p2) (%bounded bytes p1 32)
        (multiple-value-bind (sid p3) (%read-vector bytes p2 1 :maximum 32)
          (multiple-value-bind (suites p4) (%decode-cipher-suites bytes p3)
            (multiple-value-bind (compression p5) (%read-vector bytes p4 1)
              (unless (equalp compression #(0)) (%tls13-fail "TLS 1.3 requires null compression"))
              (multiple-value-bind (extensions p6) (%decode-extensions bytes p5)
                (%finish bytes p6)
                (make-tls13-client-hello version random sid suites extensions)))))))))

(defun encode-server-hello (hello)
  (%cat (%hs-u16 (tls13-server-hello-legacy-version hello))
        (%valid-random (tls13-server-hello-random hello))
        (%encode-vector (%valid-session-id (tls13-server-hello-session-id hello)) 1)
        (%hs-u16 (tls13-server-hello-cipher-suite hello))
        #(0)
        (%encode-extensions (tls13-server-hello-extensions hello))))
(defun decode-server-hello (bytes)
  (setf bytes (%tls13-octets bytes))
  (let* ((version (nth-value 0 (%read-integer bytes 0 2)))
         (random-result (multiple-value-list (%bounded bytes 2 32)))
         (random (first random-result))
         (p2 (second random-result))
         (sid-result (multiple-value-list (%read-vector bytes p2 1 :maximum 32)))
         (sid (first sid-result))
         (p3 (second sid-result))
         (suite-result (multiple-value-list (%read-integer bytes p3 2)))
         (suite (first suite-result))
         (p4 (second suite-result)))
    (when (>= p4 (length bytes)) (%tls13-fail "truncated ServerHello"))
    (unless (= (aref bytes p4) 0) (%tls13-fail "ServerHello compression is not null"))
    (multiple-value-bind (extensions p5) (%decode-extensions bytes (1+ p4))
      (%finish bytes p5)
      (let ((ks (find 51 extensions :key #'tls-extension-type)))
        (if (equalp random *tls13-hrr-random*)
            (progn
              (unless (and ks (= (length (tls-extension-data ks)) 2))
                (%tls13-fail "HRR must contain a key_share extension"))
              (make-tls13-hello-retry-request
               version (nth-value 0 (%read-integer (tls-extension-data ks) 0 2)) extensions))
            (make-tls13-server-hello version random sid suite extensions))))))
(defun encode-hello-retry-request (hrr)
  (encode-server-hello
   (make-tls13-server-hello (tls13-hello-retry-request-legacy-version hrr)
                            *tls13-hrr-random* #() 0
                            (cons (make-tls-extension 51 (%hs-u16 (tls13-hello-retry-request-selected-group hrr)))
                                  (remove 51 (tls13-hello-retry-request-extensions hrr)
                                          :key #'tls-extension-type)))))

(defun encode-encrypted-extensions (message) (%encode-extensions (tls13-encrypted-extensions-extensions message)))
(defun decode-encrypted-extensions (bytes)
  (multiple-value-bind (extensions end) (%decode-extensions (%tls13-octets bytes) 0)
    (%finish bytes end) (make-tls13-encrypted-extensions extensions)))
(defun encode-certificate (message)
  (let* ((entries (mapcar
                   (lambda (entry)
                     (%cat
                      (%encode-vector (tls13-certificate-entry-certificate entry) 3)
                      (%encode-extensions (tls13-certificate-entry-extensions entry))))
                   (tls13-certificate-entries message)))
         (body (apply #'%cat entries)))
    (%cat (%encode-vector (tls13-certificate-request-context message) 1)
          (%encode-vector body 3))))
(defun decode-certificate (bytes)
  (setf bytes (%tls13-octets bytes))
  (multiple-value-bind (context p1) (%read-vector bytes 0 1)
    (multiple-value-bind (raw p2) (%read-vector bytes p1 3)
      (let ((cursor 0) (entries '()))
        (loop while (< cursor (length raw)) do
          (multiple-value-bind (certificate p3) (%read-vector raw cursor 3)
            (multiple-value-bind (extensions p4) (%decode-extensions raw p3)
              (push (make-tls13-certificate-entry certificate extensions) entries)
              (setf cursor p4))))
        (when (null entries) (%tls13-fail "Certificate must contain an entry"))
        (%finish bytes p2)
        (make-tls13-certificate context (nreverse entries))))))
(defun encode-certificate-verify (message)
  (%cat (%hs-u16 (tls13-certificate-verify-algorithm message))
        (%encode-vector (tls13-certificate-verify-signature message) 2)))
(defun decode-certificate-verify (bytes)
  (multiple-value-bind (algorithm p1) (%read-integer (%tls13-octets bytes) 0 2)
    (multiple-value-bind (signature p2) (%read-vector bytes p1 2 :minimum 1)
      (%finish bytes p2) (make-tls13-certificate-verify algorithm signature))))
(defun encode-finished (message) (%tls13-octets (tls13-finished-verify-data message)))
(defun decode-finished (bytes)
  (let ((bytes (%tls13-octets bytes)))
    (when (zerop (length bytes)) (%tls13-fail "Finished verify_data cannot be empty"))
    (make-tls13-finished bytes)))
(defun encode-new-session-ticket (message)
  (%cat (%u32 (tls13-new-session-ticket-lifetime-age message))
        (%u32 (tls13-new-session-ticket-ticket-age-add message))
        (%encode-vector (tls13-new-session-ticket-ticket-nonce message) 1)
        (%encode-vector (tls13-new-session-ticket-ticket message) 2 :minimum 1)
        (%encode-extensions (tls13-new-session-ticket-extensions message))))
(defun decode-new-session-ticket (bytes)
  (setf bytes (%tls13-octets bytes))
  (multiple-value-bind (age p1) (%read-integer bytes 0 4)
    (multiple-value-bind (unused p2) (%read-integer bytes p1 4)
      (multiple-value-bind (nonce p3) (%read-vector bytes p2 1)
        (multiple-value-bind (ticket p4) (%read-vector bytes p3 2 :minimum 1)
          (multiple-value-bind (extensions p5) (%decode-extensions bytes p4)
            (%finish bytes p5)
            (make-tls13-new-session-ticket age nonce ticket extensions unused)))))))
(defun encode-key-update (message)
  (let ((request (tls13-key-update-request message)))
    (unless (member request '(0 1)) (%tls13-fail "invalid KeyUpdate request"))
    (%hs-u8 request)))
(defun decode-key-update (bytes)
  (let ((bytes (%tls13-octets bytes)))
    (unless (= (length bytes) 1) (%tls13-fail "KeyUpdate has a one-octet body"))
    (unless (member (aref bytes 0) '(0 1)) (%tls13-fail "invalid KeyUpdate request"))
    (make-tls13-key-update (aref bytes 0))))
(defun encode-certificate-request (message)
  (%cat (%encode-vector (tls13-certificate-request-request-context message) 1)
        (%encode-extensions (tls13-certificate-request-extensions message))))
(defun decode-certificate-request (bytes)
  (setf bytes (%tls13-octets bytes))
  (multiple-value-bind (context p1) (%read-vector bytes 0 1)
    (multiple-value-bind (extensions p2) (%decode-extensions bytes p1)
      (%finish bytes p2) (make-tls13-certificate-request context extensions))))

(defparameter *tls13-message-codecs*
  '((1 . encode-client-hello) (2 . encode-server-hello) (8 . encode-encrypted-extensions)
    (11 . encode-certificate) (13 . encode-certificate-request) (15 . encode-certificate-verify)
    (20 . encode-finished) (4 . encode-new-session-ticket) (24 . encode-key-update)))
(defun encode-handshake (type message)
  (let ((encoder (cdr (assoc type *tls13-message-codecs*))))
    (unless encoder (%tls13-fail "unsupported handshake type"))
    (let ((body (funcall encoder message)))
      (%cat (%hs-u8 type) (%u24 (length body)) body))))
(defun decode-handshake (bytes)
  (setf bytes (%tls13-octets bytes))
  (when (< (length bytes) 4) (%tls13-fail "truncated handshake header"))
  (let ((type (aref bytes 0)) (length (nth-value 0 (%read-integer bytes 1 3))))
    (when (/= (+ 4 length) (length bytes)) (%tls13-fail "handshake length does not match input"))
    (let ((body (subseq bytes 4)))
      (case type
        (1 (decode-client-hello body)) (2 (decode-server-hello body)) (8 (decode-encrypted-extensions body))
        (11 (decode-certificate body)) (13 (decode-certificate-request body))
        (15 (decode-certificate-verify body)) (20 (decode-finished body))
        (4 (decode-new-session-ticket body)) (24 (decode-key-update body))
        (otherwise (%tls13-fail "unsupported handshake type"))))))

(defun tls13-certificate-verify-context (role)
  (cond ((eq role :client) "TLS 1.3, client CertificateVerify")
        ((eq role :server) "TLS 1.3, server CertificateVerify")
        (t (%tls13-fail "role must be :client or :server" 'tls13-state-error))))
(defun %ascii-octets (string)
  (coerce (map 'list #'char-code string) '(vector (unsigned-byte 8))))
(defun tls13-certificate-verify-input (role transcript)
  (%cat (make-array 64 :initial-element #x20 :element-type '(unsigned-byte 8))
        (%ascii-octets (tls13-certificate-verify-context role))
        #(0)
        (%tls13-octets transcript)))

(defstruct (tls13-state (:constructor make-tls13-state
                                      (role &optional (phase :start) hash-function)))
  role phase (transcript (make-array 0 :element-type '(unsigned-byte 8)))
  (retry-requested nil) (key-update-count 0) transcript-hash-function hash-function)
(defun %allowed-next-p (role phase type)
  (declare (ignore role))
  (case phase
    (:start (member type '(1 2)))
    (:client-hello (member type '(2 8)))
    (:server-hello (member type '(8 11 13 20)))
    (:encrypted-extensions (member type '(11 13 20)))
    (:certificate (member type '(15 20)))
    (:certificate-verify (eql type 20))
    (:connected (member type '(4 24)))
    (otherwise nil)))
(defun tls13-state-advance (state type)
  (unless (%allowed-next-p (tls13-state-role state) (tls13-state-phase state) type)
    (%tls13-fail "handshake message is not valid in this state" 'tls13-state-error))
  (setf (tls13-state-phase state)
        (case type (1 :client-hello) (2 :server-hello) (8 :encrypted-extensions)
          (11 :certificate) (13 :certificate) (15 :certificate-verify)
          (20 :connected) (4 :connected) (24 :connected)))
  state)

(defun tls13-state-advance-message (state message)
  "Advance STATE using a decoded handshake MESSAGE.

Unlike the numeric compatibility entry point, this recognizes a
HelloRetryRequest as the special ServerHello it is on the wire."
  (cond
    ((typep message 'tls13-hello-retry-request)
     (tls13-state-handle-hello-retry-request state message nil))
    ((typep message 'tls13-server-hello)
     (tls13-state-advance state 2))
    ((typep message 'tls13-encrypted-extensions)
     (tls13-state-advance state 8))
    ((typep message 'tls13-certificate)
     (tls13-state-advance state 11))
    ((typep message 'tls13-certificate-request)
     (tls13-state-advance state 13))
    ((typep message 'tls13-certificate-verify)
     (tls13-state-advance state 15))
    ((typep message 'tls13-finished)
     (tls13-state-advance state 20))
    ((typep message 'tls13-new-session-ticket)
     (tls13-state-advance state 4))
    ((typep message 'tls13-key-update)
     (tls13-state-advance state 24))
    (t (%tls13-fail "unsupported handshake message" 'tls13-state-error))))

(defun tls13-state-add-transcript (state handshake-bytes)
  "Append one complete encoded handshake message to STATE's transcript."
  (let ((bytes (%tls13-octets handshake-bytes)))
    (setf (tls13-state-transcript state)
          (%cat (tls13-state-transcript state) bytes))))

(defun tls13-state-handle-hello-retry-request (state hrr encoded-client-hello)
  "Apply the TLS 1.3 HRR transcript marker and move back to ClientHello.

The caller supplies the first ClientHello.  The transcript becomes
message_hash(ClientHello) || HRR, as required by RFC 8446 section 4.4.1."
  (unless (and (eq (tls13-state-role state) :client)
               (eq (tls13-state-phase state) :server-hello))
    (%tls13-fail "HelloRetryRequest is not valid in this state" 'tls13-state-error))
  (unless (tls13-state-retry-requested state)
    (when (and (zerop (length (tls13-state-transcript state))) encoded-client-hello)
      (tls13-state-add-transcript state encoded-client-hello))
    (let* ((hash-function (tls13-state-hash-function state))
           (hash (if hash-function
                     (funcall hash-function (tls13-state-transcript state))
                     (tls13-state-transcript state)))
           (marker (concatenate '(vector (unsigned-byte 8))
                                (vector #xfe
                                        (ldb (byte 8 16) (length hash))
                                        (ldb (byte 8 8) (length hash))
                                        (ldb (byte 8 0) (length hash)))
                                hash)))
      (setf (tls13-state-transcript state) marker)))
  (setf (tls13-state-retry-requested state) t
        (tls13-state-phase state) :client-hello)
  (tls13-state-add-transcript state (encode-hello-retry-request hrr))
  state)

(export '(+tls13-extension-supported-groups+
          +tls13-extension-signature-algorithms+
          +tls13-extension-supported-versions+
          +tls13-extension-key-share+
          encode-key-share-extension decode-key-share-extension
          encode-key-share-server-extension decode-key-share-server-extension
          tls13-state-transcript tls13-state-retry-requested
          tls13-state-key-update-count tls13-state-add-transcript
          tls13-state-handle-hello-retry-request tls13-state-advance-message))

(export '(make-tls13-client-hello-extensions))
