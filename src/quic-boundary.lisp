(in-package #:cl-tls-kit)

;;; QUIC carries the TLS handshake directly in CRYPTO frames.  This file is
;;; intentionally only that boundary: it does not implement QUIC packets,
;;; CRYPTO offsets, AEAD, or a TLS provider.

(define-condition quic-tls-boundary-error (error)
  ((message :initarg :message :reader quic-tls-boundary-error-message))
  (:report (lambda (condition stream)
             (format stream "QUIC/TLS boundary error: ~A"
                     (quic-tls-boundary-error-message condition)))))
(define-condition quic-tls-boundary-decode-error (quic-tls-boundary-error) ())

(defparameter +quic-tls-transport-parameters-extension+ #x0039)
(defparameter +quic-tls-message-hash+ #xfe)
(defparameter +quic-tls-alert+ 21)
(defparameter +quic-tls-key-update+ 24)

(defun %quic-octets (value)
  (unless (and (vectorp value)
               (every (lambda (byte) (typep byte '(unsigned-byte 8))) value))
    (error 'quic-tls-boundary-decode-error :message "expected octet vector"))
  value)
(defun %quic-u24 (n)
  (vector (ldb (byte 8 16) n) (ldb (byte 8 8) n) (ldb (byte 8 0) n)))
(defun %quic-cat (&rest values)
  (apply #'concatenate '(vector (unsigned-byte 8)) values))
(defun %quic-integer (bytes position width)
  (when (> (+ position width) (length bytes))
    (error 'quic-tls-boundary-decode-error :message "truncated QUIC/TLS data"))
  (let ((value 0))
    (dotimes (index width value)
      (setf value (+ (ash value 8) (aref bytes (+ position index)))))))

(defun %quic-extension (type data)
  (%quic-cat (vector (ldb (byte 8 8) type) (ldb (byte 8 0) type))
             (vector (ldb (byte 8 8) (length data)) (ldb (byte 8 0) (length data)))
             data))
(defun quic-tls-transport-parameters-extension (parameters)
  "Encode PARAMETERS as the TLS quic_transport_parameters extension body."
  (%quic-extension +quic-tls-transport-parameters-extension+
                   (%quic-octets parameters)))

(defstruct (quic-tls-boundary (:constructor %make-quic-tls-boundary))
  role on-crypto on-secret on-transport-parameters hash-function
  (pending (make-array 0 :element-type '(unsigned-byte 8))
           :type (vector (unsigned-byte 8)))
  (transcript '())
  transport-parameters received-transport-parameters
  (hrr-seen-p nil) selected-group cookie)

(defun make-quic-tls-boundary (&key (role :client) on-crypto on-secret
                                    on-transport-parameters hash-function
                                    transport-parameters)
  (unless (member role '(:client :server))
    (error 'quic-tls-boundary-error :message "role must be :client or :server"))
  (%make-quic-tls-boundary :role role :on-crypto on-crypto :on-secret on-secret
                           :on-transport-parameters on-transport-parameters
                           :hash-function hash-function
                           :transport-parameters
                           (and transport-parameters (%quic-octets transport-parameters))))

(defun %quic-level-p (level)
  (member level '(:initial :handshake :0-rtt :1-rtt)))
(defun %quic-direction-p (direction)
  (member direction '(:read :write)))
(defun %quic-emit (boundary level wire)
  (when (quic-tls-boundary-on-crypto boundary)
    (funcall (quic-tls-boundary-on-crypto boundary) boundary level wire))
  wire)
(defun quic-tls-boundary-emit-secret (boundary level direction secret)
  "Forward one QUIC encryption-level secret without deriving or protecting it."
  (unless (and (%quic-level-p level) (%quic-direction-p direction))
    (error 'quic-tls-boundary-error :message "invalid QUIC secret level or direction"))
  (let ((secret (%quic-octets secret)))
    (when (quic-tls-boundary-on-secret boundary)
      (funcall (quic-tls-boundary-on-secret boundary) boundary level direction secret))
    secret))

(defun %quic-transcript-bytes (boundary)
  (apply #'%quic-cat (nreverse (copy-list (quic-tls-boundary-transcript boundary)))))
(defun %quic-transcript-add (boundary wire)
  (push wire (quic-tls-boundary-transcript boundary)))

(defun %quic-extension-data (body start)
  (let ((total (%quic-integer body start 2)) (cursor (+ start 2))
        (end (+ start 2 (%quic-integer body start 2))) (found nil))
    (declare (ignore total))
    (when (> end (length body))
      (error 'quic-tls-boundary-decode-error :message "truncated TLS extensions"))
    (loop while (< cursor end) do
      (let* ((type (%quic-integer body cursor 2))
             (length (%quic-integer body (+ cursor 2) 2))
             (data-start (+ cursor 4))
             (next (+ data-start length)))
        (when (> next end)
          (error 'quic-tls-boundary-decode-error :message "truncated TLS extension"))
        (when (= type +quic-tls-transport-parameters-extension+)
          (when found
            (error 'quic-tls-boundary-decode-error :message "duplicate transport parameters"))
          (setf found (subseq body data-start next)))
        (setf cursor next)))
    found))

(defun %quic-message-extensions (type body)
  (case type
    (1 (let ((p 34))
         (when (> p (length body))
           (error 'quic-tls-boundary-decode-error :message "truncated ClientHello"))
         (let* ((sid-length (aref body 34)) (p (+ 35 sid-length))
                (suites-length (%quic-integer body p 2))
                (p (+ p 2 suites-length)))
           (when (> (+ p 1) (length body))
             (error 'quic-tls-boundary-decode-error :message "truncated ClientHello"))
           (incf p (1+ (aref body p)))
           p)))
    (8 0)
    (otherwise nil)))

(defun %quic-transport-parameters-from-message (type body)
  (let ((start (%quic-message-extensions type body)))
    (and start (%quic-extension-data body start))))

(defun %quic-replace-transcript-for-hrr (boundary)
  (let ((hash-function (quic-tls-boundary-hash-function boundary)))
    (unless hash-function
      (error 'quic-tls-boundary-error :message "HRR requires a transcript hash function"))
    (let* ((digest (%quic-octets (funcall hash-function (%quic-transcript-bytes boundary))))
           (message-hash (%quic-cat (vector +quic-tls-message-hash+)
                                    (%quic-u24 (length digest)) digest)))
      (setf (quic-tls-boundary-transcript boundary) (list message-hash)))))

(defun quic-tls-boundary-send (boundary level type body)
  "Frame one TLS handshake message and offer it to the QUIC CRYPTO writer."
  (unless (%quic-level-p level)
    (error 'quic-tls-boundary-error :message "invalid QUIC encryption level"))
  (let* ((body (%quic-octets body))
         (wire (%quic-cat (vector type) (%quic-u24 (length body)) body)))
    (%quic-transcript-add boundary wire)
    (%quic-emit boundary level wire)))

(defun quic-tls-boundary-send-message (boundary level type message)
  (let ((wire (if (and (= type 2) (typep message 'tls13-hello-retry-request))
                  (encode-hello-retry-request message)
                  (funcall (cdr (assoc type *tls13-message-codecs*)) message))))
    (quic-tls-boundary-send boundary level type wire)))

(defun quic-tls-boundary-feed (boundary level bytes)
  "Consume CRYPTO payload bytes, retaining an incomplete handshake message."
  (unless (%quic-level-p level)
    (error 'quic-tls-boundary-error :message "invalid QUIC encryption level"))
  (let ((pending (%quic-cat (quic-tls-boundary-pending boundary) (%quic-octets bytes)))
        (messages '()))
    (loop while (>= (length pending) 4) do
      (let ((length (%quic-integer pending 1 3)))
        (if (< (length pending) (+ 4 length))
            (return)
            (let* ((wire (subseq pending 0 (+ 4 length)))
                   (type (aref wire 0))
                   (body (subseq wire 4)))
              (setf pending (subseq pending (+ 4 length)))
              (if (= type 2)
                  (progn
                    (%quic-replace-transcript-for-hrr boundary)
                    (setf (quic-tls-boundary-hrr-seen-p boundary) t)
                    (handler-case
                        (let ((hrr (decode-handshake wire)))
                          (when (typep hrr 'tls13-hello-retry-request)
                            (setf (quic-tls-boundary-selected-group boundary)
                                  (tls13-hello-retry-request-selected-group hrr))
                            (let ((cookie (find 44 (tls13-hello-retry-request-extensions hrr)
                                             :key #'tls-extension-type)))
                              (setf (quic-tls-boundary-cookie boundary)
                                    (and cookie (tls-extension-data cookie))))))
                      (tls13-error () nil))
                    (%quic-transcript-add boundary wire))
                  (%quic-transcript-add boundary wire))
              (let ((parameters (%quic-transport-parameters-from-message type body)))
                (when parameters
                  (setf (quic-tls-boundary-received-transport-parameters boundary) parameters)
                  (when (quic-tls-boundary-on-transport-parameters boundary)
                    (funcall (quic-tls-boundary-on-transport-parameters boundary)
                             boundary parameters))))
              (push (list :level level :type type :wire wire :body body) messages)))))
    (setf (quic-tls-boundary-pending boundary) pending)
    (nreverse messages)))

(defun quic-tls-boundary-receive (boundary level bytes)
  (quic-tls-boundary-feed boundary level bytes))

(defun quic-tls-boundary-send-with-transport-parameters
    (boundary level type body parameters)
  "Add the QUIC transport-parameters extension to ClientHello or EE."
  (let ((body (%quic-octets body)) (parameters (%quic-octets parameters)))
    (unless (member type '(1 8))
      (error 'quic-tls-boundary-error :message "transport parameters require CH or EE"))
    (let* ((start (%quic-message-extensions type body))
           (extensions-end (+ start 2 (when start (%quic-integer body start 2))))
           (extension (quic-tls-transport-parameters-extension parameters)))
      (unless start
        (error 'quic-tls-boundary-error :message "malformed TLS extension vector"))
      (when (%quic-extension-data body start)
        (error 'quic-tls-boundary-error :message "transport parameters already present"))
      (quic-tls-boundary-send boundary level type
                              (%quic-cat (subseq body 0 start)
                                         (vector (ldb (byte 8 8) (+ (- extensions-end start 2) (length extension)))
                                                 (ldb (byte 8 0) (+ (- extensions-end start 2) (length extension))))
                                         (subseq body (+ start 2) extensions-end)
                                         extension)))))

(defun quic-tls-boundary-send-client-hello (boundary level hello)
  (let ((wire (encode-client-hello hello)))
    (if (quic-tls-boundary-transport-parameters boundary)
        (quic-tls-boundary-send-with-transport-parameters
         boundary level 1 wire (quic-tls-boundary-transport-parameters boundary))
        (quic-tls-boundary-send boundary level 1 wire))))

(defun quic-tls-boundary-send-hrr (boundary selected-group &optional cookie)
  "Send HRR, replacing CH1 in the transcript with message_hash(CH1)."
  (%quic-replace-transcript-for-hrr boundary)
  (setf (quic-tls-boundary-selected-group boundary) selected-group
        (quic-tls-boundary-cookie boundary) cookie)
  (let ((extensions (if cookie (list (make-tls-extension 44 (%quic-octets cookie))) nil)))
    (quic-tls-boundary-send-message
     boundary :initial 2
     (make-tls13-hello-retry-request #x0303 selected-group extensions))))

(defun quic-tls-boundary-send-alert (boundary level description &key (fatal-p nil))
  "Emit a TLS alert as raw CRYPTO data; alerts are not TLS records in QUIC."
  (let ((wire (vector (if fatal-p 2 1) description)))
    (unless (and (typep description '(integer 0 255))
                 (member level '(:handshake :1-rtt :initial)))
      (error 'quic-tls-boundary-error :message "invalid QUIC TLS alert"))
    (%quic-emit boundary level wire)))

(defun quic-tls-boundary-send-close-notify (boundary level)
  (quic-tls-boundary-send-alert boundary level 0))
(defun quic-tls-boundary-send-key-update (boundary level request)
  (unless (member request '(0 1))
    (error 'quic-tls-boundary-error :message "invalid KeyUpdate request"))
  (quic-tls-boundary-send boundary level +quic-tls-key-update+ (vector request)))
(defun quic-tls-boundary-close-notify-p (bytes)
  (equalp (%quic-octets bytes) #(1 0)))
(defun quic-tls-boundary-alert-p (bytes)
  (let ((bytes (%quic-octets bytes)))
    (and (= (length bytes) 2) (member (aref bytes 0) '(1 2)))))
(defun quic-tls-boundary-key-update-p (bytes)
  (let ((bytes (%quic-octets bytes)))
    (and (= (length bytes) 5) (= (aref bytes 0) +quic-tls-key-update+)
         (zerop (aref bytes 1)) (zerop (aref bytes 2)) (= (aref bytes 3) 1)
         (member (aref bytes 4) '(0 1)))))

(export '(quic-tls-boundary-error quic-tls-boundary-decode-error
          make-quic-tls-boundary quic-tls-boundary-p
          quic-tls-boundary-role quic-tls-boundary-transport-parameters
          quic-tls-boundary-received-transport-parameters
          quic-tls-boundary-transcript quic-tls-boundary-selected-group
          quic-tls-boundary-cookie
          quic-tls-transport-parameters-extension quic-tls-boundary-send
          quic-tls-boundary-send-message quic-tls-boundary-feed
          quic-tls-boundary-receive quic-tls-boundary-send-with-transport-parameters
          quic-tls-boundary-send-client-hello quic-tls-boundary-send-hrr
          quic-tls-boundary-emit-secret quic-tls-boundary-send-alert
          quic-tls-boundary-send-close-notify quic-tls-boundary-send-key-update
          quic-tls-boundary-close-notify-p quic-tls-boundary-alert-p
          quic-tls-boundary-key-update-p))
