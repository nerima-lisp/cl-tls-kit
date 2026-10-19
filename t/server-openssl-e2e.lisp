(in-package #:cl-tls-kit/test)

(defstruct (%server-openssl-e2e-session
            (:constructor %make-server-openssl-e2e-session (driver suite)))
  driver
  suite
  negotiated-suite
  negotiated-group
  (read-states (make-hash-table :test #'equal))
  (write-states (make-hash-table :test #'equal))
  (handshake-complete-p nil)
  (resumed-p nil)
  (ticket-issued-p nil)
  (negotiated-alpn nil)
  (client-hello-count 0)
  (hello-retry-count 0)
  (hello-retry-group nil)
  (alert-description nil))

(defun %server-openssl-e2e-socket-symbol (name)
  (let ((package (or (find-package '#:sb-bsd-sockets)
                     (progn
                       (require :sb-bsd-sockets)
                       (find-package '#:sb-bsd-sockets)))))
    (or (find-symbol name package)
        (error "SBCL socket operation ~A is unavailable" name))))

(defun %server-openssl-e2e-open-listener ()
  (let* ((socket (funcall (symbol-function
                           (%server-openssl-e2e-socket-symbol "MAKE-INET-SOCKET"))
                          :stream :tcp))
         (bind (symbol-function
                (%server-openssl-e2e-socket-symbol "SOCKET-BIND")))
         (listen (symbol-function
                  (%server-openssl-e2e-socket-symbol "SOCKET-LISTEN")))
         (name (symbol-function
                (%server-openssl-e2e-socket-symbol "SOCKET-NAME")))
         (close (symbol-function
                 (%server-openssl-e2e-socket-symbol "SOCKET-CLOSE"))))
    (handler-case
        (progn
          (funcall bind socket #(127 0 0 1) 0)
          (funcall listen socket 1)
          (multiple-value-bind (address port) (funcall name socket)
            (declare (ignore address))
            (values socket port)))
      (error (condition)
        (ignore-errors (funcall close socket))
        (error condition)))))

(defun %server-openssl-e2e-read-exact (stream bytes)
  (loop with position = 0
        while (< position (length bytes))
        for next = (read-sequence bytes stream :start position)
        do (when (= next position)
             (if (zerop position)
                 (return-from %server-openssl-e2e-read-exact nil)
                 (error "OpenSSL closed during a TLS record")))
           (setf position next)
        finally (return bytes)))

(defun %server-openssl-e2e-read-record (stream)
  (let ((header (make-array 5 :element-type '(unsigned-byte 8))))
    (unless (%server-openssl-e2e-read-exact stream header)
      (return-from %server-openssl-e2e-read-record nil))
    (let* ((content-type (aref header 0))
           (version (+ (ash (aref header 1) 8) (aref header 2)))
           (length (+ (ash (aref header 3) 8) (aref header 4)))
           (maximum (if (= content-type cl-tls-kit:+tls-content-type-application-data+)
                        cl-tls-kit:+tls-ciphertext-limit+
                        cl-tls-kit:+tls-plaintext-limit+))
           (body (make-array length :element-type '(unsigned-byte 8))))
      (unless (member content-type '(20 21 22 23))
        (error "OpenSSL sent an invalid TLS record type"))
      (unless (and (member version '(#x0301 #x0303))
                   (or (/= content-type cl-tls-kit:+tls-content-type-application-data+)
                       (= version cl-tls-kit:+tls-record-version+)))
        (error "OpenSSL sent an invalid TLS record version"))
      (when (> length maximum)
        (error "OpenSSL sent an oversized TLS record"))
      (unless (%server-openssl-e2e-read-exact stream body)
        (error "OpenSSL sent a truncated TLS record"))
      (values content-type version body
              (concatenate '(vector (unsigned-byte 8)) header body)))))

(defun %server-openssl-e2e-traffic-state (provider suite secret)
  (case suite
    (#x1301
     (cl-tls-kit::make-tls13-traffic-state
      provider :sha256 :aes-128-gcm secret 16 12))
    (#x1302
     (cl-tls-kit::make-tls13-traffic-state
      provider :sha384 :aes-256-gcm secret 32 12))
    (#x1303
     (cl-tls-kit::make-tls13-traffic-state
      provider :sha256 :chacha20-poly1305 secret 32 12))
    (otherwise
     (error "OpenSSL E2E has no traffic-state parameters for suite ~X" suite))))

(defun %server-openssl-e2e-write-record (stream plaintext state)
  (write-sequence
   (if state
       (cl-tls-kit:encrypt-tls13-traffic-record plaintext state)
       (cl-tls-kit:encode-tls-plaintext plaintext))
   stream)
  (finish-output stream))

(defun %server-openssl-e2e-send-event (session stream event)
  (let* ((level (getf event :level))
         (content-type
           (case (getf event :content-type)
             ((:alert 21) cl-tls-kit:+tls-content-type-alert+)
             ((:application-data 23) cl-tls-kit:+tls-content-type-application-data+)
             (otherwise cl-tls-kit:+tls-content-type-handshake+)))
         (wire (getf event :wire))
         (plaintext (cl-tls-kit:make-tls-plaintext content-type wire))
         (state (unless (eq level :initial)
                  (or (gethash (list :write level)
                               (%server-openssl-e2e-session-write-states session))
                      (error "TLS server sent data before its traffic secret")))))
    (when (and (= content-type cl-tls-kit:+tls-content-type-handshake+)
               (>= (length wire) 4)
               (= (aref wire 0) 2))
      (let ((message (cl-tls-kit:decode-handshake wire)))
        (when (typep message 'cl-tls-kit:tls13-hello-retry-request)
          (incf (%server-openssl-e2e-session-hello-retry-count session))
          (setf (%server-openssl-e2e-session-hello-retry-group session)
                (cl-tls-kit:tls13-hello-retry-request-selected-group message)))))
    (%server-openssl-e2e-write-record stream plaintext state)))

(defun %server-openssl-e2e-process-events (session provider stream events)
  (dolist (event events)
    (case (getf event :type)
      (:send
       (%server-openssl-e2e-send-event session stream event))
      (:secret
       (let* ((direction (getf event :direction))
              (level (getf event :level))
              (state (%server-openssl-e2e-traffic-state
                      provider (%server-openssl-e2e-session-suite session)
                      (getf event :secret))))
         (ecase direction
           (:read
            (setf (gethash (list direction level)
                           (%server-openssl-e2e-session-read-states session))
                  state))
           (:write
            (setf (gethash (list direction level)
                           (%server-openssl-e2e-session-write-states session))
                  state)))))
      (:cipher-suite
       (setf (%server-openssl-e2e-session-negotiated-suite session)
             (getf event :suite))
       (unless (= (getf event :suite) (%server-openssl-e2e-session-suite session))
         (error "TLS server selected an unexpected cipher suite")))
      (:alpn
       (setf (%server-openssl-e2e-session-negotiated-alpn session)
             (getf event :protocol)))
      (:ticket-issued
       (setf (%server-openssl-e2e-session-ticket-issued-p session) t))
      (:handshake-complete
       (setf (%server-openssl-e2e-session-handshake-complete-p session) t
             (%server-openssl-e2e-session-resumed-p session)
             (getf event :resumed-p)))
      (:alert
       (setf (%server-openssl-e2e-session-alert-description session)
             (getf event :description)))
      (otherwise
       (error "TLS server driver returned an unknown event")))))

(defun %server-openssl-e2e-dispatch-handshake (session provider stream wire level)
  (let ((message (cl-tls-kit:decode-handshake wire)))
    (when (typep message 'cl-tls-kit:tls13-client-hello)
      (incf (%server-openssl-e2e-session-client-hello-count session)))
    (multiple-value-bind (driver events)
        (cl-tls-kit:tls13-server-driver-step
         (%server-openssl-e2e-session-driver session) wire :level level)
      (setf (%server-openssl-e2e-session-driver session) driver
            (%server-openssl-e2e-session-negotiated-group session)
            (cl-tls-kit::tls13-server-driver-selected-group driver))
      (%server-openssl-e2e-process-events session provider stream events))))

(defun %server-openssl-e2e-feed-handshakes
    (session provider stream buffer fragment level)
  (let* ((pending (concatenate '(vector (unsigned-byte 8)) buffer fragment))
         (position 0)
         (messages nil))
    (loop while (<= (+ position 4) (length pending))
          for body-length = (+ (ash (aref pending (+ position 1)) 16)
                               (ash (aref pending (+ position 2)) 8)
                               (aref pending (+ position 3)))
          for message-end = (+ position 4 body-length)
          do (when (> body-length cl-tls-kit::+tls13-max-handshake-body-length+)
               (error "OpenSSL sent an oversized TLS handshake message"))
             (when (> message-end (length pending))
               (return))
             (push (subseq pending position message-end) messages)
             (setf position message-end))
    (dolist (message (nreverse messages))
      (%server-openssl-e2e-dispatch-handshake
       session provider stream message level))
    (when (%server-openssl-e2e-session-alert-description session)
      (error "TLS server driver raised alert ~S"
             (%server-openssl-e2e-session-alert-description session)))
    (subseq pending position)))

(defun %server-openssl-e2e-serve-connection (session provider stream)
  (let ((handshake-buffer (make-array 0 :element-type '(unsigned-byte 8))))
    (loop until (%server-openssl-e2e-session-ticket-issued-p session)
          do (multiple-value-bind (content-type version body wire)
                 (%server-openssl-e2e-read-record stream)
               (declare (ignore version))
               (unless content-type
                 (error "OpenSSL closed before receiving a session ticket"))
               (cond
                 ((= content-type 20)
                  (unless (equalp body #(1))
                    (error "OpenSSL sent an invalid compatibility CCS")))
                 ((= content-type cl-tls-kit:+tls-content-type-handshake+)
                  (setf handshake-buffer
                        (%server-openssl-e2e-feed-handshakes
                         session provider stream handshake-buffer body :initial)))
                 ((= content-type cl-tls-kit:+tls-content-type-application-data+)
                  (let* ((level (if (%server-openssl-e2e-session-handshake-complete-p
                                     session)
                                    :application
                                    :handshake))
                         (state (or (gethash (list :read level)
                                             (%server-openssl-e2e-session-read-states
                                              session))
                                    (error "OpenSSL sent encrypted data before its traffic secret")))
                         (plaintext
                           (cl-tls-kit:decrypt-tls13-traffic-record wire state))
                         (inner-type (cl-tls-kit:tls-plaintext-content-type plaintext))
                         (fragment (cl-tls-kit:tls-plaintext-fragment plaintext)))
                    (cond
                      ((= inner-type cl-tls-kit:+tls-content-type-handshake+)
                       (setf handshake-buffer
                             (%server-openssl-e2e-feed-handshakes
                              session provider stream handshake-buffer fragment level)))
                      ((= inner-type cl-tls-kit:+tls-content-type-application-data+)
                       (error "OpenSSL sent unexpected application data"))
                      ((= inner-type cl-tls-kit:+tls-content-type-alert+)
                       (error "OpenSSL closed before the server issued a ticket"))
                      (t
                       (error "OpenSSL sent an invalid TLS inner content type")))))
                 (t
                  (error "OpenSSL sent an unexpected plaintext TLS record")))))
    (unless (and (%server-openssl-e2e-session-handshake-complete-p session)
                 (gethash (list :write :application)
                          (%server-openssl-e2e-session-write-states session)))
      (error "TLS server issued a ticket before the handshake completed"))
    (%server-openssl-e2e-write-record
     stream (cl-tls-kit:make-tls-plaintext
             cl-tls-kit:+tls-content-type-alert+ #(1 0))
     (gethash (list :write :application)
              (%server-openssl-e2e-session-write-states session)))
    session))

(defun %server-openssl-e2e-client-arguments
    (openssl port groups &key session-in session-out (suite #x1301))
  (append
   (list openssl "s_client" "-connect" (format nil "127.0.0.1:~D" port)
         "-tls1_3" "-servername" "localhost" "-alpn" "h2,http/1.1"
         "-groups" groups "-ign_eof")
   (when session-in (list "-sess_in" session-in))
   (when session-out
     (list "-sess_out" session-out "-msg" "-trace" "-msgfile"
           (format nil "~A.trace" session-out)))
   (when (or (= suite #x1302) (= suite #x1303))
     (list "-ciphersuites"
           (case suite
             (#x1302 "TLS_AES_256_GCM_SHA384")
             (#x1303 "TLS_CHACHA20_POLY1305_SHA256"))))))

(defun %server-openssl-e2e-run-connection
    (openssl provider certificate-chain private-key ticket-key-store groups
             &key session-in session-out (suite #x1301) (server-groups '(#x001d)))
  (multiple-value-bind (listener port) (%server-openssl-e2e-open-listener)
    (let* ((socket-close
             (symbol-function
              (%server-openssl-e2e-socket-symbol "SOCKET-CLOSE")))
           (socket-accept
             (symbol-function
              (%server-openssl-e2e-socket-symbol "SOCKET-ACCEPT")))
           (socket-stream
             (symbol-function
              (%server-openssl-e2e-socket-symbol "SOCKET-MAKE-STREAM")))
           (server
             (cl-tls-kit:make-tls13-server-driver
              :provider provider :certificate-chain certificate-chain
              :private-key private-key :alpn-protocols '("http/1.1")
              :ticket-key-store ticket-key-store
              :supported-groups server-groups :cipher-suites (vector suite)))
           (session (%make-server-openssl-e2e-session server suite))
           (process nil))
      (unwind-protect
           (progn
             (setf process
                   (uiop:launch-program
                    (%server-openssl-e2e-client-arguments
                     openssl port groups :session-in session-in
                     :session-out session-out :suite suite)
                    :input #P"/dev/null" :output #P"/dev/null"
                    :error-output #P"/dev/null" :wait nil))
             (sb-ext:with-timeout 30
               (multiple-value-bind (peer-socket peer-address)
                   (funcall socket-accept listener)
                 (declare (ignore peer-address))
                 (let ((stream nil))
                   (unwind-protect
                        (progn
                          (setf stream
                                (funcall socket-stream peer-socket :input t :output t
                                         :element-type '(unsigned-byte 8)))
                          (%server-openssl-e2e-serve-connection
                           session provider stream))
                     (when stream (ignore-errors (close stream)))
                     (ignore-errors (funcall socket-close peer-socket))))))
             (let ((exit-code (sb-ext:with-timeout 10
                                (uiop:wait-process process))))
               (setf process nil)
               (unless (zerop exit-code)
                 (error "OpenSSL s_client exited with status ~D" exit-code)))
             session)
        (when process
          (when (uiop:process-alive-p process)
            (ignore-errors (uiop:terminate-process process)))
          (ignore-errors (uiop:wait-process process)))
        (ignore-errors (funcall socket-close listener))))))

(defun %server-openssl-e2e-certificate-der (path)
  (cl-tls-kit:pem-block-der
   (first (cl-tls-kit:pem-decode (uiop:read-file-string path)))))

(defun run-server-openssl-e2e-tests ()
  (unless (find-package "CRYPTO-KIT")
    (error "OpenSSL server E2E requires cl-crypto-kit in the canonical test process"))
  (let* ((openssl (or (uiop:getenv "OPENSSL") "openssl"))
         (selected 0)
         (assertions 0))
    (multiple-value-bind (output error-output exit-code)
        (uiop:run-program '("mktemp" "-d") :output :string :error-output :string
                          :ignore-error-status t)
      (declare (ignore error-output))
      (check (zerop exit-code) "mktemp creates a server E2E directory")
      (let* ((directory (pathname
                         (format nil "~A/"
                                 (string-right-trim
                                  '(#\Newline #\Return #\Space #\Tab) output))))
             (certificate (namestring (merge-pathnames "server.crt" directory)))
             (key (namestring (merge-pathnames "server.key" directory)))
             (session (namestring (merge-pathnames "session.pem" directory)))
             (provider (cl-tls-kit:make-cl-crypto-kit-provider))
             (ticket-key-store (cl-tls-kit:make-tls13-server-ticket-key-store))
             (certificate-chain nil)
             (private-key nil))
        (unwind-protect
             (progn
               (%openssl-e2e-certificate openssl certificate key "localhost" 1
                                         :key-type :ecdsa)
               (setf certificate-chain
                     (list (%server-openssl-e2e-certificate-der certificate))
                     private-key (%openssl-e2e-ecdsa-private-key openssl key))
               (incf selected)
               (let ((normal
                       (%server-openssl-e2e-run-connection
                        openssl provider certificate-chain private-key
                        ticket-key-store "X25519" :session-out session)))
                 (incf assertions)
                 (check (and (%server-openssl-e2e-session-handshake-complete-p normal)
                             (not (%server-openssl-e2e-session-resumed-p normal)))
                        "OpenSSL completes a full TLS 1.3 handshake")
                 (incf assertions)
                 (check (string= (%server-openssl-e2e-session-negotiated-alpn normal)
                                 "http/1.1")
                        "OpenSSL negotiates the server ALPN selection")
                 (incf assertions)
                 (progn
                   (check (%server-openssl-e2e-session-ticket-issued-p normal)
                          "TLS server driver emits a session ticket")
                   (incf assertions)
                   (let ((trace
                           (uiop:read-file-string
                            (format nil "~A.trace" session))))
                     (check (search "NewSessionTicket" trace)
                            "OpenSSL receives a NewSessionTicket"))
                   (incf assertions)
                   (check (probe-file session)
                          "OpenSSL saves TLS 1.3 session state")
                   (incf assertions)
                   (check (plusp (with-open-file (stream session :direction :input)
                                   (file-length stream)))
                          "OpenSSL saves non-empty TLS 1.3 session state"))
                 (incf assertions)
                 (check (= (%server-openssl-e2e-session-client-hello-count normal) 1)
                        "the normal handshake sends one ClientHello"))
               (progn
                 (incf selected)
                 (let ((retry
                         (%server-openssl-e2e-run-connection
                          openssl provider certificate-chain private-key
                          ticket-key-store "P-256:X25519")))
                   (incf assertions)
                   (check (= (%server-openssl-e2e-session-hello-retry-count retry) 1)
                          "X25519-only server requests a HelloRetryRequest")
                   (incf assertions)
                   (check (and (= (%server-openssl-e2e-session-client-hello-count retry) 2)
                               (= (%server-openssl-e2e-session-hello-retry-group retry)
                                  #x001d))
                          "OpenSSL retries ClientHello with the requested X25519 group")
                   (incf assertions)
                   (check (and (%server-openssl-e2e-session-handshake-complete-p retry)
                               (not (%server-openssl-e2e-session-resumed-p retry)))
                          "OpenSSL completes a full handshake after HelloRetryRequest")
                   (incf assertions)
                   (check (string= (%server-openssl-e2e-session-negotiated-alpn retry)
                                   "http/1.1")
                          "OpenSSL negotiates ALPN after HelloRetryRequest")))
               (progn
                 (incf selected)
                 (let ((sha384-retry
                         (%server-openssl-e2e-run-connection
                          openssl provider certificate-chain private-key
                          ticket-key-store "P-256:X25519" :suite #x1302
                          :server-groups '(#x001d))))
                   (incf assertions)
                   (check (and (= (%server-openssl-e2e-session-client-hello-count
                                   sha384-retry) 2)
                               (= (%server-openssl-e2e-session-hello-retry-count
                                   sha384-retry) 1))
                          "OpenSSL negotiates SHA-384 through HelloRetryRequest")
                   (incf assertions)
                   (check (and (= (%server-openssl-e2e-session-hello-retry-group
                                   sha384-retry) #x001d)
                               (= (%server-openssl-e2e-session-negotiated-suite
                                   sha384-retry) #x1302))
                          "server retains the SHA-384 suite and requested retry group")
                   (incf assertions)
                   (check (and (%server-openssl-e2e-session-handshake-complete-p
                                sha384-retry)
                               (not (%server-openssl-e2e-session-resumed-p sha384-retry)))
                          "OpenSSL verifies the SHA-384 HRR handshake Finished")
                   (incf assertions)
                   (check (string= (%server-openssl-e2e-session-negotiated-alpn
                                    sha384-retry) "http/1.1")
                          "OpenSSL negotiates ALPN after SHA-384 HelloRetryRequest")))
               (progn
                 (incf selected)
                 (let ((resumed
                         (%server-openssl-e2e-run-connection
                          openssl provider certificate-chain private-key
                          ticket-key-store "X25519" :session-in session)))
                   (incf assertions)
                   (check (and (%server-openssl-e2e-session-handshake-complete-p resumed)
                               (%server-openssl-e2e-session-resumed-p resumed))
                          "server confirms OpenSSL resumed with the saved PSK")
                   (incf assertions)
                   (check (string= (%server-openssl-e2e-session-negotiated-alpn resumed)
                                   "http/1.1")
                          "OpenSSL retains ALPN on a resumed handshake")))
               (progn
                 (incf selected)
                 (let ((chacha
                         (%server-openssl-e2e-run-connection
                          openssl provider certificate-chain private-key
                          ticket-key-store "P-256" :suite #x1303
                          :server-groups '(#x0017))))
                   (incf assertions)
                   (check (and (= (%server-openssl-e2e-session-negotiated-group chacha)
                                  #x0017)
                               (= (%server-openssl-e2e-session-negotiated-suite chacha)
                                  #x1303)
                               (zerop (%server-openssl-e2e-session-hello-retry-count chacha)))
                          "OpenSSL negotiates P-256 with ChaCha20-Poly1305 without HelloRetryRequest")
                   (incf assertions)
                   (check (and (%server-openssl-e2e-session-handshake-complete-p chacha)
                               (not (%server-openssl-e2e-session-resumed-p chacha)))
                          "OpenSSL completes a full P-256 ChaCha20-Poly1305 handshake")
                   (incf assertions)
                   (check (string= (%server-openssl-e2e-session-negotiated-alpn chacha)
                                   "http/1.1")
                          "OpenSSL negotiates ALPN with P-256 and ChaCha20-Poly1305")))
               (check (= selected 5) "OpenSSL server E2E selects all five cases")
               (check (= assertions 20) "OpenSSL server E2E runs all assertions")
               (format t "OpenSSL server E2E: selected test count: ~D; assertions: ~D~%"
                       selected assertions)
               t)
          (ignore-errors (uiop:delete-directory-tree directory :validate t))
          (check (not (probe-file directory))
                 "server E2E temporary credentials and session are removed"))))))
