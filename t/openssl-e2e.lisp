(in-package #:cl-tls-kit/test)

(defparameter *openssl-e2e-port* 45100)

(defun %openssl-e2e-call (name)
  (let* ((package (find-package "CRYPTO-KIT"))
         (symbol (and package (find-symbol name package))))
    (unless (and symbol (fboundp symbol))
      (error "CL-CRYPTO-KIT:~A is unavailable" name))
    (symbol-function symbol)))

(defun %openssl-e2e-key-exchange ()
  (let ((random (%openssl-e2e-call "RANDOM-OCTETS"))
        (x25519 (%openssl-e2e-call "X25519"))
        (p256-generate (%openssl-e2e-call "P256-GENERATE-KEYPAIR"))
        (p256-ecdh (%openssl-e2e-call "P256-ECDH")))
    (list :random random
          :generate
          (lambda (group)
            (if (= group #x001d)
                (let ((private (funcall random 32)))
                  (let ((base (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 0)))
                    (setf (aref base 0) 9)
                    (values private (nth-value 0 (funcall x25519 private base)))))
                (funcall p256-generate)))
          :shared-secret
          (lambda (group private public)
            (if (= group #x001d)
                (multiple-value-bind (secret all-zero)
                    (funcall x25519 private public)
                  (when all-zero (error "X25519 produced an all-zero secret"))
                  secret)
                (funcall p256-ecdh private public))))))

(defun %openssl-e2e-run (program arguments)
  (multiple-value-bind (output error-output exit-code)
      (uiop:run-program (cons program arguments)
                        :output :string :error-output :string
                        :ignore-error-status t)
    (declare (ignore error-output))
    (values output exit-code)))

(defun %openssl-e2e-temp-directory ()
  (multiple-value-bind (output exit-code)
      (%openssl-e2e-run
       "mktemp"
       (list "-d" (namestring
                   (merge-pathnames "cl-tls-kit-openssl-e2e.XXXXXXXX"
                                    (uiop:temporary-directory)))))
    (unless (zerop exit-code)
      (error "OpenSSL E2E temporary directory creation failed"))
    (uiop:ensure-directory-pathname
     (string-trim '(#\Space #\Newline #\Return) output))))

(defun %openssl-e2e-cleanup-directory (directory files)
  (let ((failures nil))
    (dolist (file files)
      (handler-case
          (when (probe-file file) (delete-file file))
        (error (condition) (push condition failures))))
    (handler-case
        (uiop:delete-empty-directory directory)
      (error (condition) (push condition failures)))
    (nreverse failures)))

(defun %openssl-e2e-certificate (openssl path key-name common-name days
                                  &key ca (key-type :rsa))
  (multiple-value-bind (output exit-code)
      (%openssl-e2e-run
       openssl
       (append (list "req" "-x509")
               (if (eq key-type :ecdsa)
                   (list "-newkey" "ec" "-pkeyopt" "ec_paramgen_curve:P-256")
                   (list "-newkey" "rsa:2048"))
               (list "-nodes"
             "-days" (princ-to-string days) "-subj"
             (format nil "/CN=~A" common-name)
             "-addext" (format nil "subjectAltName=DNS:~A" common-name)
             "-addext" (if ca
                            "basicConstraints=critical,CA:TRUE"
                            "basicConstraints=critical,CA:FALSE")
             "-addext" (if ca
                            "keyUsage=critical,keyCertSign,digitalSignature"
                            "keyUsage=critical,digitalSignature")
             "-addext" "extendedKeyUsage=serverAuth"
             "-keyout" key-name "-out" path)))
    (declare (ignore output))
    (unless (zerop exit-code)
      (error "OpenSSL certificate generation failed"))))

(defun %openssl-e2e-start (openssl port certificate key suite groups &key chain)
  (uiop:launch-program
   (append (list openssl "s_server" "-accept" (princ-to-string port)
                 "-cert" certificate "-key" key "-tls1_3"
                 "-ciphersuites" suite "-groups" groups "-alpn" "http/1.1"
                 "-no_ticket" "-www" "-quiet")
           (when chain (list "-cert_chain" chain)))
   :output *standard-output* :error-output *error-output*
   :wait nil))

(defun %openssl-e2e-pem-certificate (path)
  (cl-tls-kit.x509:parse-certificate-der
   (cl-tls-kit:pem-block-der
    (first (cl-tls-kit:pem-decode (uiop:read-file-string path))))))

(defun %openssl-e2e-driver (host port provider suite groups &key trust-anchors now)
  (cl-tls-kit:make-tls13-client-driver-over-tcp
   host port
   :provider provider
   :key-exchange (%openssl-e2e-key-exchange)
   :on-send nil
   :alpn '("http/1.1")
   :cipher-suites (vector suite)
   :supported-groups groups
   :hostname "localhost"
   :trust-anchors trust-anchors
   :now (or now (get-universal-time))))

(defun %openssl-e2e-http-request ()
  (map 'vector #'char-code
       (format nil "GET / HTTP/1.0~C~CHost: localhost~C~CConnection: close~C~C~C~C"
               #\Return #\Linefeed #\Return #\Linefeed
               #\Return #\Linefeed #\Return #\Linefeed)))

(defun %openssl-e2e-read-application (driver)
  (loop repeat 16
        for plaintext = (cl-tls-kit:tls13-client-driver-read-record driver)
        when plaintext return (cl-tls-kit:tls-plaintext-fragment plaintext)
        finally (error "OpenSSL did not return application data")))

(defun %openssl-e2e-listening-p (port)
  (let ((socket (uiop:symbol-call '#:sb-bsd-sockets
                                 '#:make-inet-socket :stream :tcp)))
    (unwind-protect
         (handler-case
             (progn
               (uiop:symbol-call '#:sb-bsd-sockets '#:socket-connect
                                 socket #(127 0 0 1) port)
               t)
           (error (condition)
             (if (typep condition
                        (find-symbol "CONNECTION-REFUSED-ERROR" '#:sb-bsd-sockets))
                 nil
                 (error condition))))
      (uiop:symbol-call '#:sb-bsd-sockets '#:socket-close socket))))

(defun %openssl-e2e-wait-ready (server port suite groups)
  (let ((deadline (+ (get-internal-real-time) internal-time-units-per-second)))
    (labels ((fail (reason)
               (error "OpenSSL readiness failed: ~A; suite=~A groups=~A port=~D child-pid=~D child-exit=~A"
                      reason suite groups port (uiop:process-info-pid server)
                      (if (uiop:process-alive-p server)
                          "running"
                          (uiop:wait-process server)))))
      (loop
        (unless (uiop:process-alive-p server)
          (fail "exited"))
        (let ((remaining (/ (- deadline (get-internal-real-time))
                            internal-time-units-per-second)))
          (unless (plusp remaining)
            (fail "not-listening (deadline-before-connect)"))
          (handler-case
              (sb-ext:with-timeout remaining
                (when (%openssl-e2e-listening-p port)
                  (unless (uiop:process-alive-p server)
                    (fail "exited"))
                  (when (>= (get-internal-real-time) deadline)
                    (fail "connected-after-deadline"))
                  (return-from %openssl-e2e-wait-ready t)))
            (sb-ext:timeout () (fail "readiness-probe-timeout")))
          (sleep (max 0 (min 0.01 (/ (- deadline (get-internal-real-time))
                                    internal-time-units-per-second)))))))))

(define-condition openssl-e2e-cleanup-error (simple-error)
  ((failures :initarg :failures :reader %openssl-e2e-cleanup-failures)))

(define-condition openssl-e2e-cleanup-warning (simple-warning)
  ((failures :initarg :failures :reader %openssl-e2e-cleanup-failures)
   (cause :initarg :cause :reader %openssl-e2e-cleanup-cause)))

(defun %openssl-e2e-with-process-cleanup
    (process function &key (terminate #'uiop:terminate-process)
                           (wait #'uiop:wait-process)
                           (alive-p #'uiop:process-alive-p))
  (let ((primary nil)
        (failures nil))
    (labels ((attempt (operation function)
               (handler-case
                   (sb-ext:with-timeout 1 (funcall function process))
                 (serious-condition (condition)
                   (push (cons operation condition) failures)
                   nil))))
      (unwind-protect
           ;; Only escaping conditions are primary, not expected failures caught by the body.
           (handler-case (funcall function)
             (serious-condition (condition)
               (setf primary condition)
               (error condition)))
        (attempt :terminate terminate)
        (attempt :wait wait)
        (when (attempt :alive alive-p)
          (push (cons :surviving
                      (make-condition 'simple-error
                                      :format-control "Owned process survived cleanup"))
                failures))
        (when failures
          (let ((ordered (nreverse failures)))
            (if primary
                (warn 'openssl-e2e-cleanup-warning
                      :cause primary
                      :failures ordered
                      :format-control "OpenSSL process cleanup failed while handling ~A: ~{~A~^; ~}"
                      :format-arguments (list primary ordered))
                (error 'openssl-e2e-cleanup-error
                       :failures ordered
                       :format-control "OpenSSL process cleanup failed: ~{~A~^; ~}"
                       :format-arguments (list ordered)))))))))

(defun run-openssl-cleanup-tests ()
  (let ((selected 0)
        (assertions 0))
    (labels ((expect (value message)
               (incf assertions)
               (unless value
                 (format t "Cleanup failure selected=~D assertions=~D: ~A~%"
                         selected assertions message))
               (check value message))
             (injected-error (operation)
               (make-condition 'simple-error
                               :format-control "Injected ~A failure"
                               :format-arguments (list operation))))
      (dolist (primary-p '(nil t))
        (dolist (mode '(:terminate :wait :both :surviving :alive :none))
          (incf selected)
          (let* ((process (gensym "OWNED-PROCESS"))
                 (primary (injected-error :body))
                 (terminate-error (injected-error :terminate))
                 (wait-error (injected-error :wait))
                 (alive-error (injected-error :alive))
                 (events nil)
                 (terminate-child nil)
                 (wait-child nil)
                 (alive-child nil)
                 (callback-count 0)
                 (warnings nil)
                 (result nil)
                 (caught
                   (handler-bind
                       ((warning (lambda (condition)
                                   (push condition warnings)
                                   (muffle-warning condition))))
                   (handler-case
                       (progn
                         (setf result
                             (multiple-value-list
                              (%openssl-e2e-with-process-cleanup
                               process
                               (lambda ()
                                 (incf callback-count)
                                 (if primary-p
                                     (error primary)
                                     (values :complete :secondary)))
                               :terminate
                               (lambda (child)
                                 (push :terminate events)
                                 (setf terminate-child child)
                                 (when (member mode '(:terminate :both))
                                   (error terminate-error)))
                               :wait
                               (lambda (child)
                                 (push :wait events)
                                 (setf wait-child child)
                                 (when (member mode '(:wait :both))
                                   (error wait-error)))
                               :alive-p
                               (lambda (child)
                                 (push :alive events)
                                 (setf alive-child child)
                                 (when (eq mode :alive) (error alive-error))
                                 (eq mode :surviving)))))
                         nil)
                     (error (condition) condition)))))
            (expect (= callback-count 1) "body callback runs exactly once")
            (expect (eq terminate-child process)
                    "terminate receives only the owned process")
            (expect (eq wait-child process)
                    "wait receives only the owned process")
            (expect (eq alive-child process)
                    "postcondition checks only the owned process")
            (expect (= (length warnings)
                       (if (and primary-p (not (eq mode :none))) 1 0))
                    "escaping primary exposes cleanup failures in exactly one warning")
            (when warnings
              (let* ((warning (first warnings))
                     (failures (%openssl-e2e-cleanup-failures warning)))
                (expect (typep warning 'openssl-e2e-cleanup-warning)
                        "cleanup diagnostic is a typed simple warning")
                (expect (typep warning 'simple-warning)
                        "cleanup diagnostic supports ordinary warning handlers")
                (expect (eq (%openssl-e2e-cleanup-cause warning) primary)
                        "cleanup warning retains the identical primary cause")
                (expect (equal (mapcar #'car failures)
                               (ecase mode
                                 (:terminate '(:terminate))
                                 (:wait '(:wait))
                                 (:both '(:terminate :wait))
                                 (:surviving '(:surviving))
                                 (:alive '(:alive))))
                        "warning retains every cleanup failure in operation order")
                (when (member mode '(:terminate :both))
                  (expect (eq (cdr (assoc :terminate failures)) terminate-error)
                          "warning retains the identical terminate failure"))
                (when (member mode '(:wait :both))
                  (expect (eq (cdr (assoc :wait failures)) wait-error)
                          "warning retains the identical wait failure"))
                (when (eq mode :alive)
                  (expect (eq (cdr (assoc :alive failures)) alive-error)
                          "warning retains the identical process-state failure"))
                (when (eq mode :surviving)
                  (expect (string= (princ-to-string (cdr (assoc :surviving failures)))
                                   "Owned process survived cleanup")
                          "warning identifies a surviving owned process"))))
            (cond
              (primary-p
               (expect (eq caught primary)
                       "cleanup preserves the identical escaping body condition"))
              ((eq mode :none)
               (expect (null caught) "successful cleanup does not fail the test")
               (expect (equal result '(:complete :secondary))
                       "successful cleanup preserves all callback values"))
              (t
               (expect (typep caught 'openssl-e2e-cleanup-error)
                       (format nil "normal completion exposes cleanup failure ~A" mode))
               (let ((failures (%openssl-e2e-cleanup-failures caught)))
                 (when (member mode '(:terminate :both))
                   (expect (eq (cdr (assoc :terminate failures)) terminate-error)
                           "terminate failure retains its condition"))
                 (when (member mode '(:wait :both))
                   (expect (eq (cdr (assoc :wait failures)) wait-error)
                           "wait failure retains its condition"))
                 (when (eq mode :surviving)
                   (expect (assoc :surviving failures)
                           "surviving process fails the cleanup postcondition"))
                 (when (eq mode :alive)
                   (expect (eq (cdr (assoc :alive failures)) alive-error)
                           "failed process-state query fails cleanup")))))
            (expect (equal (reverse events) '(:terminate :wait :alive))
                    "both cleanup actions and the postcondition run exactly once"))))
      (incf selected)
      (let* ((expected (injected-error :readiness))
             (cleanup (injected-error :terminate))
             (events nil)
             (caught
               (handler-case
                   (%openssl-e2e-with-process-cleanup
                    :owned-control
                    (lambda ()
                      (handler-case (error expected)
                        (error (condition)
                          (expect (eq condition expected)
                                  "expected readiness failure is caught inside the body"))))
                    :terminate (lambda (child)
                                 (declare (ignore child))
                                 (push :terminate events)
                                 (error cleanup))
                    :wait (lambda (child)
                            (declare (ignore child))
                            (push :wait events))
                    :alive-p (lambda (child)
                               (declare (ignore child))
                               (push :alive events)
                               nil))
                 (error (condition) condition))))
        (expect (typep caught 'openssl-e2e-cleanup-error)
                "caught readiness failure cannot mask a cleanup failure")
        (expect (eq (cdr (assoc :terminate (%openssl-e2e-cleanup-failures caught)))
                    cleanup)
                "caught readiness control exposes the cleanup condition")
        (expect (equal (reverse events) '(:terminate :wait :alive))
                "caught readiness control attempts both cleanup actions"))
      (incf selected)
      (let ((child (uiop:launch-program '("sleep" "5") :wait nil)))
        (%openssl-e2e-with-process-cleanup
         child
         (lambda ()
           (expect (uiop:process-alive-p child)
                   "known-good cleanup control owns a live child")))
        (expect (not (uiop:process-alive-p child))
                "known-good cleanup control terminates and reaps its child"))
      (dolist (blocked '(:terminate :wait))
        (incf selected)
        (let* ((events nil)
               (caught
                 (handler-case
                     (%openssl-e2e-with-process-cleanup
                      :owned-control (lambda () :complete)
                      :terminate (lambda (child)
                                   (declare (ignore child))
                                   (push :terminate events)
                                   (when (eq blocked :terminate) (sleep 2)))
                      :wait (lambda (child)
                              (declare (ignore child))
                              (push :wait events)
                              (when (eq blocked :wait) (sleep 2)))
                      :alive-p (lambda (child)
                                 (declare (ignore child))
                                 (push :alive events)
                                 nil))
                   (serious-condition (condition) condition))))
          (expect (typep caught 'openssl-e2e-cleanup-error)
                  "blocked cleanup action fails within its one-second limit")
          (expect (typep (cdr (assoc blocked (%openssl-e2e-cleanup-failures caught)))
                         'sb-ext:timeout)
                  "cleanup retains the timeout condition")
          (expect (equal (reverse events) '(:terminate :wait :alive))
                  "timed-out cleanup still attempts both actions and the postcondition")))
      (incf selected)
      (let* ((primary (make-condition 'sb-ext:timeout))
             (terminate-error (injected-error :terminate))
             (wait-error (injected-error :wait))
             (warnings nil)
             (events nil)
             (caught
               (handler-bind
                   ((warning (lambda (condition)
                               (push condition warnings)
                               (muffle-warning condition))))
               (handler-case
                   (%openssl-e2e-with-process-cleanup
                    :owned-control (lambda () (error primary))
                    :terminate (lambda (child)
                                 (declare (ignore child))
                                 (push :terminate events)
                                 (error terminate-error))
                    :wait (lambda (child)
                            (declare (ignore child))
                            (push :wait events)
                            (error wait-error))
                    :alive-p (lambda (child)
                               (declare (ignore child))
                               (push :alive events)
                               nil))
                 (serious-condition (condition) condition)))))
        (expect (eq caught primary)
                "cleanup preserves the identical escaping timeout condition")
        (expect (= (length warnings) 1) "timeout cleanup emits exactly one warning")
        (expect (eq (%openssl-e2e-cleanup-cause (first warnings)) primary)
                "timeout warning retains the identical primary cause")
        (expect (eq (cdr (assoc :terminate (%openssl-e2e-cleanup-failures (first warnings))))
                    terminate-error)
                "timeout warning retains the identical terminate failure")
        (expect (eq (cdr (assoc :wait (%openssl-e2e-cleanup-failures (first warnings))))
                    wait-error)
                "timeout warning retains the identical wait failure")
        (expect (equal (reverse events) '(:terminate :wait :alive))
                "primary timeout still attempts both cleanup actions"))
      (check (= selected 17) "all cleanup controls ran")
      (check (plusp assertions) "cleanup controls ran assertions")
      (format t "OpenSSL cleanup: selected test count: ~D; assertions: ~D~%"
              selected assertions)
      t)))

(defun %openssl-e2e-with-server
    (openssl suite groups certificate key function &key chain)
  (require :sb-bsd-sockets)
  (let* ((port (prog1 *openssl-e2e-port* (incf *openssl-e2e-port*)))
         (server (%openssl-e2e-start openssl port certificate key suite groups
                                     :chain chain)))
    (%openssl-e2e-with-process-cleanup
     server
     (lambda ()
       (%openssl-e2e-wait-ready server port suite groups)
       (format t "OpenSSL server ready: suite=~A groups=~A port=~D child-pid=~D~%"
               suite groups port (uiop:process-info-pid server))
       (funcall function port)))))

(defun run-openssl-readiness-tests ()
  (let* ((openssl (or (uiop:getenv "OPENSSL") "openssl"))
         (directory (%openssl-e2e-temp-directory))
         (certificate (namestring (merge-pathnames "server.crt" directory)))
         (key (namestring (merge-pathnames "server.key" directory)))
         (suite "TLS_AES_128_GCM_SHA256")
         (selected 0)
         (assertions 0))
    (labels ((expect (value message)
               (incf assertions)
               (check value message))
             (failure (function)
               (handler-case (progn (funcall function) nil)
                 (simple-error (condition) (princ-to-string condition)))))
      (unwind-protect
           (progn
             (%openssl-e2e-certificate openssl certificate key "localhost" 1 :key-type :ecdsa)
             (incf selected)
             (let ((called nil)
                   (port *openssl-e2e-port*))
               (let ((message
                       (failure
                        (lambda ()
                          (%openssl-e2e-with-server
                           openssl suite "INVALID_READINESS_GROUP" certificate key
                           (lambda (port)
                             (declare (ignore port))
                             (setf called t)))))))
                 (expect (not called) "exited server cannot enter the test callback")
                 (expect message "exited server fails the original readiness gate")
                 (expect (search suite message) "exit diagnostic identifies the suite")
                 (expect (search "INVALID_READINESS_GROUP" message)
                         "exit diagnostic identifies the groups")
                 (expect (search (format nil "port=~D" port) message)
                         "exit diagnostic identifies the port")
                 (expect (member "child-exit=1"
                                 (uiop:split-string message :separator '(#\Space))
                                 :test #'string=)
                         "exit diagnostic reports the actual child exit")))
             (incf selected)
             (require :sb-bsd-sockets)
             (let ((socket (uiop:symbol-call '#:sb-bsd-sockets
                                            '#:make-inet-socket :stream :tcp)))
               (unwind-protect
                    (progn
                      (uiop:symbol-call '#:sb-bsd-sockets '#:socket-bind
                                        socket #(127 0 0 1) 0)
                      (multiple-value-bind (address port)
                          (uiop:symbol-call '#:sb-bsd-sockets '#:socket-name socket)
                        (declare (ignore address))
                        (let ((child (uiop:launch-program '("sleep" "5") :wait nil)))
                          (%openssl-e2e-with-process-cleanup
                           child
                           (lambda ()
                             (expect (uiop:process-alive-p child)
                                     "not-ready control process is alive before the gate")
                             (let ((message
                                     (failure
                                      (lambda ()
                                        (%openssl-e2e-wait-ready child port suite "X25519")))))
                               (expect message "live non-listener fails readiness")
                               (expect (or (search "not-listening (deadline-before-connect)"
                                                   message)
                                           (search "readiness-probe-timeout" message))
                                       "bound non-listener identifies the actual timeout phase")
                               (expect (not (search "connected-after-deadline" message))
                                       "bound non-listener never reports a successful connect")
                               (expect (search (format nil "port=~D" port) message)
                                       "deadline diagnostic identifies the port")
                               (expect (search "child-exit=running" message)
                                       "deadline diagnostic distinguishes a live child")
                               (expect (uiop:process-alive-p child)
                                       "readiness failure does not terminate the child")))))))
                 (uiop:symbol-call '#:sb-bsd-sockets '#:socket-close socket)))
             (incf selected)
             (let ((called 0)
                   (provider (cl-tls-kit:make-cl-crypto-kit-provider)))
               (%openssl-e2e-with-server
                openssl suite "X25519" certificate key
                (lambda (port)
                  (incf called)
                  (let ((driver (%openssl-e2e-driver
                                 "127.0.0.1" port provider #x1301 '(#x001d)
                                 :trust-anchors
                                 (list (%openssl-e2e-pem-certificate certificate)))))
                    (unwind-protect
                         (progn
                           (cl-tls-kit:tls13-client-driver-connect driver)
                           (expect (eq (cl-tls-kit::tls13-client-driver-state driver)
                                       :connected)
                                   "readiness probe preserves the TLS server fixture")
                           (expect (string=
                                    (cl-tls-kit:tls13-client-driver-negotiated-alpn driver)
                                    "http/1.1")
                                   "positive control negotiates the original ALPN")
                           (cl-tls-kit:tls13-client-driver-write
                            driver (%openssl-e2e-http-request))
                           (expect
                            (search "HTTP/1.0"
                                    (map 'string #'code-char
                                         (%openssl-e2e-read-application driver)))
                            "readiness probe preserves subsequent HTTP service"))
                      (cl-tls-kit:tls13-client-driver-close driver)))))
               (expect (= called 1) "ready gate enters the callback exactly once")))
        (let ((failures (%openssl-e2e-cleanup-directory
                         directory (list certificate key))))
          (check (null failures) "readiness fixture cleanup succeeds")))
      (check (= selected 3) "all readiness controls ran")
      (check (plusp assertions) "readiness checks ran assertions")
      (format t "OpenSSL readiness: selected test count: ~D; assertions: ~D~%"
              selected assertions)
      t)))

(defun %openssl-e2e-expect-verification
    (openssl provider certificate key trust-anchor now expected)
  (%openssl-e2e-with-server
   openssl "TLS_AES_128_GCM_SHA256" "X25519" certificate key
   (lambda (port)
     (let ((driver (%openssl-e2e-driver "127.0.0.1" port provider #x1301
                                        '(#x001d) :trust-anchors
                                        (list trust-anchor) :now now))
           (condition nil))
       (unwind-protect
            (handler-case
                (cl-tls-kit:tls13-client-driver-connect driver)
              (cl-tls-kit:tls13-client-driver-error (error)
                (let ((reason (cl-tls-kit:tls13-client-driver-error-reason error)))
                  (setf condition (getf (cdr reason) :condition)))))
         (cl-tls-kit:tls13-client-driver-close driver))
       (check (typep condition expected)
              "OpenSSL certificate failure has the expected condition")))))

(defun run-openssl-e2e-tests ()
  (unless (find-package "CRYPTO-KIT")
    (error "OpenSSL E2E requires cl-crypto-kit in the canonical test process"))
  (let* ((openssl (or (uiop:getenv "OPENSSL") "openssl"))
         (provider (cl-tls-kit:make-cl-crypto-kit-provider))
         (directory (%openssl-e2e-temp-directory))
         (certificate (namestring (merge-pathnames "server.crt" directory)))
         (key (namestring (merge-pathnames "server.key" directory)))
         (wrong-certificate (namestring (merge-pathnames "wrong.crt" directory)))
         (wrong-key (namestring (merge-pathnames "wrong.key" directory)))
         (other-certificate (namestring (merge-pathnames "other.crt" directory)))
         (other-key (namestring (merge-pathnames "other.key" directory)))
         (anchor-certificate (namestring (merge-pathnames "anchor.crt" directory)))
         (anchor-key (namestring (merge-pathnames "anchor.key" directory)))
         (ecdsa-certificate (namestring (merge-pathnames "ecdsa.crt" directory)))
         (ecdsa-key (namestring (merge-pathnames "ecdsa.key" directory)))
         (files (list certificate key wrong-certificate wrong-key
                      other-certificate other-key anchor-certificate anchor-key
                      ecdsa-certificate ecdsa-key))
         (body-failure nil)
         (cleanup-failures nil)
         (selected 0)
         (assertions 0))
    (unwind-protect
         (handler-case
          (progn
           (%openssl-e2e-certificate openssl certificate key "localhost" 1)
           (dolist (suite '(#x1301 #x1302 #x1303))
             (dolist (group '((#x001d) (#x0017)))
               (incf selected)
               (%openssl-e2e-with-server
                openssl
                (case suite
                  (#x1301 "TLS_AES_128_GCM_SHA256")
                  (#x1302 "TLS_AES_256_GCM_SHA384")
                  (#x1303 "TLS_CHACHA20_POLY1305_SHA256"))
                (if (= (first group) #x001d) "X25519" "P-256")
                certificate key
                (lambda (port)
                  (let ((driver (%openssl-e2e-driver "127.0.0.1" port provider
                                                     suite group :trust-anchors
                                                     (list (%openssl-e2e-pem-certificate certificate)))))
                    (unwind-protect
                         (progn
                           (cl-tls-kit:tls13-client-driver-connect driver)
                           (incf assertions)
                           (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                                      :connected)
                                  "cl-tls-kit completes an OpenSSL TLS 1.3 handshake")
                           (incf assertions)
                           (check (string= (cl-tls-kit:tls13-client-driver-negotiated-alpn driver)
                                           "http/1.1")
                                  "OpenSSL negotiates the requested ALPN")
                           (cl-tls-kit:tls13-client-driver-key-update driver 0)
                           (cl-tls-kit:tls13-client-driver-write
                            driver (%openssl-e2e-http-request))
                           (incf assertions)
                           (let ((response (%openssl-e2e-read-application driver)))
                             (check (search "HTTP/1.0" (map 'string #'code-char response))
                                    "OpenSSL accepts application data after KeyUpdate")))
                      (cl-tls-kit:tls13-client-driver-close driver)))))))
           (incf selected)
           (%openssl-e2e-with-server
            openssl "TLS_AES_128_GCM_SHA256" "P-256" certificate key
            (lambda (port)
              (let ((driver (%openssl-e2e-driver "127.0.0.1" port provider #x1301
                                                 '(#x001d #x0017) :trust-anchors
                                                 (list (%openssl-e2e-pem-certificate certificate)))))
                (unwind-protect
                     (progn
                       (cl-tls-kit:tls13-client-driver-connect driver)
                       (incf assertions)
                       (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                                  :connected)
                              "cl-tls-kit completes an OpenSSL HelloRetryRequest")
                       (incf assertions)
                       (check (string= (cl-tls-kit:tls13-client-driver-negotiated-alpn driver)
                                       "http/1.1")
                              "OpenSSL negotiates ALPN after HelloRetryRequest")
                       (cl-tls-kit:tls13-client-driver-write
                        driver (%openssl-e2e-http-request))
                       (incf assertions)
                       (check (search "HTTP/1.0"
                                      (map 'string #'code-char
                                           (%openssl-e2e-read-application driver)))
                              "OpenSSL accepts application data after HelloRetryRequest"))
                  (cl-tls-kit:tls13-client-driver-close driver)
                  (incf assertions)
                  (check (eq (cl-tls-kit::tls13-client-driver-state driver) :closed)
                         "cl-tls-kit sends close_notify")))))
           (%openssl-e2e-certificate openssl wrong-certificate wrong-key "wrong.local" 1)
           (%openssl-e2e-certificate openssl other-certificate other-key "other.local" 1)
           (%openssl-e2e-certificate openssl anchor-certificate anchor-key "localhost" 1 :ca t)
           (%openssl-e2e-certificate openssl ecdsa-certificate ecdsa-key "localhost" 1
                                     :key-type :ecdsa)
           (incf selected)
           (%openssl-e2e-with-server
            openssl "TLS_AES_128_GCM_SHA256" "X25519" anchor-certificate anchor-key
            (lambda (port)
              (let ((driver (%openssl-e2e-driver
                             "127.0.0.1" port provider #x1301 '(#x001d)
                             :trust-anchors
                             (list (%openssl-e2e-pem-certificate anchor-certificate)))))
                (unwind-protect
                     (progn
                       (cl-tls-kit:tls13-client-driver-connect driver)
                       (incf assertions)
                       (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                                  :connected)
                              "TLS 1.3 accepts a self-signed CA trust anchor with localhost SAN"))
                  (cl-tls-kit:tls13-client-driver-close driver)))))
           (incf selected)
           (%openssl-e2e-with-server
            openssl "TLS_AES_128_GCM_SHA256" "X25519" ecdsa-certificate ecdsa-key
            (lambda (port)
              (let ((driver (%openssl-e2e-driver
                             "127.0.0.1" port provider #x1301 '(#x001d)
                             :trust-anchors
                             (list (%openssl-e2e-pem-certificate ecdsa-certificate)))))
                (unwind-protect
                     (progn
                       (cl-tls-kit:tls13-client-driver-connect driver)
                       (incf assertions)
                       (check (eq (cl-tls-kit::tls13-client-driver-state driver)
                                  :connected)
                              "TLS 1.3 completes with an ECDSA P-256 certificate")
                       (cl-tls-kit:tls13-client-driver-write
                        driver (%openssl-e2e-http-request))
                       (incf assertions)
                       (check (search "HTTP/1.0"
                                      (map 'string #'code-char
                                           (%openssl-e2e-read-application driver)))
                              "OpenSSL accepts application data after ECDSA CertificateVerify"))
                  (cl-tls-kit:tls13-client-driver-close driver)))))
           (let ((anchor (%openssl-e2e-pem-certificate certificate))
                 (future (+ (get-universal-time) (* 3 86400))))
             (incf selected)
             (%openssl-e2e-expect-verification
              openssl provider certificate key anchor future
              'cl-tls-kit:certificate-expired)
             (incf assertions)
             (incf selected)
             (%openssl-e2e-expect-verification
              openssl provider wrong-certificate wrong-key
              (%openssl-e2e-pem-certificate wrong-certificate)
              (get-universal-time) 'cl-tls-kit:certificate-hostname-mismatch)
             (incf assertions)
             (incf selected)
             (%openssl-e2e-expect-verification
              openssl provider other-certificate other-key anchor
              (get-universal-time) 'cl-tls-kit:untrusted-root)
             (incf assertions))
           (multiple-value-bind (chain-selected chain-assertions)
               (run-openssl-chain-tests openssl provider)
             (incf selected chain-selected)
             (incf assertions chain-assertions))
           (incf assertions (run-pss-signature-tests))
           (check (plusp selected) "OpenSSL E2E selected at least one case")
           (check (plusp assertions) "OpenSSL E2E executed at least one assertion")
           (incf assertions 2)
           t)
          (error (condition) (setf body-failure condition)))
      (setf cleanup-failures (%openssl-e2e-cleanup-directory directory files)))
    (when body-failure
      (when cleanup-failures
        (format *error-output* "OpenSSL E2E cleanup also failed: ~{~A~^; ~}~%"
                cleanup-failures))
      (error body-failure))
    (when cleanup-failures
      (error "OpenSSL E2E cleanup failed: ~{~A~^; ~}" cleanup-failures))
    (incf assertions)
    (check (every (lambda (file) (not (probe-file file))) files)
           "OpenSSL E2E removes all temporary certificates and private keys")
    (incf assertions)
    (check (not (uiop:directory-exists-p directory))
           "OpenSSL E2E removes its temporary directory")
    (format t "OpenSSL E2E: selected test count: ~D; assertions: ~D~%"
            selected assertions)
    t))
