(in-package #:cl-tls-kit/test)

(defparameter *rfc8448-server-client-hello-wire*
  (rfc8448-%hex
   "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a
    8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91
    00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
    00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26
    00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51
    c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04
    03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
    02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01"))

(defparameter *rfc8448-server-private-key*
  (rfc8448-%hex
   "b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56 52 57 8c c8 10 e9 98 01 91 ec 8d 05 83
    08 ce a2 16 a2 1e"))

(defparameter *rfc8448-server-public-key*
  (rfc8448-%hex
   "c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69
    b1 b0 4e 75 1f 0f"))
(defparameter *rfc8448-client-public-key*
  (rfc8448-%hex
   "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13
    69 1e 52 9a af 2c"))

(defparameter *rfc8448-server-random*
  (rfc8448-%hex
   "a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55
    77 2e d3 e2 69 28"))

(defparameter *rfc8448-server-dhe-secret*
  (rfc8448-%hex
   "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62
    72 90 0f 89 49 2d"))

(defparameter *rfc8448-server-handshake-secret*
  (rfc8448-%hex
   "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9
    f0 ca 04 3f be ac"))

(defparameter *rfc8448-server-handshake-traffic-secret*
  (rfc8448-%hex
   "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be
    fd 59 d3 91 ad 38"))

(defparameter *rfc8448-server-application-traffic-secret*
  (rfc8448-%hex
   "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f
    1f 3f cb 63 16 43"))

(defparameter *rfc8448-server-resumption-master-secret*
  (rfc8448-%hex
   "7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf da f8 6c c8 56 23 1f 2d 5a ba
    46 c4 34 ec 19 6c"))

(defparameter *rfc8448-server-hello-wire*
  (rfc8448-%hex
   "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5
    cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20
    c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69
    b1 b0 4e 75 1f 0f 00 2b 00 02 03 04"))

(defparameter *rfc8448-server-encrypted-extensions-wire*
  (rfc8448-%hex
   "08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
    01 03 01 04 00 1c 00 02 40 01 00 00 00 00"))

(defparameter *rfc8448-server-certificate-wire*
  (rfc8448-%hex
   "0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30 82 01 15 a0 03 02 01 02 02 01
    02 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04
    03 13 03 72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17 0d 32
    36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72
    73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 81 8d 00 30 81
    89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55
    e1 bd b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a
    f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b
    63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef
    bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f
    7f 1e 3f 02 03 01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
    03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03
    81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f 8a 7b
    33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5
    5b 80 f2 1a 03 01 51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6
    be c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84 e0
    a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29 ac 91 87 b4 2b 4d
    e1 00 00"))

(defparameter *rfc8448-server-certificate-verify-wire*
  (rfc8448-%hex
   "0f 00 00 84 08 04 00 80 5a 74 7c 5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f
    82 4c d4 84 14 5a b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a
    07 86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b be 8d 48 59
    ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c 9e a5 8c 18 1e 81 8e 95
    b8 c3 fb 0b f3 27 84 09 d3 be 15 2a 3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53
    df ac d4 2f 74 f3"))

(defparameter *rfc8448-server-finished-wire*
  (rfc8448-%hex
   "14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72
    cb 7f ff ee 54 54 b7 8f 07 18"))

(defparameter *rfc8448-client-application-traffic-secret*
  (rfc8448-%hex
   "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92
    eb b7 c1 75 04 a5"))

(defun %rfc8448-server-operation (name)
  (let* ((package (or (find-package "CRYPTO-KIT")
                      (find-package "CL-CRYPTO-KIT")))
         (symbol (and package (find-symbol name package))))
    (unless (and symbol (fboundp symbol))
      (error "RFC 8448 server trace crypto operation unavailable"))
    (symbol-function symbol)))

(progn
  (defparameter *rfc8448-server-assertions* 0)
  (defparameter *rfc8448-server-random-calls* 0)
  (defun %rfc8448-server-check (condition name)
    (incf *rfc8448-server-assertions*)
    (unless condition
      (error "RFC 8448 section 3 server trace failed for ~A" name)))
  (defun %rfc8448-server-event (events type &key level direction wire-type)
    (find-if
     (lambda (event)
       (and (eq (getf event :type) type)
            (or (null level) (eq (getf event :level) level))
            (or (null direction) (eq (getf event :direction) direction))
            (or (null wire-type)
                (and (getf event :wire)
                     (= (aref (getf event :wire) 0) wire-type)))))
     events))
  (defun %rfc8448-server-random (length)
    (case (incf *rfc8448-server-random-calls*)
      (1
       (unless (= length 32)
         (error "RFC 8448 server trace random sequence is invalid"))
       (copy-seq *rfc8448-server-private-key*))
      (2
       (unless (= length 32)
         (error "RFC 8448 server trace random sequence is invalid"))
       (copy-seq *rfc8448-server-random*))
      (otherwise
       (make-array length :element-type (quote (unsigned-byte 8))
                          :initial-element 0))))
  (defun %rfc8448-server-continue-with-opaque-flight (driver opaque-flight)
    (unless (and (typep driver 'cl-tls-kit::tls13-server-driver)
                 (eq (cl-tls-kit::tls13-server-driver-state driver)
                     :awaiting-client-finished)
                 (cl-tls-kit::tls13-server-driver-server-flight-prefix driver)
                 (cl-tls-kit::%tls13-server-octets-p opaque-flight))
      (error "RFC 8448 trace transcript continuation is invalid"))
    (let ((position 0)
          (wire-length (length opaque-flight)))
      (dolist (expected-type '(8 11 15))
        (unless (and (<= (+ position 4) wire-length)
                     (= (aref opaque-flight position) expected-type))
          (error "RFC 8448 trace handshake flight is invalid"))
        (let ((body-length
                (cl-tls-kit::%tls13-server-read-u24 opaque-flight (+ position 1))))
          (unless (<= (+ position 4 body-length) wire-length)
            (error "RFC 8448 trace handshake flight is truncated"))
          (incf position (+ 4 body-length))))
      (unless (= position wire-length)
        (error "RFC 8448 trace handshake flight has trailing bytes")))
    (cl-tls-kit::%tls13-server-finish-flight
     driver
     (cl-tls-kit::%tls13-server-cat
      (cl-tls-kit::tls13-server-driver-server-flight-prefix driver)
      opaque-flight)))
  (defun run-rfc8448-server-trace-tests ()
    (unless (find-package "CRYPTO-KIT")
      (format t "RFC 8448 section 3 server trace: SKIPPED (cl-crypto-kit unavailable)~%")
      (return-from run-rfc8448-server-trace-tests :skipped))
    (let* ((openssl (or (uiop:getenv "OPENSSL") "openssl"))
           (directory
             (merge-pathnames
              (format nil "cl-tls-kit-rfc8448-server-~D-~D/"
                      (get-universal-time) (random 1000000000))
              (uiop:temporary-directory)))
           (certificate-path (namestring (merge-pathnames "server.crt" directory)))
           (private-key-path (namestring (merge-pathnames "server.key" directory)))
           (provider (make-cl-crypto-kit-provider))
           (chain nil)
           (private-key nil)
           (selected 0))
      (setf *rfc8448-server-assertions* 0
            *rfc8448-server-random-calls* 0)
      (ensure-directories-exist directory)
      (unwind-protect
           (progn
             (funcall
              (symbol-function
               (find-symbol "%OPENSSL-E2E-CERTIFICATE" :cl-tls-kit/test))
              openssl certificate-path private-key-path "server" 1 :key-type :ecdsa)
             (setf chain
                   (list (pem-block-der
                          (first (pem-decode
                                  (uiop:read-file-string certificate-path)))))
                   private-key
                   (funcall
                    (symbol-function
                     (find-symbol "%OPENSSL-E2E-ECDSA-PRIVATE-KEY" :cl-tls-kit/test))
                    openssl private-key-path))
             (let* ((x25519-base (%rfc8448-server-operation "X25519-BASE"))
                    (x25519 (%rfc8448-server-operation "X25519"))
                    (server-private *rfc8448-server-private-key*)
                    (server-public *rfc8448-server-public-key*)
                    (dhe (nth-value 0
                                    (funcall x25519 server-private
                                             *rfc8448-client-public-key*)))
                    (driver
                      (make-tls13-server-driver
                       :provider provider :certificate-chain chain
                       :private-key private-key :alpn-protocols nil
                       :ticket-key-store (make-tls13-server-ticket-key-store)
                       :clock (lambda () 4000000000)
                       :random (function %rfc8448-server-random)))
                    (events nil)
                    (finish-events nil)
                    (server-hello-wire nil))
               (incf selected)
               (%rfc8448-server-check
                (= (length *rfc8448-server-client-hello-wire*) 196)
                :rfc-client-hello-length)
               (%rfc8448-server-check
                (= (length *rfc8448-server-encrypted-extensions-wire*) 40)
                :rfc-encrypted-extensions-length)
               (%rfc8448-server-check
                (= (length *rfc8448-server-certificate-wire*) 445)
                :rfc-certificate-length)
               (%rfc8448-server-check
                (= (length *rfc8448-server-certificate-verify-wire*) 136)
                :rfc-certificate-verify-length)
               (%rfc8448-server-check
                (equalp (funcall x25519-base server-private) server-public)
                :server-x25519-public-key)
               (multiple-value-setq (driver events)
                 (tls13-server-driver-step
                  driver *rfc8448-server-client-hello-wire* :level :initial))
               (%rfc8448-server-check
                (null (%rfc8448-server-event events :alert))
                :production-client-hello-accepted)
               (setf server-hello-wire
                     (getf (%rfc8448-server-event events :send :level :initial) :wire))
               (%rfc8448-server-check
                (equalp server-hello-wire *rfc8448-server-hello-wire*)
                :server-hello-wire)
               (%rfc8448-server-check
                (equalp dhe *rfc8448-server-dhe-secret*)
                :x25519-shared-secret)
               (%rfc8448-server-check
                (equalp
                 (tls13-handshake-secret
                  provider :sha256 (tls13-early-secret provider :sha256) dhe)
                 *rfc8448-server-handshake-secret*)
                :handshake-secret)
               (%rfc8448-server-check
                (equalp (getf (%rfc8448-server-event
                               events :secret :level :handshake :direction :read)
                              :secret)
                        (rfc8448-%fixture :client-handshake-traffic-secret))
                :client-handshake-traffic-secret)
               (%rfc8448-server-check
                (equalp (getf (%rfc8448-server-event
                               events :secret :level :handshake :direction :write)
                              :secret)
                        *rfc8448-server-handshake-traffic-secret*)
                :server-handshake-traffic-secret)
               (%rfc8448-server-check
                (equalp
                 (cl-tls-kit::tls13-server-driver-master-secret driver)
                 (rfc8448-%fixture :master-secret))
                :master-secret)
               (let* ((ee-event
                        (%rfc8448-server-event
                         events :send :level :handshake :wire-type 8))
                      (ee-wire (and ee-event (getf ee-event :wire)))
                      (ee (and ee-wire (decode-handshake ee-wire)))
                      (groups-extension
                        (and ee
                             (find 10 (cl-tls-kit::tls13-encrypted-extensions-extensions ee)
                                   :key (function tls-extension-type))))
                      (opaque-flight
                        (cl-tls-kit::%cat *rfc8448-server-encrypted-extensions-wire*
                              *rfc8448-server-certificate-wire*
                              *rfc8448-server-certificate-verify-wire*)))
                 (%rfc8448-server-check
                  (equalp ee-wire
                          (rfc8448-%hex
                           "08 00 00 0c 00 0a 00 0a 00 06 00 04 00 1d 00 17"))
                  :production-encrypted-extensions-wire)
                 (%rfc8448-server-check
                  (and groups-extension
                       (equalp (tls-extension-data groups-extension)
                               #(0 4 0 29 0 23)))
                  :production-supported-groups-only)
                 (let ((finished
                         (%rfc8448-server-continue-with-opaque-flight
                          driver opaque-flight)))
                   (%rfc8448-server-check
                    (equalp finished *rfc8448-server-finished-wire*)
                    :server-finished-wire)
                   (multiple-value-setq (driver finish-events)
                     (tls13-server-driver-step
                      driver *rfc8448-client-finished-wire* :level :handshake))))
               (%rfc8448-server-check
                (%rfc8448-server-event events :send :level :handshake :wire-type 11)
                :production-ecdsa-certificate)
               (%rfc8448-server-check
                (%rfc8448-server-event events :send :level :handshake :wire-type 15)
                :production-certificate-verify)
               (%rfc8448-server-check
                (null (%rfc8448-server-event finish-events :alert))
                :client-finished-accepted)
               (%rfc8448-server-check
                (equalp (getf (%rfc8448-server-event
                               finish-events :secret :level :application
                               :direction :read)
                              :secret)
                        *rfc8448-client-application-traffic-secret*)
                :client-application-traffic-secret)
               (%rfc8448-server-check
                (equalp (getf (%rfc8448-server-event
                               finish-events :secret :level :application
                               :direction :write)
                              :secret)
                        *rfc8448-server-application-traffic-secret*)
                :server-application-traffic-secret)
               (%rfc8448-server-check
                (equalp
                 (cl-tls-kit::tls13-server-driver-resumption-master-secret driver)
                 *rfc8448-server-resumption-master-secret*)
                :resumption-master-secret)
               (%rfc8448-server-check
                (and (%rfc8448-server-event finish-events :ticket-issued)
                     (let ((complete
                             (%rfc8448-server-event
                              finish-events :handshake-complete)))
                       (and complete (not (getf complete :resumed-p)))))
                :handshake-completion-and-ticket)
               (%rfc8448-server-check (= selected 1) :one-rfc-server-trace-selected)
               (%rfc8448-server-check
                (plusp *rfc8448-server-assertions*) :assertions-executed)))
        (ignore-errors (delete-file certificate-path))
        (ignore-errors (delete-file private-key-path))
        (when (probe-file directory)
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))
      (%rfc8448-server-check
       (not (probe-file directory)) :temporary-files-removed)
      (format t "RFC 8448 section 3 server trace: selected traces: ~D; assertions: ~D~%"
              selected *rfc8448-server-assertions*)
      t)))
