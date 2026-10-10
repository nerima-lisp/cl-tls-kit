(in-package #:cl-tls-kit/test)

(defun run-client-driver-order-tests ()
  (let* ((states '(:awaiting-server-hello :awaiting-encrypted-extensions
                   :awaiting-certificate :awaiting-certificate-verify
                   :awaiting-finished))
         (messages
           (list (encode-handshake
                  2 (make-tls13-server-hello
                     #x0303 (make-array 32 :element-type '(unsigned-byte 8))
                     #() #x1301
                     (list (make-tls-extension 43 #(3 4))
                           (make-tls-extension
                            51 (encode-key-share-server-extension #x001d #(1 2))))))
                 (encode-handshake 8 (make-tls13-encrypted-extensions nil))
                 (encode-handshake
                  11 (make-tls13-certificate
                      #() (list (make-tls13-certificate-entry #(48 0) nil))))
                 (encode-handshake 15 (make-tls13-certificate-verify #x0804 #(1)))
                 (encode-handshake
                  20 (make-tls13-finished
                      (make-array 32 :element-type '(unsigned-byte 8))))))
         (selected 0)
         (assertions 0))
    (mapc #'decode-handshake messages)
    (flet ((assertion (condition message)
             (incf assertions)
             (check condition message)))
      (let ((driver (cl-tls-kit::%make-tls13-client-driver
                     :state :awaiting-encrypted-extensions :transcript #(42))))
        (assertion (eq driver (tls13-client-driver-step driver (second messages)))
                   "an expected message advances the same driver")
        (assertion (eq (cl-tls-kit::tls13-client-driver-state driver)
                       :awaiting-certificate)
                   "EncryptedExtensions advances to Certificate")
        (assertion (equalp (cl-tls-kit::tls13-client-driver-transcript driver)
                          (concatenate '(vector (unsigned-byte 8))
                                       #(42) (second messages)))
                   "an expected message updates the transcript"))
      (loop for state in states
            for expected-index from 0
            do (loop for wire in messages
                     for index from 0
                     unless (= index expected-index)
                       do (incf selected)
                          (let ((driver (cl-tls-kit::%make-tls13-client-driver
                                         :state state :transcript #(42))))
                            (assertion
                             (handler-case
                                 (progn (tls13-client-driver-step driver wire) nil)
                               (tls13-client-driver-error (condition)
                                 (eq (tls13-client-driver-error-reason condition)
                                     :unexpected-message))
                               (error () nil))
                             "a message outside its expected state is rejected")
                            (assertion
                             (eq state (cl-tls-kit::tls13-client-driver-state driver))
                             "an unexpected message leaves the state unchanged")
                            (assertion
                             (equalp #(42)
                                     (cl-tls-kit::tls13-client-driver-transcript driver))
                             "an unexpected message leaves the transcript unchanged")))))
    (format t "~&Driver ordering tests: selected: ~D; assertions: ~D~%"
            selected assertions)
    (values selected assertions)))

(defun run-client-driver-hrr-tests (provider key-exchange)
  (let ((selected 0)
        (assertions 0))
    (flet ((assertion (condition message)
             (incf assertions)
             (check condition message)))
      (dolist (second-group '(#x001d #x0017))
        (let* ((generated 0)
               (sent 0)
               (written 0)
               (exchange (copy-list key-exchange))
               (generate (getf exchange :generate)))
          (setf (getf exchange :generate)
                (lambda (group)
                  (incf generated)
                  (funcall generate group)))
          (let ((driver (make-tls13-client-driver
                         :provider provider :key-exchange exchange
                         :on-send (lambda (driver wire)
                                    (declare (ignore driver wire))
                                    (incf sent))
                         :transport-write (lambda (driver wire)
                                            (declare (ignore driver wire))
                                            (incf written)))))
            (tls13-client-driver-start driver)
            (flet ((retry-wire (group)
                     (let ((body (encode-hello-retry-request
                                  (make-tls13-hello-retry-request
                                   #x0303 group nil))))
                       (cl-tls-kit::%cat #(2) (cl-tls-kit::%u24 (length body)) body))))
              (tls13-client-driver-step driver (retry-wire #x0017))
              (assertion (= generated 2) "the first HRR generates one new key share")
              (assertion (= sent 2) "the first HRR emits one replacement ClientHello")
              (assertion (= written 2) "the first HRR writes one replacement ClientHello")
              (let ((transcript (copy-seq (cl-tls-kit::tls13-client-driver-transcript driver)))
                    (hello (cl-tls-kit::tls13-client-driver-client-hello driver))
                    (private (cl-tls-kit::tls13-client-driver-private-key driver)))
                (incf selected)
                (assertion
                 (handler-case
                     (progn (tls13-client-driver-step driver (retry-wire second-group)) nil)
                   (tls13-client-driver-error (condition)
                     (eq :unexpected-hrr (tls13-client-driver-error-reason condition)))
                   (error () nil))
                 "a second HRR is rejected regardless of its group")
                (assertion (equalp transcript (cl-tls-kit::tls13-client-driver-transcript driver))
                           "a second HRR does not rewrite the transcript")
                (assertion (eq hello (cl-tls-kit::tls13-client-driver-client-hello driver))
                           "a second HRR does not replace ClientHello")
                (assertion (eq private (cl-tls-kit::tls13-client-driver-private-key driver))
                           "a second HRR does not replace the private key")
                (assertion (= generated 2) "a second HRR does not generate a key share")
                (assertion (= sent 2) "a second HRR does not emit ClientHello")
                (assertion (= written 2) "a second HRR does not write ClientHello")
                (assertion (= #x0017 (cl-tls-kit::tls13-client-driver-selected-group driver))
                           "a second HRR leaves the selected group unchanged")
                (assertion (eq :awaiting-server-hello
                               (cl-tls-kit::tls13-client-driver-state driver))
                           "a second HRR leaves the handshake state unchanged")))))))
    (format t "~&Driver HRR tests: selected: ~D; assertions: ~D~%" selected assertions)
    (values selected assertions)))
