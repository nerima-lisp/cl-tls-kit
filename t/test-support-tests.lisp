(in-package #:cl-tls-kit/test)

(defun run-test-support-tests ()
  (let* ((driver (cl-tls-kit::%make-tls13-client-driver))
         (read-state (list :read-state))
         (write-state (list :write-state)))
    (check
     (and
      (eq :connected
          (cl-tls-kit/test-support:set-tls13-client-driver-state driver
                                                                 :connected))
      (eq :connected (cl-tls-kit::tls13-client-driver-state driver)))
     "test support sets the client driver state")
    (check
     (and
      (eq read-state
          (cl-tls-kit/test-support:set-tls13-client-driver-application-read-state
           driver
           read-state))
      (eq read-state
          (cl-tls-kit::tls13-client-driver-application-read-state driver)))
     "test support sets the application read state")
    (check
     (and
      (eq write-state
          (cl-tls-kit/test-support:set-tls13-client-driver-application-write-state
           driver
           write-state))
      (eq write-state
          (cl-tls-kit::tls13-client-driver-application-write-state driver)))
     "test support sets the application write state")
    (check
     (and
      (eq t
          (cl-tls-kit/test-support:set-tls13-client-driver-close-notify-received
           driver
           t))
      (eq t (cl-tls-kit:tls13-client-driver-close-notify-received-p driver)))
     "test support sets the close-notify received state"))
  t)
