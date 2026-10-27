(in-package #:cl-tls-kit/test-support)

(defun set-tls13-client-driver-state (driver state)
  (setf (cl-tls-kit::tls13-client-driver-state driver) state))

(defun set-tls13-client-driver-application-read-state (driver state)
  (setf (cl-tls-kit::tls13-client-driver-application-read-state driver) state))

(defun set-tls13-client-driver-application-write-state (driver state)
  (setf (cl-tls-kit::tls13-client-driver-application-write-state driver) state))

(defun set-tls13-client-driver-close-notify-received (driver received-p)
  (setf (cl-tls-kit::tls13-client-driver-close-notify-received driver) received-p))
