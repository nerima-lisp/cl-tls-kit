(defpackage #:cl-tls-kit/test-support
            (:use #:cl #:cl-tls-kit)
            (:export #:set-tls13-client-driver-state
                     #:set-tls13-client-driver-application-read-state
                     #:set-tls13-client-driver-application-write-state
                     #:set-tls13-client-driver-close-notify-received))
