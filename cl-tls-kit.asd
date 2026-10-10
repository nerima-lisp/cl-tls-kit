(in-package #:asdf-user)

(asdf:defsystem "cl-tls-kit"
  :description "TLS 1.3 client, certificate verification, and QUIC TLS boundaries."
  :author "nerima-lisp"
  :license "MIT"
  :version "0.1.1"
  :depends-on ()
  :weakly-depends-on ("cl-crypto-kit")
  :pathname "src"
  :serial t
  :components ((:file "package") (:file "asn1") (:file "pem")
               (:file "hostname") (:file "x509") (:file "trust-store")
               (:file "verify") (:file "key-schedule") (:file "record")
               (:file "handshake") (:file "verification")
               (:file "quic-boundary") (:file "rfc8448") (:file "client")
               (:file "client-driver"))
  :in-order-to ((test-op (test-op "cl-tls-kit/test"))))

(asdf:defsystem "cl-tls-kit/test"
  :description "Tests for cl-tls-kit."
  :depends-on ("cl-tls-kit")
  :pathname "t"
  :serial t
  :components ((:file "package") (:file "pss-parameters-tests") (:file "tests")
               (:file "key-schedule-tests") (:file "record-tests")
               (:file "handshake-tests") (:file "client-tests")
               (:file "client-driver-order-tests")
               (:file "client-driver-tests")
               (:file "verification-tests") (:file "quic-boundary-tests")
               (:file "rfc8448-tests") (:file "openssl-e2e")
               (:file "openssl-chain-tests") (:file "pss-signature-tests")
               (:file "runner"))
  :perform (asdf:test-op (op c)
             (declare (ignore op c))
             (uiop:symbol-call "CL-TLS-KIT/TEST" "RUN-TESTS")))
