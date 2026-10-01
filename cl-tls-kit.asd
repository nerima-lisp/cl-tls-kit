(in-package #:asdf-user)

(asdf:defsystem "cl-tls-kit"
  :description "Small, strict DER and PEM building blocks for TLS certificate tooling."
  :author "nerima-lisp"
  :license "MIT"
  :version "0.1.0"
  ;; Cryptographic operations are intentionally not part of this foundation.
  ;; A future certificate/crypto layer may add ironclad and cl-base64 here.
  :depends-on ()
  :weakly-depends-on ("cl-crypto-kit")
  :pathname "src"
  :serial t
  :components ((:file "package") (:file "asn1") (:file "pem")
               (:file "hostname") (:file "x509") (:file "trust-store")
               (:file "verify"))
  :in-order-to ((test-op (test-op "cl-tls-kit/test"))))

(asdf:defsystem "cl-tls-kit/test"
  :description "Tests for cl-tls-kit."
  :depends-on ("cl-tls-kit")
  :pathname "t"
  :serial t
  :components ((:file "package") (:file "tests") (:file "runner"))
  :perform (asdf:test-op (op c)
             (declare (ignore op c))
             (uiop:symbol-call "CL-TLS-KIT/TEST" "RUN-TESTS")))
