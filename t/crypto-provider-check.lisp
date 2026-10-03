(require :asdf)
(asdf:load-system "cl-tls-kit")
(asdf:load-system "cl-crypto-kit")

(unless (find-package '#:crypto-kit)
  (error "cl-crypto-kit did not load; the OpenSSL checks must not pass without crypto integration"))

(let ((provider (cl-tls-kit:make-cl-crypto-kit-provider)))
  (unless (and (typep provider 'cl-tls-kit::tls13-crypto-provider)
               (= (length (cl-tls-kit::tls13-empty-hash provider :sha256)) 32)
               (= (length (cl-tls-kit::tls13-early-secret provider :sha256)) 32))
    (error "cl-crypto-kit provider is not usable by cl-tls-kit")))

(format t "cl-crypto-kit provider: PASS~%")
