(in-package #:cl-tls-kit/test)

(defun run-path-building-tests ()
  (let ((now (get-universal-time))
        (verify-signature (lambda (&rest arguments)
                            (declare (ignore arguments))
                            t)))
    (flet ((certificate (issuer subject serial &optional ca self-signed
                                  subject-alternative-names name-constraints)
             (list :issuer issuer :subject subject
                   :not-before 0 :not-after (1+ now)
                   :signature-algorithm :rsa-pkcs1-sha256
                   :tbs-certificate (vector serial)
                   :signature (vector (logand serial #xff))
                   :public-key (vector serial)
                   :basic-constraints (when ca '(:ca t))
                   :subject-alternative-names subject-alternative-names
                   :name-constraints name-constraints
                   :self-signed self-signed)))
      (let* ((leaf (certificate "intermediate-a" "leaf" 1))
             (intermediate-a (certificate "intermediate-b" "intermediate-a" 2 t))
             (intermediate-b (certificate "root" "intermediate-b" 3 t))
             (root (certificate nil "root" 4 t t)))
        (check (verify-certificate-chain
                (list leaf intermediate-b root intermediate-a)
                :trust-anchors (list root)
                :verify-signature verify-signature)
               "unordered peer intermediates build a valid path")
        (check (verify-certificate-chain
                (list leaf intermediate-a intermediate-b)
                :trust-anchors (list root)
                :verify-signature verify-signature)
               "peer may omit the trusted root")
        (check (verify-certificate-chain
                (list leaf intermediate-a intermediate-b root)
                :trust-anchors (list root)
                :verify-signature verify-signature)
               "ordered complete chain remains valid"))
      (let* ((leaf (certificate "missing-issuer" "orphan" 10))
             (root (certificate nil "root" 11 t t)))
        (check (handler-case
                   (progn
                     (verify-certificate-chain
                      (list leaf) :trust-anchors (list root)
                      :verify-signature verify-signature)
                     nil)
                 (untrusted-root () t)
                 (condition () nil))
               "missing issuer fails as an untrusted path"))
      (let* ((leaf (certificate "missing" "leaf" 20))
             (extras (loop for serial from 21
                           below (+ cl-tls-kit::+max-certificate-path-candidates+ 21)
                           collect (certificate "unused" "extra" serial)))
             (root (certificate nil "root" 90 t t)))
        (check (handler-case
                   (progn
                     (verify-certificate-chain
                      (cons leaf extras) :trust-anchors (list root)
                      :verify-signature verify-signature)
                     nil)
                 (invalid-certificate-chain () t)
                 (condition () nil))
               "peer certificate candidate count is bounded"))
      (let* ((leaf (certificate "root" "leaf" 22))
             (root (certificate "root" "root" 90 t t))
             (extra-anchors
               (loop for serial from 100 below (+ 100 512)
                     collect (certificate "unused" "unused" serial t t))))
        (check (handler-case
                   (progn
                     (verify-certificate-chain
                      (list leaf) :trust-anchors (cons root extra-anchors)
                      :verify-signature verify-signature)
                     nil)
                 (invalid-certificate-chain () t)
                 (condition () nil))
               "trust-anchor candidate count is bounded"))
      (let* ((leaf (certificate "intermediate" "leaf" 30))
             (bad-issuer (certificate "root" "intermediate" 31 t))
             (good-issuer (certificate "root" "intermediate" 32 t))
             (root (certificate "root" "root" 33 t t))
             (reject-bad-issuer-signature
               (lambda (algorithm public-key tbs signature)
                 (declare (ignore algorithm tbs))
                 (not (and (= (aref signature 0) 30)
                           (= (aref public-key 0) 31))))))
        (check (verify-certificate-chain
                (list leaf bad-issuer good-issuer)
                :trust-anchors (list root)
                :verify-signature reject-bad-issuer-signature)
               "bad signature on one issuer candidate allows a valid alternative"))
      (let* ((leaf (certificate "intermediate" "leaf" 40
                                nil nil
                                '((:dns "api.example.test")
                                  (:dns "outside.invalid"))))
             (intermediate
               (certificate "root" "intermediate" 41 t nil nil
                            '(:permitted-subtrees ((:dns "example.test")))))
             (root (certificate "root" "root" 42 t t)))
        (check (handler-case
                   (progn
                     (verify-certificate-chain
                      (list leaf intermediate) :trust-anchors (list root)
                      :verify-signature verify-signature)
                     nil)
                 (invalid-certificate-chain () t)
                 (condition () nil))
               "every DNS SAN must match a permitted subtree"))
      (let* ((leaf (certificate "intermediate" "leaf" 43))
             (intermediate
               (certificate "root" "intermediate" 44 t nil nil
                            '(:permitted-subtrees ((:dns "example.test")))))
             (root (certificate "root" "root" 45 t t)))
        (check (verify-certificate-chain
                (list leaf intermediate) :trust-anchors (list root)
                :verify-signature verify-signature)
               "DNS permitted subtree does not require a DNS SAN"))
      (let* ((leaf (certificate "rollover" "leaf" 50
                                nil nil '((:dns "api.example.test"))))
             (rollover (certificate "rollover" "rollover" 51 t nil
                                   '((:dns "outside.invalid"))))
             (old-issuer (certificate "root" "rollover" 52 t))
             (root (certificate "root" "root" 53 t t nil
                                '(:permitted-subtrees ((:dns "example.test")))))
             (bad-leaf (certificate "rollover" "leaf" 54
                                    nil nil '((:dns "outside.invalid")))))
        (check (verify-certificate-chain
                (list leaf rollover old-issuer) :trust-anchors (list root)
                :verify-signature verify-signature)
               "self-issued non-final rollover skips name constraints")
        (check (handler-case
                   (progn
                     (verify-certificate-chain
                      (list bad-leaf rollover old-issuer) :trust-anchors (list root)
                      :verify-signature verify-signature)
                     nil)
                 (invalid-certificate-chain () t)
                 (condition () nil))
               "final leaf remains subject to name constraints"))
      (let* ((leaf (certificate "loop" "leaf" 60))
             (first-issuer (certificate "loop" "loop" 61 t))
             (second-issuer (certificate "loop" "loop" 62 t))
             (root (certificate nil "root" 63 t t)))
        (let ((cl-tls-kit::+max-certificate-path-expansions+ 1))
          (check (handler-case
                     (progn
                       (verify-certificate-chain
                        (list leaf first-issuer second-issuer)
                        :trust-anchors (list root)
                        :verify-signature verify-signature)
                       nil)
                   (invalid-certificate-chain () t)
                   (condition () nil))
                 "issuer path exploration count is bounded")))
      (let ((leaf (certificate "root" "leaf" 70)))
          (check (handler-case
                     (progn
                       (verify-certificate-chain
                        (make-list
                         (1+ cl-tls-kit::+max-certificate-chain-length+)
                         :initial-element leaf)
                        :trust-anchors nil
                        :verify-signature verify-signature)
                       nil)
                   (invalid-certificate-chain () t)
                   (condition () nil))
                 "ordered chain length is bounded without trust anchors")
          (check (handler-case
                     (progn
                       (verify-certificate-chain
                        (cons leaf :tail)
                        :trust-anchors nil
                        :verify-signature verify-signature)
                       nil)
                   (invalid-certificate-chain () t)
                   (condition () nil))
                 "improper ordered chain is rejected")
          (check (handler-case
                     (progn
                       (verify-certificate-chain
                        nil :trust-anchors nil
                        :verify-signature verify-signature)
                       nil)
                   (untrusted-root () t)
                   (condition () nil))
                 "nil ordered chain keeps its untrusted-root condition"))
        (let* ((leaf (certificate "intermediate" "leaf" 71))
               (intermediate (certificate "root" "intermediate" 72 t))
               (root (certificate "root" "root" 73 t t)))
          (let ((cl-tls-kit::+max-certificate-chain-length+ 2))
            (check (handler-case
                       (progn
                         (verify-certificate-chain
                          (list leaf intermediate)
                          :trust-anchors (list root)
                          :verify-signature verify-signature)
                         nil)
                     (invalid-certificate-chain () t)
                     (condition () nil))
                   "candidate path depth is bounded")))
        t)))
