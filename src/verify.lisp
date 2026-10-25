(in-package #:cl-tls-kit)

(export '(expired certificate-expired hostname-mismatch certificate-hostname-mismatch
          untrusted-root self-signed self-signed-certificate not-a-ca path-length-exceeded
          bad-signature invalid-key-usage invalid-extended-key-usage
          invalid-certificate-chain certificate-signature-provider-unavailable
          verify-certificate verify-certificate-chain))

(define-condition certificate-verification-error (error)
  ((certificate :initarg :certificate :reader verification-error-certificate)))
(define-condition expired (certificate-verification-error) ())
(define-condition certificate-expired (expired) ())
(define-condition certificate-hostname-mismatch (hostname-mismatch certificate-verification-error) ())
(define-condition untrusted-root (certificate-verification-error) ())
(define-condition self-signed (certificate-verification-error) ())
(define-condition self-signed-certificate (self-signed) ())
(define-condition not-a-ca (certificate-verification-error) ())
(define-condition path-length-exceeded (certificate-verification-error) ())
(define-condition bad-signature (certificate-verification-error) ())
(define-condition invalid-key-usage (certificate-verification-error) ())
(define-condition invalid-extended-key-usage (certificate-verification-error) ())
(define-condition invalid-certificate-chain (certificate-verification-error) ())
(define-condition certificate-signature-provider-unavailable (certificate-verification-error) ())

(defparameter +max-certificate-chain-length+ 16)
(defparameter +max-certificate-chain-bytes+ (* 4 1024 1024))

(defun %bounded-proper-list-count (items limit)
  (loop with count = 0
        for tail = items then (cdr tail)
        do (cond ((null tail) (return count))
                 ((not (consp tail)) (return nil))
                 ((>= count limit) (return nil))
                 (t (incf count)))))

(defun %field (object key &optional default)
  (cond ((hash-table-p object) (gethash key object default))
        ((and (listp object) (or (null object) (keywordp (first object))))
         (getf object key default))
        ((listp object) (or (cdr (assoc key object)) default))
        ((typep object 'cl-tls-kit.x509:x509-certificate)
         (case key
           (:not-before (cl-tls-kit.x509:x509-certificate-not-before object))
           (:not-after (cl-tls-kit.x509:x509-certificate-not-after object))
           (:issuer (or (cl-tls-kit.x509::x509-certificate-issuer-name-der object)
                       (cl-tls-kit.x509:x509-certificate-issuer object)))
           (:subject (or (cl-tls-kit.x509::x509-certificate-subject-name-der object)
                        (cl-tls-kit.x509:x509-certificate-subject object)))
           (:public-key (cl-tls-kit.x509:x509-certificate-public-key object))
           (:signature-algorithm (cl-tls-kit.x509:x509-certificate-signature-algorithm object))
           (:signature-parameters (cl-tls-kit.x509::x509-certificate-signature-parameters object))
           (:tbs-certificate (cl-tls-kit.x509::x509-certificate-tbs-certificate object))
           (:signature (cl-tls-kit.x509::x509-certificate-signature object))
           (:basic-constraints (cl-tls-kit.x509:x509-certificate-basic-constraints object))
           (:key-usage (cl-tls-kit.x509:x509-certificate-key-usage object))
           (:extended-key-usage (cl-tls-kit.x509:x509-certificate-extended-key-usage object))
           (:subject-alternative-names (cl-tls-kit.x509:x509-certificate-subject-alternative-name object))
           (:subject-alternative-name (cl-tls-kit.x509:x509-certificate-subject-alternative-name object))
           (:name-constraints (cl-tls-kit.x509:x509-certificate-name-constraints object))
           (otherwise default)))
        (t default)))

(defun %time-ok-p (certificate now)
  (let ((not-before (%field certificate :not-before 0))
        (not-after (%field certificate :not-after most-positive-fixnum)))
    (and (<= not-before now) (<= now not-after))))

(defun %token (value)
  (let ((token (coerce (remove-if (lambda (character) (find character "-_ "))
                                  (string-downcase (string value)))
                        'string)))
    (cond ((string= token "1.3.6.1.5.5.7.3.1") "serverauth")
          ((string= token "2.5.29.37.0") "anyextendedkeyusage")
          (t token))))

(defun %has-p (value item)
  (some (lambda (x) (string= (%token x) (%token item))) value))

(defun %same-name-p (left right) (cl-tls-kit.x509:x509-name-equal-p left right))
(defun %self-issued-p (certificate)
  (let ((issuer (%field certificate :issuer nil))
        (subject (%field certificate :subject nil)))
    (and issuer subject (%same-name-p issuer subject))))

(defun %crypto-verify-function ()
  (let* ((package (or (find-package "CRYPTO-KIT")
                      (find-package "CL-CRYPTO-KIT")))
         (symbol (and package (find-symbol "VERIFY-SIGNATURE" package))))
    (when (and symbol (fboundp symbol)) symbol)))

(defun %signature-scheme (certificate)
  (let ((algorithm (%field certificate :signature-algorithm)))
    (if (keywordp algorithm)
        algorithm
        (cond
          ((string= algorithm "1.2.840.113549.1.1.11") :rsa-pkcs1-sha256)
          ((string= algorithm "1.2.840.113549.1.1.12") :rsa-pkcs1-sha384)
          ((string= algorithm "1.2.840.113549.1.1.13") :rsa-pkcs1-sha512)
          ((string= algorithm "1.2.840.113549.1.1.10")
           (let* ((parameters (%field certificate :signature-parameters))
                  (hash (getf parameters :hash))
                  (digest-length (case hash (:sha256 32) (:sha384 48) (:sha512 64))))
             (unless (and digest-length
                          (eq (getf parameters :mgf-hash) hash)
                          (eql (getf parameters :salt-length) digest-length)
                          (eql (getf parameters :trailer-field) 1))
               (error 'bad-signature :certificate certificate))
             (ecase hash
               (:sha256 :rsa-pss-rsae-sha256)
               (:sha384 :rsa-pss-rsae-sha384)
               (:sha512 :rsa-pss-rsae-sha512))))
          ((string= algorithm "1.2.840.10045.4.3.2") :ecdsa-p256-sha256)
          ((string= algorithm "1.2.840.10045.4.3.3") :ecdsa-p384-sha384)
          ((string= algorithm "1.2.840.10045.4.3.4") :ecdsa-p521-sha512)
          ((string= algorithm "1.3.101.112") :ed25519)
          (t (error 'bad-signature :certificate certificate))))))

(defun %same-signature-algorithm-p (certificate)
  (let* ((x509-p (typep certificate 'cl-tls-kit.x509:x509-certificate))
         (outer (%field certificate :signature-algorithm))
         (tbs (and x509-p
                   (cl-tls-kit.x509:x509-certificate-tbs-signature-algorithm certificate)))
         (outer-parameters
           (and x509-p
                (cl-tls-kit.x509::x509-certificate-signature-parameters certificate)))
         (tbs-parameters
           (and x509-p
                (cl-tls-kit.x509::x509-certificate-tbs-signature-parameters certificate))))
    (and (or (null tbs) (equalp outer tbs))
         (or (not x509-p) (equalp outer-parameters tbs-parameters)))))

(defun %crypto-public-key (key)
  (if (not (typep key 'cl-tls-kit.x509:x509-public-key))
      key
      (let* ((package (or (find-package "CRYPTO-KIT")
                          (find-package "CL-CRYPTO-KIT")))
             (constructor (and package
                               (find-symbol
                                (ecase (cl-tls-kit.x509:x509-public-key-type key)
                                  (:rsa "MAKE-RSA-PUBLIC-KEY")
                                  (:ec "MAKE-EC-PUBLIC-KEY")
                                  (:ed25519 "MAKE-ED25519-PUBLIC-KEY"))
                                package))))
        (unless (and constructor (fboundp constructor))
          (error 'certificate-signature-provider-unavailable :certificate key))
        (case (cl-tls-kit.x509:x509-public-key-type key)
          (:rsa (funcall constructor
                         (cl-tls-kit.x509:x509-rsa-public-key-modulus key)
                         (cl-tls-kit.x509:x509-rsa-public-key-exponent key)))
          (:ec (funcall constructor
                        (cond ((string= (cl-tls-kit.x509:x509-ec-public-key-curve key)
                                       "1.3.132.0.34") :p384)
                              ((string= (cl-tls-kit.x509:x509-ec-public-key-curve key)
                                        "1.2.840.10045.3.1.7") :p256)
                              (t (error 'certificate-signature-provider-unavailable
                                        :certificate key)))
                        (cl-tls-kit.x509:x509-ec-public-key-point key)))
          (:ed25519 (funcall constructor
                             (cl-tls-kit.x509:x509-ed25519-public-key-point key)))))))

(defun %verify-signature (certificate issuer verify-signature)
  (unless (%same-signature-algorithm-p certificate)
    (error 'bad-signature :certificate certificate))
  (let ((function (or verify-signature (%crypto-verify-function))))
    (unless (and function (or (functionp function) (fboundp function)))
      (error 'certificate-signature-provider-unavailable :certificate certificate))
    (handler-case
        (unless (funcall function
                         (%signature-scheme certificate)
                         (%crypto-public-key (%field issuer :public-key))
                         (%field certificate :tbs-certificate)
                         (%field certificate :signature))
          (error 'bad-signature :certificate certificate))
      (certificate-verification-error (condition)
        (error condition))
      (error ()
        (error 'certificate-signature-provider-unavailable :certificate certificate)))))

(defun %basic-constraint (certificate key &optional default)
  (let ((constraints (%field certificate :basic-constraints nil)))
    (if (and constraints (listp constraints)) (getf constraints key default) default)))

(defun %ip-octets-p (value)
  (and (vectorp value) (= (array-rank value) 1)
       (member (length value) '(4 16))
       (every (lambda (octet) (typep octet '(unsigned-byte 8))) value)))

(defun %ip-constraint-octets-p (value)
  (and (vectorp value) (= (array-rank value) 1)
       (member (length value) '(8 32))
       (every (lambda (octet) (typep octet '(unsigned-byte 8))) value)))

(defun %constraint-match-p (entry san)
  (let* ((kind (and (consp entry) (first entry)))
         (constraint (and (consp entry) (second entry)))
         (san-kind (and (consp san) (first san)))
         (value (if (and (consp san) (consp (rest san))) (second san) san)))
    (cond
      ((and (eq kind :dns) (eq san-kind :dns) (stringp constraint) (stringp value))
       (let* ((base (string-downcase constraint))
              (name (string-downcase value))
              (base (if (and (plusp (length base)) (char= (char base 0) #\.))
                        (subseq base 1) base)))
         (or (string= name base)
             (and (> (length name) (length base))
                  (string= name base :start1 (- (length name) (length base)))
                  (char= (char name (- (length name) (length base) 1)) #\.)))))
      ((and (eq kind :ip) (eq san-kind :ip)
            (%ip-constraint-octets-p constraint) (%ip-octets-p value)
            (= (length constraint) (* 2 (length value))))
       (let ((address (subseq constraint 0 (length value)))
             (mask (subseq constraint (length value))))
         (every (lambda (a b m) (= (logand a m) (logand b m))) value address mask)))
      (t nil))))

(defun %check-name-constraints (certificate issuer)
  (let* ((constraints (%field issuer :name-constraints nil))
         (names (%field certificate :subject-alternative-names nil))
         (permitted (and constraints (getf constraints :permitted-subtrees)))
         (excluded (and constraints (getf constraints :excluded-subtrees))))
    (when constraints
      (when (and (getf constraints :critical)
                 (or (some (lambda (entry) (eq (first entry) :unsupported)) permitted)
                     (some (lambda (entry) (eq (first entry) :unsupported)) excluded)
                     (some (lambda (san) (not (member (first san) '(:dns :ip)))) names)))
        (error 'invalid-certificate-chain :certificate certificate))
      (when (some (lambda (entry) (some (lambda (san) (%constraint-match-p entry san)) names))
                  excluded)
        (error 'invalid-certificate-chain :certificate certificate))
      (dolist (kind '(:dns :ip))
        (let ((rules (remove-if-not (lambda (entry) (eq (first entry) kind)) permitted))
              (values (remove-if-not (lambda (san) (eq (first san) kind)) names)))
          (when (and rules values
                     (not (every (lambda (san)
                                   (some (lambda (entry) (%constraint-match-p entry san))
                                         rules))
                                 values)))
            (error 'invalid-certificate-chain :certificate certificate)))))))

(defun %check-chain-name-constraints (chain index certificate)
  "Apply every ancestor's name constraints to CERTIFICATE."
  (dolist (issuer (nthcdr (1+ index) chain))
    (when (%field issuer :name-constraints nil)
      (%check-name-constraints certificate issuer))))

(defun %check-certificate (certificate issuer ca-depth now verify-signature
                           &optional (check-name-constraints-p t))
  (unless (%time-ok-p certificate now)
    (error 'certificate-expired :certificate certificate))
  (when issuer
    (unless (%same-name-p (%field certificate :issuer nil) (%field issuer :subject nil))
      (error 'invalid-certificate-chain :certificate certificate))
    (when check-name-constraints-p
      (%check-name-constraints certificate issuer))
    (%verify-signature certificate issuer verify-signature)
    (unless (eq t (%basic-constraint issuer :ca nil))
      (error 'not-a-ca :certificate issuer))
    (let ((usage (%field issuer :key-usage nil)))
      (when (and usage (not (%has-p usage :key-cert-sign)))
        (error 'invalid-key-usage :certificate issuer)))
    (let ((limit (%basic-constraint issuer :path-length nil)))
      (when (and limit (> ca-depth limit))
        (error 'path-length-exceeded :certificate issuer)))))

(defun %subordinate-ca-depth (chain issuer-index)
  (count-if (lambda (item)
              (and (eq t (%basic-constraint item :ca nil))
                   (not (%self-issued-p item))))
            (subseq chain 1 (min issuer-index (length chain)))))

(defparameter +max-certificate-path-candidates+ 64)
(defparameter +max-certificate-anchor-candidates+ 512)
(defparameter +max-certificate-path-expansions+ 256)

(defun %certificate-identical-p (left right)
  (or (eq left right)
      (let ((left-tbs (%field left :tbs-certificate))
            (right-tbs (%field right :tbs-certificate))
            (left-signature (%field left :signature))
            (right-signature (%field right :signature)))
        (and left-tbs right-tbs left-signature right-signature
             (equalp left-tbs right-tbs)
             (equalp left-signature right-signature)))
      (equalp left right)))

(defun %verify-ordered-certificate-chain (chain &key hostname trust-anchors
                                           (now (get-universal-time)) verify-signature)
  "Verify a leaf-first CHAIN using crypto-kit's common VERIFY-SIGNATURE API.
VERIFY-SIGNATURE, when supplied, has the same four-argument contract."
  (unless chain (error 'untrusted-root :certificate nil))
  (unless (%bounded-proper-list-count chain +max-certificate-chain-length+)
    (error 'invalid-certificate-chain
           :certificate (and (consp chain) (car chain))))
  (let ((bytes 0))
    (dolist (certificate chain)
      (incf bytes (length (or (%field certificate :tbs-certificate) #())))
      (incf bytes (length (or (%field certificate :signature) #())))
      (when (> bytes +max-certificate-chain-bytes+)
        (error 'invalid-certificate-chain :certificate certificate))))
  (loop for certificate in chain
        for issuer in (append (rest chain) '(nil))
        for index from 0
        for check-name-constraints-p =
          (not (and (plusp index)
                    (let ((subject (%field certificate :subject nil))
                          (issuer-name (%field certificate :issuer nil)))
                      (and subject issuer-name (%same-name-p subject issuer-name)))))
        do (when check-name-constraints-p
             (%check-chain-name-constraints chain index certificate))
           (%check-certificate certificate issuer
                               (%subordinate-ca-depth chain (1+ index))
                               now verify-signature check-name-constraints-p))
  (let* ((leaf (first chain)) (root (car (last chain))))
    (unless (and trust-anchors (member root trust-anchors :test #'equalp))
      (if (%field root :self-signed nil)
          (error 'self-signed-certificate :certificate root)
          (error 'untrusted-root :certificate root)))
    (let ((eku (%field leaf :extended-key-usage nil)))
      (when (and eku (not (or (%has-p eku :server-auth)
                              (%has-p eku :any-extended-key-usage))))
        (error 'invalid-extended-key-usage :certificate leaf)))
    (let ((usage (%field leaf :key-usage nil)))
      (when (and usage (not (%has-p usage :digital-signature)))
        (error 'invalid-key-usage :certificate leaf)))
    (when hostname
      (unless (hostname-match-p hostname (%field leaf :subject-alternative-names nil))
        (error 'certificate-hostname-mismatch :certificate leaf)))
    t))

(defun %verify-certificate-candidate-paths (peer-certificates trust-anchors
                                                              &key hostname
                                                              (now (get-universal-time))
                                                              verify-signature)
  (let* ((peer-count
          (%bounded-proper-list-count
           peer-certificates +max-certificate-path-candidates+))
         (anchor-count
          (%bounded-proper-list-count
           trust-anchors +max-certificate-anchor-candidates+))
         (leaf (and (consp peer-certificates) (car peer-certificates))))
    (unless (and peer-count
                 (plusp peer-count)
                 anchor-count
                 (plusp anchor-count))
      (error 'invalid-certificate-chain :certificate leaf))
    (let ((bytes 0))
      (dolist (certificate peer-certificates)
        (incf bytes (length (or (%field certificate :tbs-certificate) #())))
        (incf bytes (length (or (%field certificate :signature) #())))
        (when (> bytes +max-certificate-chain-bytes+)
          (error 'invalid-certificate-chain :certificate certificate))))
    (let ((candidates (append (rest peer-certificates) trust-anchors))
          (expansions 0)
          (last-failure nil)
          (unresolved-certificate leaf)
          (depth-certificate nil)
          (depth-exceeded-p nil)
          (verified-tag (gensym "VERIFIED-")))
      (catch verified-tag
        (labels ((issuer-candidate-p (certificate candidate)
                                     (let ((issuer (%field certificate :issuer nil))
                                           (subject (%field candidate :subject nil)))
                                       (and issuer subject (%same-name-p issuer subject))))
                 (verify-path (reversed-path)
                              (handler-case
                                  (%verify-ordered-certificate-chain
                                   (reverse reversed-path)
                                   :hostname hostname
                                   :trust-anchors trust-anchors
                                   :now now
                                   :verify-signature verify-signature)
                                (certificate-signature-provider-unavailable (condition)
                                                                            (error condition))
                                (certificate-verification-error (condition)
                                                                (setf last-failure condition)
                                                                nil)))
                 (walk (reversed-path)
                       (let ((current (car reversed-path))
                             (matched-issuer-p nil))
                         (when (member current trust-anchors
                                       :test #'%certificate-identical-p)
                           (when (verify-path reversed-path)
                             (throw verified-tag t)))
                         (dolist (candidate candidates)
                           (when (issuer-candidate-p current candidate)
                             (setf matched-issuer-p t)
                             (unless (member candidate reversed-path
                                             :test #'%certificate-identical-p)
                               (if (>= (length reversed-path)
                                       +max-certificate-chain-length+)
                                   (setf depth-exceeded-p t
                                         depth-certificate current)
                                 (progn
                                   (when (>= expansions
                                             +max-certificate-path-expansions+)
                                     (error 'invalid-certificate-chain
                                            :certificate current))
                                   (incf expansions)
                                   (walk (cons candidate reversed-path)))))))
                         (unless matched-issuer-p
                           (setf unresolved-certificate current)))))
          (walk (list leaf))

          (cond (last-failure (error last-failure))
                (depth-exceeded-p
                 (error 'invalid-certificate-chain
                        :certificate (or depth-certificate leaf)))
                (t (error 'untrusted-root
                          :certificate unresolved-certificate))))))))

(defun verify-certificate-chain (chain &key hostname trust-anchors
                                           (now (get-universal-time)) verify-signature)
  "Build a bounded leaf-first path from peer certificates, then verify it."
  (if (or (null chain) (null trust-anchors))
      (%verify-ordered-certificate-chain
       chain :hostname hostname :trust-anchors trust-anchors
       :now now :verify-signature verify-signature)
      (%verify-certificate-candidate-paths
       chain trust-anchors :hostname hostname :now now
       :verify-signature verify-signature)))

(defun verify-certificate (chain &rest keys)
  (apply #'verify-certificate-chain chain keys))
