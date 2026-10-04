(in-package #:cl-tls-kit)

(define-condition hostname-mismatch (error)
  ((hostname :initarg :hostname :initform nil :reader hostname-mismatch-hostname)
   (names :initarg :names :initform nil :reader hostname-mismatch-names))
  (:report (lambda (condition stream)
            (format stream "Certificate does not identify ~A (names: ~{~A~^, ~})"
                    (hostname-mismatch-hostname condition)
                    (hostname-mismatch-names condition)))))

(defun normalize-hostname (name)
  "Return the ASCII, lower-case form used for RFC 6125 comparison.
NAME may already be an A-label.  The optional IDN dependency is used when
available; otherwise non-ASCII names are rejected rather than compared as
Unicode (which would make the result dependent on implementation details)."
  (check-type name string)
  (let ((name (string-downcase (string-trim '(#\Space #\Tab #\Newline #\Return)
                                             name))))
    (when (or (zerop (length name))
              (find #\Null name))
      (error 'hostname-mismatch :hostname name :names nil))
    (when (and (> (length name) 1) (char= (char name (1- (length name))) #\.))
      (setf name (subseq name 0 (1- (length name)))))
    (if (every (lambda (character) (< (char-code character) 128)) name)
        name
        (let* ((package (find-package "IDNA"))
               (symbol (and package (or (find-symbol "TO-ASCII" package)
                                        (find-symbol "NAME-TO-ASCII" package)))))
          (if (and symbol (fboundp symbol))
              (string-downcase (funcall symbol name))
              (error 'hostname-mismatch :hostname name :names nil))))))

(defun %dns-name-match-p (pattern hostname)
  (let ((pattern (normalize-hostname pattern))
        (hostname (normalize-hostname hostname)))
    (if (and (>= (length pattern) 3)
             (string= "*." (subseq pattern 0 2)))
        ;; RFC 6125 permits the wildcard only in the complete left-most label.
        (and (not (find #\* (subseq pattern 2)))
             (let ((suffix (subseq pattern 1)))
               (and (> (length hostname) (length suffix))
                    (string= suffix (subseq hostname (- (length hostname)
                                                        (length suffix))))
                    (not (find #\. (subseq hostname 0 (- (length hostname)
                                                          (length suffix))))))))
        (and (not (find #\* pattern)) (string= pattern hostname)))))

(defun %parse-ipv4 (name)
  (let ((parts (uiop:split-string name :separator ".")))
    (when (and (= (length parts) 4)
               (every (lambda (part)
                        (and (plusp (length part))
                             (every #'digit-char-p part)
                             (<= (parse-integer part) 255)))
                      parts))
      (map 'vector #'parse-integer parts))))

(defun %split-colons (name)
  (labels ((split (start)
             (let ((end (position #\: name :start start)))
               (if end
                   (cons (subseq name start end) (split (1+ end)))
                   (list (subseq name start))))))
    (split 0)))

(defun %parse-ipv6-part (part)
  (if (find #\. part)
      (let ((ipv4 (%parse-ipv4 part)))
        (and ipv4
             (list (+ (ash (aref ipv4 0) 8) (aref ipv4 1))
                   (+ (ash (aref ipv4 2) 8) (aref ipv4 3)))))
      (and (<= 1 (length part) 4)
           (every (lambda (character) (digit-char-p character 16)) part)
           (list (parse-integer part :radix 16)))))

(defun %parse-ipv6 (name)
  (let* ((compression (search "::" name))
         (second-compression (and compression
                                  (search "::" name :start2 (+ compression 2)))))
    (when (and (find #\: name) (null second-compression))
      (let* ((left (if compression (subseq name 0 compression) name))
             (right (if compression (subseq name (+ compression 2)) ""))
             (left-parts (if (zerop (length left)) nil (%split-colons left)))
             (right-parts (if (zerop (length right)) nil (%split-colons right)))
             (left-parsed (mapcar #'%parse-ipv6-part left-parts))
             (right-parsed (mapcar #'%parse-ipv6-part right-parts))
             (valid-parts-p (lambda (parts parsed)
                              (and (every (lambda (part) (plusp (length part))) parts)
                                   (every #'identity parsed))))
             (left-valid (funcall valid-parts-p left-parts left-parsed))
             (right-valid (funcall valid-parts-p right-parts right-parsed))
             (left-values (and left-valid (mapcan #'identity left-parsed)))
             (right-values (and right-valid (mapcan #'identity right-parsed)))
             (total (+ (length left-values) (length right-values))))
        (when (and left-valid right-valid
                   (if compression
                       (< total 8)
                       (= total 8)))
          (let ((values (append left-values
                                (make-list (- 8 total) :initial-element 0)
                                right-values)))
            (make-array 16 :element-type '(unsigned-byte 8)
                        :initial-contents
                        (loop for value in values append
                          (list (ldb (byte 8 8) value) (ldb (byte 8 0) value))))))))))

(defun %ip-octets (name)
  (cond
    ((and (vectorp name) (= (array-rank name) 1)
          (member (length name) '(4 16))
          (every (lambda (octet) (typep octet '(unsigned-byte 8))) name))
     (coerce name '(vector (unsigned-byte 8))))
    ((stringp name)
     (or (%parse-ipv4 name) (%parse-ipv6 name)))
    (t nil)))

(defun hostname-match-p (hostname subject-alternative-names)
  "Match HOSTNAME against SAN entries.  SAN entries are (:DNS NAME) or
(:IP ADDRESS), and bare strings are treated as DNS names for convenience.
There is deliberately no CN fallback."
  (let ((hostname-ip (%ip-octets hostname)))
    (some (lambda (entry)
            (let ((kind (and (consp entry) (car entry)))
                  (value (if (and (consp entry) (cdr entry)) (cadr entry) entry)))
              (cond ((and hostname-ip (eq kind :ip))
                     (equalp hostname-ip (%ip-octets value)))
                    ((and (not hostname-ip) (or (null kind) (eq kind :dns)))
                     (%dns-name-match-p value hostname)))))
          subject-alternative-names)))
