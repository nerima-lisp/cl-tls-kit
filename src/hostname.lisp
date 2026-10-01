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

(defun %ip-address-p (name)
  (cond
    ((and (arrayp name) (not (stringp name)) (= (array-rank name) 1))
     (or (= (length name) 4) (= (length name) 16)))
    ((stringp name)
     (or
      (let ((parts (uiop:split-string name :separator ".")))
        (and (= (length parts) 4)
             (every (lambda (part)
                      (and (plusp (length part))
                           (every #'digit-char-p part)
                           (<= (parse-integer part) 255)))
                    parts)))
      (and (find #\: name)
           (every (lambda (character)
                   (or (digit-char-p character 16)
                       (char= character #\:))) name))))
    (t nil)))

(defun hostname-match-p (hostname subject-alternative-names)
  "Match HOSTNAME against SAN entries.  SAN entries are (:DNS NAME) or
(:IP ADDRESS), and bare strings are treated as DNS names for convenience.
There is deliberately no CN fallback."
  (let ((hostname-ip (%ip-address-p hostname)))
    (some (lambda (entry)
            (let ((kind (and (consp entry) (car entry)))
                  (value (if (and (consp entry) (cdr entry)) (cadr entry) entry)))
              (cond ((and hostname-ip (eq kind :ip))
                     (if (and (stringp hostname) (stringp value))
                         (string= hostname value)
                         (equalp hostname value)))
                    ((and (not hostname-ip) (or (null kind) (eq kind :dns)))
                     (%dns-name-match-p value hostname)))))
          subject-alternative-names)))
