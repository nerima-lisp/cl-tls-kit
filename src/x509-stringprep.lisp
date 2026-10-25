(in-package #:cl-tls-kit.x509)

(defun %x509-in-range-table-p (codepoint ranges)
  (loop with low = 0
        with high = (1- (floor (length ranges) 2))
        while (<= low high)
        for middle = (floor (+ low high) 2)
        for start = (aref ranges (* 2 middle))
        for
        end = (aref ranges (1+ (* 2 middle)))
        do (cond
             ((< codepoint start)
              (setf high (1- middle)))
             ((> codepoint end)
              (setf low (1+ middle)))
             (t (return t)))
        finally (return nil)))

(defun %x509-combining-class (codepoint)
  (gethash codepoint +x509-combining-classes+ 0))

(defun %x509-mark-p (codepoint)
  (%x509-in-range-table-p codepoint +x509-stringprep-mark-ranges+))

(defun %x509-prohibited-p (codepoint)
  (%x509-in-range-table-p codepoint +x509-stringprep-prohibited-ranges+))

(defun %x509-canonical-order (codepoints)
  (let* ((ordered (coerce codepoints 'vector))
         (length (length ordered))
         (start 0))
    (loop while (< start length)
          for marks-start = (if (zerop
                                 (%x509-combining-class (aref ordered start)))
                                (1+ start)
                                start)
          for
          end = (or
                 (position-if
                  (lambda (codepoint)
                    (zerop (%x509-combining-class codepoint)))
                  ordered
                  :start
                  (1+ start))
                 length)
          do (when (< marks-start end)
               (replace ordered
                        (stable-sort (subseq ordered marks-start end)
                                     #'<
                                     :key
                                     #'%x509-combining-class)
                        :start1
                        marks-start)) (setf start end))
    ordered))

(defun %x509-compose-pair (starter combining)
  (let ((l-index (- starter #x1100))
        (v-index (- combining #x1161)))
    (cond ((and (<= 0 l-index 18) (<= 0 v-index 20))
           (+ #xac00 (* (+ (* l-index 21) v-index) 28)))
          ((and (<= #xac00 starter #xd7a3)
                (zerop (mod (- starter #xac00) 28))
                (< #x11a7 combining #x11c3))
           (+ starter (- combining #x11a7)))
          (t (gethash (logior (ash starter 21) combining)
                      +x509-normalization-composition+)))))

(defun %x509-canonical-compose (codepoints)
  (let ((output (make-array (length codepoints) :adjustable t :fill-pointer 0))
        (starter-index nil)
        (starter nil)
        (last-class 0))
    (loop for codepoint across codepoints
          for combining-class = (%x509-combining-class codepoint)
          for composite = (when starter
                            (%x509-compose-pair starter codepoint))
          do (if (and composite
                      (or (zerop last-class) (< last-class combining-class)))
                 (progn
                   (setf (aref output starter-index) composite
                         starter composite))
                 (progn
                   (when (zerop combining-class)
                     (setf starter-index (fill-pointer output)
                           starter codepoint))
                   (vector-push-extend codepoint output)
                   (setf last-class combining-class))))
    (coerce output 'list)))

(defun %x509-nfkc (codepoints)
  (let* ((decomposed
          (loop for codepoint in codepoints
                append (multiple-value-bind (mapping mapped-p)
                           (gethash codepoint
                                    +x509-normalization-decomposition+)
                         (if mapped-p
                             (copy-list mapping)
                             (list codepoint)))))
         (ordered (%x509-canonical-order decomposed)))
    (%x509-canonical-compose ordered)))

(defun %x509-decode-utf8-sequence (octets start)
  (let* ((first (aref octets start))
         (count
          (cond
            ((<= first #x7f) 1)
            ((<= #xc2 first #xdf) 2)
            ((<= #xe0 first #xef) 3)
            ((<= #xf0 first #xf4) 4)))
         (minimum
          (case count
            (2 #x80)
            (3 #x800)
            (4 #x10000)
            (otherwise 0)))
         (codepoint
          (case count
            (1 first)
            (2 (logand first #x1f))
            (3 (logand first #x0f))
            (4 (logand first #x07)))))
    (unless (and count (<= (+ start count) (length octets)))
      (return-from %x509-decode-utf8-sequence
        (values nil nil)))
    (loop for offset from 1 below
          count
          for byte = (aref octets (+ start offset))
          do (unless (<= #x80 byte #xbf)
               (return-from %x509-decode-utf8-sequence
                 (values nil nil))) (setf codepoint (+ (ash codepoint 6)
                                                       (logand byte #x3f))))
    (unless
        (and (>= codepoint minimum)
             (<= codepoint #x10ffff)
             (not (<= #xd800 codepoint #xdfff)))
      (return-from %x509-decode-utf8-sequence
        (values nil nil)))
    (values codepoint (+ start count))))

(defun %x509-utf8-codepoints (octets)
  (let ((codepoints nil)
        (offset 0))
    (loop while (< offset (length octets))
          do (multiple-value-bind (codepoint next-offset)
                 (%x509-decode-utf8-sequence octets offset)
               (unless next-offset
                 (return-from %x509-utf8-codepoints
                   (values nil nil)))
               (push codepoint codepoints)
               (setf offset next-offset)))
    (values (nreverse codepoints) t)))

(defun %x509-stringprep-map (codepoints)
  (loop for codepoint in codepoints
        append (multiple-value-bind (mapping mapped-p)
                   (gethash codepoint +x509-stringprep-map+)
                 (if mapped-p
                     (copy-list mapping)
                     (list codepoint)))))

(defun %x509-space-token-p (codepoints index)
  (and (= (aref codepoints index) #x20)
       (or (= (1+ index) (length codepoints))
           (not (%x509-mark-p (aref codepoints (1+ index)))))))

(defun %x509-insignificant-spaces (codepoints)
  (let* ((input (coerce codepoints 'vector))
         (length (length input))
         (first
          (loop for index below length
                unless (%x509-space-token-p input index)
                  return index))
         (last
          (loop for index downfrom (1- length) to 0
                unless (%x509-space-token-p input index)
                  return index)))
    (unless first
      (return-from %x509-insignificant-spaces
        '(#x20 #x20)))
    (let ((output (make-array 0 :adjustable t :fill-pointer 0)))
      (vector-push-extend #x20 output)
      (loop for index from first to last
            do (if (%x509-space-token-p input index)
                   (progn
                     (loop while (and (<= index last)
                                      (%x509-space-token-p input index))
                           do (incf index))
                     (vector-push-extend #x20 output)
                     (vector-push-extend #x20 output)
                     (decf index))
                   (vector-push-extend (aref input index) output)))
      (vector-push-extend #x20 output)
      (coerce output 'list))))

(defun %x509-prepare-directory-string (codepoints)
  (let ((normalized (%x509-nfkc (%x509-stringprep-map codepoints))))
    (if (some #'%x509-prohibited-p normalized)
        (values nil nil)
        (values (%x509-insignificant-spaces normalized) t))))
