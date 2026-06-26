;;; package-upgrade-guard-diff.el --- Diff generation logic for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains diff generation logic for package-upgrade-guard.

;;; Code:

(require 'diff)
(require 'cl-lib)
(require 'subr-x)
(require 'package-upgrade-guard-constants)
(require 'package-upgrade-guard-utils)

(defvar package-upgrade-guard--security-review-complete t
  "Non-nil while the current security diff can be checked completely.")

(defun package-upgrade-guard--file-read-error-p (content)
  "Return non-nil when CONTENT is an error from the safe file reader."
  (string-prefix-p "[Error reading file:" content))

(defun package-upgrade-guard--show-simple-diff
    (old-content new-content)
  "Show a simple comparison between OLD-CONTENT and NEW-CONTENT."
  (let ((old-lines (split-string old-content "\n" t))
        (new-lines (split-string new-content "\n" t))
        (max-lines package-upgrade-guard--max-diff-lines)
        (shown-lines 0))

    (insert
     (format "  File sizes: %d → %d bytes\n"
             (length old-content)
             (length new-content)))
    (insert
     (format "  Lines: %d → %d\n"
             (length old-lines)
             (length new-lines)))
    (insert "  First few different lines:\n")

    (let ((i 0))
      (while (and (< i (max (length old-lines) (length new-lines)))
                  (< shown-lines max-lines))
        (let ((old-line
               (if (< i (length old-lines))
                   (nth i old-lines)
                 nil))
              (new-line
               (if (< i (length new-lines))
                   (nth i new-lines)
                 nil)))

          (cond
           ;; Both lines exist but are different
           ((and old-line new-line (not (string= old-line new-line)))
            (insert
             (format
              "  -%d: %s\n"
              (1+ i)
              (truncate-string-to-width
               old-line package-upgrade-guard--line-truncate-length)))
            (insert
             (format
              "  +%d: %s\n"
              (1+ i)
              (truncate-string-to-width
               new-line package-upgrade-guard--line-truncate-length)))
            (setq shown-lines (+ shown-lines 2)))
           ;; Line deleted
           ((and old-line (not new-line))
            (insert
             (format
              "  -%d: %s\n"
              (1+ i)
              (truncate-string-to-width
               old-line package-upgrade-guard--line-truncate-length)))
            (setq shown-lines (1+ shown-lines)))
           ;; Line added
           ((and (not old-line) new-line)
            (insert
             (format
              "  +%d: %s\n"
              (1+ i)
              (truncate-string-to-width
               new-line package-upgrade-guard--line-truncate-length)))
            (setq shown-lines (1+ shown-lines))))

          (setq i (1+ i))))

      (when (>= shown-lines max-lines)
        (insert
         (format "  ... [truncated, showing first %d changes] ...\n"
                 package-upgrade-guard--max-diff-lines))))))

(defun package-upgrade-guard--file-size (file)
  "Return FILE size in bytes, or 0 if it cannot be read."
  (or (nth 7 (file-attributes file)) 0))

(defun package-upgrade-guard--binary-file-p (file)
  "Return non-nil when FILE appears to contain binary data."
  (when (file-regular-p file)
    (condition-case nil
        (with-temp-buffer
          (set-buffer-multibyte nil)
          (let ((coding-system-for-read 'no-conversion))
            (insert-file-contents-literally file nil 0 4096))
          (goto-char (point-min))
          (search-forward (string 0) nil t))
      (error nil))))

(defun package-upgrade-guard--insert-truncated-content
    (content max-size)
  "Insert CONTENT, truncating it to MAX-SIZE characters when needed."
  (if (<= (length content) max-size)
      (insert content)
    (insert (substring content 0 max-size))
    (insert
     (format "\n... [truncated after %d characters] ...\n" max-size))))

(defun package-upgrade-guard--security-diff-only-p ()
  "Return non-nil when only security-sensitive diff content should be shown."
  (eq package-upgrade-guard-diff-mode 'security))

(defun package-upgrade-guard--security-diff-line-p (line)
  "Return non-nil when unified diff LINE looks security-sensitive."
  (and (string-match-p "\\`[-+]" line)
       (not (string-prefix-p "+++" line))
       (not (string-prefix-p "---" line))
       (let ((content (substring line 1))
             (matched nil))
         (dolist (regexp package-upgrade-guard-security-diff-regexp-list matched)
           (when (string-match-p regexp content)
             (setq matched t))))))

(defun package-upgrade-guard--filter-security-unified-diff (diff-content)
  "Return only security-sensitive hunks from unified DIFF-CONTENT."
  (let ((lines (split-string diff-content "\n"))
        (file-header nil)
        (current-hunk nil)
        (current-hunk-matches nil)
        (result nil)
        (file-header-inserted nil))
    (cl-labels
        ((flush-hunk
          ()
          (when (and current-hunk current-hunk-matches)
            (unless file-header-inserted
              (setq result (append result file-header))
              (setq file-header-inserted t))
            (setq result (append result (nreverse current-hunk)))))
         (reset-hunk
          (line)
          (flush-hunk)
          (setq current-hunk (list line))
          (setq current-hunk-matches nil))
         (reset-file
          (line)
          (flush-hunk)
          (setq file-header (list line))
          (setq file-header-inserted nil)
          (setq current-hunk nil)
          (setq current-hunk-matches nil)))
      (dolist (line lines)
        (cond
         ((string-prefix-p "diff --git " line)
          (reset-file line))
         ((or (string-prefix-p "index " line)
              (string-prefix-p "new file mode " line)
              (string-prefix-p "deleted file mode " line)
              (string-prefix-p "similarity index " line)
              (string-prefix-p "rename from " line)
              (string-prefix-p "rename to " line)
              (string-prefix-p "--- " line)
              (string-prefix-p "+++ " line))
          (setq file-header (append file-header (list line))))
         ((string-prefix-p "@@ " line)
          (reset-hunk line))
         (current-hunk
          (push line current-hunk)
          (when (package-upgrade-guard--security-diff-line-p line)
            (setq current-hunk-matches t)))))
      (flush-hunk))
    (if result
        (mapconcat #'identity result "\n")
      "")))

(defun package-upgrade-guard--security-content-lines (content prefix)
  "Return matching lines from CONTENT with PREFIX and line numbers."
  (let ((lines (split-string content "\n"))
        (line-number 1)
        (shown 0)
        (result nil))
    (dolist (line lines)
      (when (and (< shown package-upgrade-guard--max-diff-lines)
                 (let ((diff-line (concat prefix line)))
                   (package-upgrade-guard--security-diff-line-p diff-line)))
        (push
         (format "%s%d: %s"
                 prefix
                 line-number
                 (truncate-string-to-width
                  line package-upgrade-guard--line-truncate-length))
         result)
        (setq shown (1+ shown)))
      (setq line-number (1+ line-number)))
    (when result
      (let ((text (mapconcat #'identity (nreverse result) "\n")))
        (if (>= shown package-upgrade-guard--max-diff-lines)
            (concat text
                    (format "\n... [truncated, showing first %d matches] ...\n"
                            package-upgrade-guard--max-diff-lines))
          (concat text "\n"))))))

(defun package-upgrade-guard--unified-file-diff-section
    (old-file new-file old-content new-content)
  "Return a review section for modified OLD-FILE and NEW-FILE."
  (condition-case err
      (let ((diff-result (diff-no-select old-file new-file nil 'noasync)))
        (unwind-protect
            (if (not diff-result)
                (progn
                  (when (package-upgrade-guard--security-diff-only-p)
                    (setq package-upgrade-guard--security-review-complete nil))
                  nil)
              (let ((diff-content
                     (with-current-buffer diff-result
                       (buffer-string))))
                (if (package-upgrade-guard--security-diff-only-p)
                    (let ((filtered
                           (package-upgrade-guard--filter-security-unified-diff
                            diff-content)))
                      (unless (string-empty-p filtered)
                        (concat
                         "File modified - showing security-sensitive hunks:\n"
                         filtered "\n")))
                  (with-temp-buffer
                    (insert "File modified - showing unified diff:\n")
                    (package-upgrade-guard--insert-truncated-content
                     diff-content
                     package-upgrade-guard--max-unified-diff-size)
                    (buffer-string)))))
          (when (buffer-live-p diff-result)
            (kill-buffer diff-result))))
    (error
     (when (package-upgrade-guard--security-diff-only-p)
       (setq package-upgrade-guard--security-review-complete nil))
     (unless (package-upgrade-guard--security-diff-only-p)
       (with-temp-buffer
         (insert
          (format "  Diff generation failed: %s\n"
                  (error-message-string err)))
         (insert "  Showing simple comparison:\n")
         (package-upgrade-guard--show-simple-diff old-content new-content)
         (buffer-string))))))

(defun package-upgrade-guard--new-file-diff-section (new-file)
  "Return a review section for NEW-FILE."
  (let ((content
         (package-upgrade-guard--safe-read-file
          new-file
          (if (package-upgrade-guard--security-diff-only-p)
              package-upgrade-guard--max-unified-diff-size
            package-upgrade-guard--file-preview-size))))
    (if (package-upgrade-guard--security-diff-only-p)
        (let ((matches
               (package-upgrade-guard--security-content-lines content "+")))
          (when (or (package-upgrade-guard--file-read-error-p content)
                    (> (package-upgrade-guard--file-size new-file)
                       package-upgrade-guard--max-unified-diff-size))
            (setq package-upgrade-guard--security-review-complete nil))
          (when matches
            (concat "New file added - showing security-sensitive lines:\n"
                    matches)))
      (with-temp-buffer
        (insert "New file added:\n")
        (insert content)
        (when (and (not (string-prefix-p "[Error" content))
                   (> (nth 7 (file-attributes new-file))
                      package-upgrade-guard--file-preview-size))
          (insert "\n... [truncated] ..."))
        (buffer-string)))))

(defun package-upgrade-guard--file-diff-section (rel-file old-dir new-dir)
  "Return the diff review section for REL-FILE between OLD-DIR and NEW-DIR."
  (let ((old-file (expand-file-name rel-file old-dir))
        (new-file (expand-file-name rel-file new-dir)))
    (cond
     ((and (file-exists-p old-file) (file-exists-p new-file))
      (cond
       ((file-directory-p old-file)
        (unless (package-upgrade-guard--security-diff-only-p)
          "Directory (skipped)\n"))
       ((or (package-upgrade-guard--binary-file-p old-file)
            (package-upgrade-guard--binary-file-p new-file))
        (unless (package-upgrade-guard--security-diff-only-p)
          (format
           "Binary file modified (%d → %d bytes); textual diff skipped\n"
           (package-upgrade-guard--file-size old-file)
           (package-upgrade-guard--file-size new-file))))
       (t
        (let ((old-content (package-upgrade-guard--safe-read-file old-file))
              (new-content (package-upgrade-guard--safe-read-file new-file)))
          (when (and (package-upgrade-guard--security-diff-only-p)
                     (or (package-upgrade-guard--file-read-error-p old-content)
                         (package-upgrade-guard--file-read-error-p new-content)))
            (setq package-upgrade-guard--security-review-complete nil))
          (if (string= old-content new-content)
              (unless (package-upgrade-guard--security-diff-only-p)
                "No changes\n")
            (package-upgrade-guard--unified-file-diff-section
             old-file new-file old-content new-content))))))
     ((file-exists-p new-file)
      (package-upgrade-guard--new-file-diff-section new-file))
     ((file-exists-p old-file)
      (unless (package-upgrade-guard--security-diff-only-p)
        "File deleted\n")))))

(defun package-upgrade-guard--generate-diff (old-dir new-dir)
  "Generate diff between OLD-DIR and NEW-DIR.
In security diff mode, return the number of files with matching hunks."
  (insert
   (format "Comparing directories:\n  Old: %s\n  New: %s\n\n"
           old-dir
           new-dir))
  (when (package-upgrade-guard--security-diff-only-p)
    (insert "Diff mode: security-sensitive hunks only\n\n"))
  (let ((package-upgrade-guard--security-review-complete t)
        (file-set (make-hash-table :test 'equal))
        (matched-files 0)
        (skipped-files 0))
    (dolist (file (when (file-exists-p old-dir)
                    (directory-files-recursively old-dir ".*")))
      (puthash (file-relative-name file old-dir) t file-set))
    (dolist (file (when (file-exists-p new-dir)
                    (directory-files-recursively new-dir ".*")))
      (puthash (file-relative-name file new-dir) t file-set))
    (dolist (rel-file (sort (hash-table-keys file-set) #'string<))
      (let ((section
             (package-upgrade-guard--file-diff-section
              rel-file old-dir new-dir)))
        (if section
            (progn
              (insert (format "\n=== %s ===\n%s" rel-file section))
              (when (package-upgrade-guard--security-diff-only-p)
                (setq matched-files (1+ matched-files))))
          (when (package-upgrade-guard--security-diff-only-p)
            (setq skipped-files (1+ skipped-files))))))
    (when (package-upgrade-guard--security-diff-only-p)
      (insert
       (format "\nSecurity diff filter skipped %d file(s) with no matching hunks.\n"
               skipped-files)))
    (when (and (package-upgrade-guard--security-diff-only-p)
               (not package-upgrade-guard--security-review-complete))
      (insert
       "Security diff check was incomplete; manual approval is required.\n"))
    (when (and (package-upgrade-guard--security-diff-only-p)
               package-upgrade-guard--security-review-complete)
      matched-files)))

(provide 'package-upgrade-guard-diff)

;;; package-upgrade-guard-diff.el ends here
