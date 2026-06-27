;;; package-upgrade-guard-diff.el --- Diff generation logic for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 kn66

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

(defvar package-upgrade-guard--security-review-reasons nil
  "Reasons the current security review requires manual approval.")

(defvar package-upgrade-guard--security-file-sensitive nil
  "Non-nil when the current file contains a configured sensitive pattern.")

(defvar package-upgrade-guard--review-file-changed nil
  "Non-nil when the current file differs between reviewed trees.")

(defun package-upgrade-guard--file-read-error-p (content)
  "Return non-nil when CONTENT is an error from the safe file reader."
  (string-prefix-p "[Error reading file:" content))

(defun package-upgrade-guard--security-documentation-file-p (file)
  "Return non-nil when FILE is recognized as non-executable documentation."
  (let* ((name (downcase (file-name-nondirectory file)))
         (extension (file-name-extension name)))
    (or (member extension '("md" "markdown" "org" "rst" "adoc" "txt"))
        (and (null extension)
             (member name
                     '("readme" "license" "copying" "changelog" "changes"
                       "news" "authors" "contributing"
                       "code-of-conduct"))))))

(defun package-upgrade-guard--require-manual-review (reason)
  "Mark the current security review as manual because of REASON."
  (cl-pushnew reason package-upgrade-guard--security-review-reasons
              :test #'equal))

(defun package-upgrade-guard--security-review-result (matches changes)
  "Return a review result for MATCHES.
Argument CHANGES is the changed item count."
  (list :matches matches
        :changes changes
        :complete package-upgrade-guard--security-review-complete
        :reasons (nreverse package-upgrade-guard--security-review-reasons)))

(defun package-upgrade-guard--review-no-changes-p (review)
  "Return non-nil when REVIEW completed and found no differences."
  (and review
       (plist-get review :complete)
       (zerop (or (plist-get review :changes) -1))))

(defun package-upgrade-guard--classify-git-security-changes
    (name-status numstat &optional diff-content)
  "Classify git NAME-STATUS, NUMSTAT and DIFF-CONTENT for review diagnostics."
  (let ((safe t)
        reasons)
    (dolist (line (split-string name-status "\n" t))
      (let* ((fields (split-string line "\t"))
             (status (car fields))
             (path (car (last fields))))
        (cond
         ((or (null status) (null path) (< (length fields) 2))
          (setq safe nil)
          (push "unrecognized git change metadata" reasons))
         ((string-match-p (rx string-start (or "D" "R" "C" "T")) status)
          (setq safe nil)
          (push (format "git %s change: %s" status path) reasons))
         ((not (string-match-p (rx string-start (or "A" "M") string-end)
                               status))
          (setq safe nil)
          (push (format "unclassified git %s change: %s" status path) reasons))
         ((not (package-upgrade-guard--security-documentation-file-p path))
          (setq safe nil)
          (push (format "executable or unclassified file changed: %s" path)
                reasons)))))
    (dolist (line (split-string numstat "\n" t))
      (let ((fields (split-string line "\t")))
        (when (or (< (length fields) 3)
                  (string= (car fields) "-")
                  (string= (cadr fields) "-"))
          (setq safe nil)
          (push (if (>= (length fields) 3)
                    (format "binary file changed: %s" (car (last fields)))
                  "unrecognized git size metadata")
                reasons))))
    (dolist (line (split-string (or diff-content "") "\n" t))
      (cond
       ((string-match-p (rx string-start (or "old mode " "new mode ")) line)
        (setq safe nil)
        (push "file mode changed" reasons))
       ((string-match (rx string-start "new file mode "
                          (group (+ digit)) string-end)
                      line)
        (let ((mode (match-string 1 line)))
          (unless (string= mode "100644")
            (setq safe nil)
            (push (format "unsafe new file mode: %s" mode) reasons))))))
    (list :safe safe :reasons (delete-dups (nreverse reasons)))))

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

(defun package-upgrade-guard--file-digest (file)
  "Return a SHA-256 digest for FILE, or nil when it cannot be read."
  (condition-case nil
      (with-temp-buffer
        (set-buffer-multibyte nil)
        (insert-file-contents-literally file)
        (secure-hash 'sha256 (current-buffer)))
    (error nil)))

(defun package-upgrade-guard--files-identical-p (old-file new-file)
  "Return non-nil when OLD-FILE and NEW-FILE have identical bytes."
  (let ((old-size (package-upgrade-guard--file-size old-file))
        (new-size (package-upgrade-guard--file-size new-file)))
    (and (= old-size new-size)
         (let ((old-digest (package-upgrade-guard--file-digest old-file))
               (new-digest (package-upgrade-guard--file-digest new-file)))
           (and old-digest new-digest (equal old-digest new-digest))))))

(defun package-upgrade-guard--insert-truncated-content
    (content max-size)
  "Insert CONTENT, truncating it to MAX-SIZE characters when needed."
  (if (<= (length content) max-size)
      (insert content)
    (insert (substring content 0 max-size))
    (insert
     (format "\n... [truncated after %d characters] ...\n" max-size))))

(defun package-upgrade-guard--security-diff-only-p ()
  "Return non-nil when security annotations and policy validation are enabled."
  (eq package-upgrade-guard-diff-mode 'security))

(defun package-upgrade-guard--security-regexp-match-p (content regexps)
  "Return non-nil when CONTENT matches one of REGEXPS.
Matching is case-insensitive so document directives and URL schemes cannot
evade review through capitalization."
  (let ((case-fold-search t)
        (matched nil))
    (dolist (regexp regexps matched)
      (when (string-match-p regexp content)
        (setq matched t)))))

(defun package-upgrade-guard--security-content-p (content)
  "Return non-nil when CONTENT has a configured sensitive pattern."
  (package-upgrade-guard--security-regexp-match-p
   content package-upgrade-guard-security-diff-regexp-list))

(defun package-upgrade-guard--security-active-document-p (content)
  "Return non-nil when CONTENT has an active document construct."
  (package-upgrade-guard--security-regexp-match-p
   content package-upgrade-guard-security-active-document-regexp-list))

(defun package-upgrade-guard--security-diff-line-p (line)
  "Return non-nil when unified diff LINE is security-sensitive."
  (and (string-match-p "\\`[-+]" line)
       (not (string-prefix-p "+++" line))
       (not (string-prefix-p "---" line))
       (package-upgrade-guard--security-content-p (substring line 1))))

(defun package-upgrade-guard--security-diff-hunk-line-p (line)
  "Return non-nil when changed or context diff LINE is security-sensitive."
  (and (> (length line) 0)
       (memq (aref line 0) '(?\s ?+ ?-))
       (not (string-prefix-p "+++" line))
       (not (string-prefix-p "---" line))
       (package-upgrade-guard--security-content-p (substring line 1))))

(defun package-upgrade-guard--security-diff-header-path (line)
  "Return the changed path named by a unified diff +++ LINE."
  (when (string-prefix-p "+++ " line)
    (let* ((raw (car (split-string (substring line 4) "\t")))
           (path
            (if (and (> (length raw) 1)
                     (string-prefix-p "\"" raw))
                (condition-case nil
                    (read raw)
                  (error raw))
              raw)))
      (cond
       ((string= path "/dev/null") nil)
       ((string-prefix-p "b/" path) (substring path 2))
       (t path)))))

(defun package-upgrade-guard--filter-security-unified-diff (diff-content)
  "Return sensitive portions of unified DIFF-CONTENT for analysis only.
The returned text must not be used as the user-visible review diff because
unmatched changes need to remain visible."
  (let ((lines (split-string diff-content "\n"))
        (file-header nil)
        (current-hunk nil)
        (current-hunk-matches nil)
        ;; Malformed or headerless diffs are shown conservatively.
        (current-file-full t)
        (result nil)
        (file-header-inserted nil))
    (cl-labels
        ((flush-hunk
          ()
          (when (and current-hunk
                     (or current-file-full current-hunk-matches))
            (unless file-header-inserted
              (setq result (append result file-header))
              (setq file-header-inserted t))
            (setq result (append result (nreverse current-hunk))))
          (when (and current-file-full
                     (null current-hunk)
                     file-header
                     (not file-header-inserted))
            (setq result (append result file-header))
            (setq file-header-inserted t)))
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
          (setq current-hunk-matches nil)
          (setq current-file-full t)))
      (dolist (line lines)
        (cond
         ((string-prefix-p "diff --git " line)
          (reset-file line))
         ((or (string-prefix-p "index " line)
              (string-prefix-p "new file mode " line)
              (string-prefix-p "deleted file mode " line)
              (string-prefix-p "old mode " line)
              (string-prefix-p "new mode " line)
              (string-prefix-p "similarity index " line)
              (string-prefix-p "rename from " line)
              (string-prefix-p "rename to " line)
              (string-prefix-p "--- " line)
              (string-prefix-p "+++ " line))
          (setq file-header (append file-header (list line)))
          (when (string-prefix-p "+++ " line)
            (let ((path
                   (package-upgrade-guard--security-diff-header-path line)))
              (setq current-file-full
                    (or (null path)
                        (not
                         (package-upgrade-guard--security-documentation-file-p
                          path)))))))
         ((string-prefix-p "@@ " line)
          (reset-hunk line))
         (current-hunk
          (push line current-hunk)
          (when (package-upgrade-guard--security-diff-hunk-line-p line)
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
  "Return review section for OLD-FILE and NEW-FILE.
OLD-CONTENT and NEW-CONTENT are used as fallbacks when external diff output is
unavailable."
  (condition-case err
      (let ((diff-result (diff-no-select old-file new-file nil 'noasync)))
        (unwind-protect
            (if (not diff-result)
                (progn
                  (setq package-upgrade-guard--security-review-complete nil)
                  nil)
              (let ((diff-content
                     (with-current-buffer diff-result
                       (buffer-string))))
                (with-temp-buffer
                  (when (> (length diff-content)
                           package-upgrade-guard--max-unified-diff-size)
                    (setq package-upgrade-guard--security-review-complete nil))
                  (when (package-upgrade-guard--security-diff-only-p)
                    (let ((sensitive
                           (package-upgrade-guard--filter-security-unified-diff
                            diff-content)))
                      (unless (string-empty-p sensitive)
                        (setq package-upgrade-guard--security-file-sensitive t)
                         (insert "WARNING: sensitive patterns detected; complete diff follows.\n"))))
                  (insert "File modified - showing unified diff:\n")
                  (package-upgrade-guard--insert-truncated-content
                   diff-content
                   package-upgrade-guard--max-unified-diff-size)
                  (buffer-string))))
          (when (buffer-live-p diff-result)
            (kill-buffer diff-result))))
    (error
     (setq package-upgrade-guard--security-review-complete nil)
     (unless (package-upgrade-guard--security-diff-only-p)
       (with-temp-buffer
         (insert
          (format "  Diff generation failed: %s\n"
                  (error-message-string err)))
         (insert "  Showing simple comparison:\n")
         (package-upgrade-guard--show-simple-diff old-content new-content)
         (buffer-string))))))

(defun package-upgrade-guard--new-file-diff-section (new-file rel-file)
  "Return a review section for NEW-FILE at REL-FILE."
  (setq package-upgrade-guard--review-file-changed t)
  (let ((content
         (package-upgrade-guard--safe-read-file
          new-file package-upgrade-guard--max-unified-diff-size))
        (documentation-p
         (package-upgrade-guard--security-documentation-file-p rel-file))
        (binary-p (package-upgrade-guard--binary-file-p new-file))
         (executable-p
         (let ((mode (file-modes new-file)))
           (and mode (not (zerop (logand mode #o111)))))))
    (when (or (package-upgrade-guard--file-read-error-p content)
              (> (package-upgrade-guard--file-size new-file)
                 package-upgrade-guard--max-unified-diff-size))
      (setq package-upgrade-guard--security-review-complete nil))
    (if (package-upgrade-guard--security-diff-only-p)
        (let ((matches
               (package-upgrade-guard--security-content-lines content "+")))
          (when matches
            (setq package-upgrade-guard--security-file-sensitive t))
          (unless documentation-p
            (package-upgrade-guard--require-manual-review
             (format "new non-documentation file: %s" rel-file)))
          (when (and documentation-p
                     (package-upgrade-guard--security-active-document-p
                      content))
            (package-upgrade-guard--require-manual-review
             (format "active content in documentation: %s" rel-file)))
          (when (or (file-symlink-p new-file)
                    binary-p)
            (package-upgrade-guard--require-manual-review
             (format "new link or binary file: %s" rel-file)))
          (when executable-p
            (package-upgrade-guard--require-manual-review
             (format "new executable file: %s" rel-file)))
          (cond
           (binary-p
            (format "New binary file added (%d bytes); content skipped\n"
                    (package-upgrade-guard--file-size new-file)))
           (t
            (with-temp-buffer
              (when matches
                (insert "WARNING: sensitive patterns detected; complete content follows.\n"))
              (insert (if documentation-p
                          "New documentation file added - showing content:\n"
                        "New non-documentation file added - showing content:\n"))
              (package-upgrade-guard--insert-truncated-content
               content package-upgrade-guard--max-unified-diff-size)
              (unless (string-suffix-p "\n" content)
                (insert "\n"))
              (buffer-string)))))
      (if binary-p
          (format "New binary file added (%d bytes); content skipped\n"
                  (package-upgrade-guard--file-size new-file))
        (with-temp-buffer
          (insert "New file added - showing content:\n")
          (package-upgrade-guard--insert-truncated-content
           content package-upgrade-guard--max-unified-diff-size)
          (unless (string-suffix-p "\n" content)
            (insert "\n"))
          (buffer-string))))))

(defun package-upgrade-guard--deleted-file-diff-section (old-file rel-file)
  "Return a conservative security review section for deleted REL-FILE.
OLD-FILE is the path to the deleted file's previous content."
  (setq package-upgrade-guard--review-file-changed t)
  (package-upgrade-guard--require-manual-review
   (format "file deleted: %s" rel-file))
  (if (package-upgrade-guard--binary-file-p old-file)
      (format "Binary file deleted (%d bytes); content skipped\n"
              (package-upgrade-guard--file-size old-file))
    (let ((content
           (package-upgrade-guard--safe-read-file
            old-file package-upgrade-guard--max-unified-diff-size)))
      (when (package-upgrade-guard--security-content-p content)
        (setq package-upgrade-guard--security-file-sensitive t))
      (when (or (package-upgrade-guard--file-read-error-p content)
                (> (package-upgrade-guard--file-size old-file)
                   package-upgrade-guard--max-unified-diff-size))
        (setq package-upgrade-guard--security-review-complete nil))
      (with-temp-buffer
        (insert "File deleted - showing previous content:\n")
        (package-upgrade-guard--insert-truncated-content
         content package-upgrade-guard--max-unified-diff-size)
        (unless (string-suffix-p "\n" content)
          (insert "\n"))
        (buffer-string)))))

(defun package-upgrade-guard--file-diff-section (rel-file old-dir new-dir)
  "Return the diff review section for REL-FILE between OLD-DIR and NEW-DIR."
  (let ((old-file (expand-file-name rel-file old-dir))
        (new-file (expand-file-name rel-file new-dir)))
    (cond
     ((or (file-symlink-p old-file) (file-symlink-p new-file))
      (if (equal (file-symlink-p old-file) (file-symlink-p new-file))
          (unless (package-upgrade-guard--security-diff-only-p)
            "No changes\n")
        (setq package-upgrade-guard--review-file-changed t)
        (when (package-upgrade-guard--security-diff-only-p)
          (package-upgrade-guard--require-manual-review
           (format "symbolic link changed: %s" rel-file)))
         (format "Symbolic link changed: %S -> %S\n"
                 (file-symlink-p old-file) (file-symlink-p new-file))))
     ((and (file-exists-p old-file)
           (file-exists-p new-file)
           (not (eq (file-directory-p old-file)
                    (file-directory-p new-file))))
      (setq package-upgrade-guard--review-file-changed t)
      (when (package-upgrade-guard--security-diff-only-p)
        (package-upgrade-guard--require-manual-review
         (format "file type changed: %s" rel-file)))
      (format "File type changed: %s -> %s\n"
              (if (file-directory-p old-file) "directory" "file")
              (if (file-directory-p new-file) "directory" "file")))
     ((and (file-exists-p old-file) (file-exists-p new-file))
      (cond
       ((file-directory-p old-file)
        (unless (package-upgrade-guard--security-diff-only-p)
          "Directory (skipped)\n"))
        ((or (package-upgrade-guard--binary-file-p old-file)
             (package-upgrade-guard--binary-file-p new-file))
         (if (and (equal (file-modes old-file) (file-modes new-file))
                  (package-upgrade-guard--files-identical-p old-file new-file))
             (unless (package-upgrade-guard--security-diff-only-p)
               "No changes\n")
           (setq package-upgrade-guard--review-file-changed t)
           (when (package-upgrade-guard--security-diff-only-p)
             (package-upgrade-guard--require-manual-review
              (format "binary file changed: %s" rel-file)))
           (format
            "Binary file modified (%d → %d bytes); textual diff skipped\n"
            (package-upgrade-guard--file-size old-file)
            (package-upgrade-guard--file-size new-file))))
       (t
        (let ((old-content (package-upgrade-guard--safe-read-file old-file))
              (new-content (package-upgrade-guard--safe-read-file new-file))
              (mode-changed
               (not (equal (file-modes old-file) (file-modes new-file)))))
          (when (and (package-upgrade-guard--security-diff-only-p)
                     (or (package-upgrade-guard--file-read-error-p old-content)
                         (package-upgrade-guard--file-read-error-p new-content)))
            (setq package-upgrade-guard--security-review-complete nil))
           (when (and (package-upgrade-guard--security-diff-only-p)
                      mode-changed)
            (package-upgrade-guard--require-manual-review
             (format "file mode changed: %s" rel-file)))
          (when (and (package-upgrade-guard--security-diff-only-p)
                     (package-upgrade-guard--security-documentation-file-p
                      rel-file)
                     (package-upgrade-guard--security-active-document-p
                      new-content))
            (package-upgrade-guard--require-manual-review
             (format "active content in documentation: %s" rel-file)))
           (if (string= old-content new-content)
               (cond
                (mode-changed
                 (setq package-upgrade-guard--review-file-changed t)
                 (format "File mode changed: %o -> %o\n"
                        (file-modes old-file) (file-modes new-file)))
               ((not (package-upgrade-guard--security-diff-only-p))
                "No changes\n"))
             (progn
               (setq package-upgrade-guard--review-file-changed t)
               (when (and (package-upgrade-guard--security-diff-only-p)
                         (not
                          (package-upgrade-guard--security-documentation-file-p
                           rel-file)))
                (package-upgrade-guard--require-manual-review
                 (format "executable or unclassified file changed: %s"
                         rel-file)))
              (package-upgrade-guard--unified-file-diff-section
               old-file new-file old-content new-content)))))))
     ((file-exists-p new-file)
      (package-upgrade-guard--new-file-diff-section new-file rel-file))
     ((file-exists-p old-file)
      (package-upgrade-guard--deleted-file-diff-section
       old-file rel-file)))))

(defun package-upgrade-guard--generate-diff (old-dir new-dir)
  "Generate diff between OLD-DIR and NEW-DIR and return a review result plist."
  (insert
   (format "Comparing directories:\n  Old: %s\n  New: %s\n\n"
           old-dir
           new-dir))
  (when (package-upgrade-guard--security-diff-only-p)
    (insert
     "Diff mode: complete available diffs with sensitive-pattern highlighting\n\n"))
  (let ((package-upgrade-guard--security-review-complete t)
        (package-upgrade-guard--security-review-reasons nil)
         (file-set (make-hash-table :test 'equal))
         (sensitive-files 0)
         (changed-files 0)
         (limit-reached nil))
    (dolist (file (when (file-exists-p old-dir)
                    (directory-files-recursively old-dir ".*")))
      (puthash (file-relative-name file old-dir) t file-set))
    (dolist (file (when (file-exists-p new-dir)
                    (directory-files-recursively new-dir ".*")))
      (puthash (file-relative-name file new-dir) t file-set))
    (when (> (hash-table-count file-set)
             package-upgrade-guard-max-review-files)
      (error "Package review contains too many files: %d (limit %d)"
             (hash-table-count file-set)
             package-upgrade-guard-max-review-files))
    (dolist (rel-file (sort (hash-table-keys file-set) #'string<))
      (unless limit-reached
        (let* ((package-upgrade-guard--security-file-sensitive nil)
               (package-upgrade-guard--review-file-changed nil)
               (section
                (package-upgrade-guard--file-diff-section
                 rel-file old-dir new-dir)))
          (if section
              (insert (format "\n=== %s ===\n%s" rel-file section)))
          (when (and (package-upgrade-guard--security-diff-only-p)
                     package-upgrade-guard--security-file-sensitive)
            (setq sensitive-files (1+ sensitive-files)))
          (when package-upgrade-guard--review-file-changed
            (setq changed-files (1+ changed-files)))
          (when (> (buffer-size)
                   package-upgrade-guard-max-total-diff-size)
            (setq limit-reached t
                  package-upgrade-guard--security-review-complete nil)
            (package-upgrade-guard--require-manual-review
             "total diff exceeds the display limit")
            (insert "\nReview aborted: total diff exceeds the display limit.\n")))))
    (when (package-upgrade-guard--security-diff-only-p)
      (insert
       (format "\nSensitive patterns detected in %d file(s); no changes were hidden.\n"
               sensitive-files)))
    (when (and (package-upgrade-guard--security-diff-only-p)
               (not package-upgrade-guard--security-review-complete))
      (insert
       "Security diff check was incomplete; manual approval is required.\n"))
    (when (and (package-upgrade-guard--security-diff-only-p)
               package-upgrade-guard--security-review-reasons)
      (insert "Manual approval required:\n")
      (dolist (reason (reverse package-upgrade-guard--security-review-reasons))
        (insert (format "  - %s\n" reason))))
    (package-upgrade-guard--security-review-result
     sensitive-files changed-files)))

(provide 'package-upgrade-guard-diff)

;;; package-upgrade-guard-diff.el ends here
