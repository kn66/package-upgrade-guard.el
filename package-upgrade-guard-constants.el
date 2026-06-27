;;; package-upgrade-guard-constants.el --- Constants and customization for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains constants and customization variables for package-upgrade-guard.

;;; Code:

(defconst package-upgrade-guard--max-diff-lines 20
  "Maximum number of diff lines to show.")

(defconst package-upgrade-guard--file-preview-size 500
  "Maximum bytes to show in file preview.")

(defconst package-upgrade-guard--line-truncate-length 80
  "Maximum length for truncated lines in diff output.")

(defconst package-upgrade-guard--max-unified-diff-size 200000
  "Maximum characters of unified diff output to insert per file.")

(defconst package-upgrade-guard--buffer-names
  '("*Package Security Diff*"
    "*Package VC Diff*"
    "*Package Contents*")
  "List of buffer names used by package security check.")

;; Customization group
(defgroup package-upgrade-guard nil
  "Security checking for package upgrades."
  :group 'package
  :prefix "package-upgrade-guard-")

;; Customization variables
(defcustom package-upgrade-guard-enabled t
  "Whether to perform security checks before installing packages."
  :type 'boolean
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-temp-dir nil
  "Base directory for temporary package review session directories."
  :type '(choice (const :tag "Default" nil) (directory :tag "Directory"))
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-prefer-built-in-review t
  "Use Emacs' built-in package review support when available.
This delegates archive package review to `package-review-policy'
on Emacs versions that provide it.  VC package upgrades still use
package-upgrade-guard's review."
  :type 'boolean
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-diff-mode 'all
  "How much diff content to show during package review.
When set to `all', show the normal package diff.  When set to
`security', show only diff hunks that match
`package-upgrade-guard-security-diff-regexp-list'.  Automatic approval
is controlled separately by
`package-upgrade-guard-security-auto-approve'."
  :type '(choice (const :tag "Show all diff content" all)
                 (const :tag "Show only security-sensitive hunks" security))
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-security-auto-approve t
  "Automatically approve conservatively classified security reviews.
This applies only in `security' diff mode.  A review is eligible only
when it completed successfully, found no sensitive patterns, and all
changes are additions or modifications to recognized documentation
files.  Reviews with executable files, binary content, deletions,
renames, dependency metadata, or other unclassified changes always
require manual approval."
  :type 'boolean
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-security-diff-regexp-list
  (list
   (rx symbol-start
       (or "eval" "eval-buffer" "eval-region" "eval-expression"
           "funcall" "apply" "command-execute"
           "load" "load-file" "load-library" "require" "autoload"
           "module-load" "native-compile" "byte-compile-file"
           "read" "read-from-string" "intern" "fset" "defalias"
           "advice-add" "add-function" "defadvice" "add-hook"
           "remove-hook")
       symbol-end)
   (rx symbol-start
       (or "shell-command" "async-shell-command" "call-process"
           "shell-command-to-string" "call-process-shell-command"
           "process-file" "process-lines" "process-lines-ignore-status"
           "start-process" "start-process-shell-command"
           "start-file-process" "start-file-process-shell-command"
           "make-process" "compile")
       symbol-end)
   (rx symbol-start
       (or "url-retrieve" "url-retrieve-synchronously" "url-copy-file"
           "url-insert-file-contents" "make-network-process"
           "open-network-stream" "network-stream-open-starttls"
           "gnutls-negotiate" "browse-url")
       symbol-end)
   (rx symbol-start
       (or "write-region" "append-to-file" "with-temp-file" "write-file"
           "save-buffer" "delete-file" "delete-directory" "rename-file"
           "copy-file" "make-directory" "make-symbolic-link"
           "add-name-to-file" "set-file-modes" "set-file-times")
       symbol-end)
   (rx symbol-start
       (or "package-install" "package-vc-install" "package-refresh-contents"
           "straight-use-package" "quelpa")
       symbol-end)
   (rx (or "http://" "https://" "curl " "wget "))
   (rx (or ";;;###autoload" "Package-Requires:"
           (seq "Local " "Variables:") "eval:")))
  "Regexps used by `package-upgrade-guard-diff-mode' value `security'.
A diff hunk is shown when at least one added or removed line
matches any regexp in this list."
  :type '(repeat regexp)
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-excluded-archives nil
  "List of package archives to exclude from security checks.
Each element should be a string matching an archive name from
`package-archives'.  For example, list \"gnu\" and \"nongnu\" to
exclude GNU ELPA and NonGNU ELPA."
  :type '(repeat string)
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-excluded-packages nil
  "List of package names to exclude from security checks.
Each element should be a symbol or string matching a package name.
For example, use a list such as `magit', `org-mode', and `helm'
to exclude specific packages."
  :type '(repeat (choice symbol string))
  :group 'package-upgrade-guard)

;; Internal variables
(defvar package-upgrade-guard--temp-dir nil
  "Actual temporary directory used for security checks.")

(defvar package-upgrade-guard--saved-package-review-policy nil
  "Previous value of `package-review-policy' before enabling guard.")

(defvar package-upgrade-guard--saved-package-review-policy-bound nil
  "Non-nil if `package-review-policy' was bound before enabling guard.")

(provide 'package-upgrade-guard-constants)

;;; package-upgrade-guard-constants.el ends here
