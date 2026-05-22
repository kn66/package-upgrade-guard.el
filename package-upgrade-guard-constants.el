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
