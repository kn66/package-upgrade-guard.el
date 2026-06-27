;;; package-upgrade-guard-constants.el --- Constants and customization for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 kn66

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains constants and customization variables for package-upgrade-guard.

;;; Code:

(defconst package-upgrade-guard--max-diff-lines 20
  "Maximum number of diff lines to show.")

(defconst package-upgrade-guard--line-truncate-length 80
  "Maximum length for truncated lines in diff output.")

(defconst package-upgrade-guard--max-unified-diff-size 200000
  "Maximum characters of unified diff output to insert per file.")

(defconst package-upgrade-guard--buffer-names
  '("*Package Security Diff*"
    "*Package VC Diff*")
  "List of buffer names used by package security check.")

;; Customization group
(defgroup package-upgrade-guard nil
  "Security checking for package upgrades."
  :group 'package
  :prefix "package-upgrade-guard-")

(defvar package-upgrade-guard-mode)
(defvar package-upgrade-guard--built-in-review-active)

(defun package-upgrade-guard--set-enabled (symbol value)
  "Set SYMBOL to VALUE and synchronize an active built-in review policy."
  (set-default symbol value)
  (when (and (bound-and-true-p package-upgrade-guard-mode)
             (bound-and-true-p package-upgrade-guard--built-in-review-active)
             (boundp 'package-review-policy))
    (set 'package-review-policy (and value t))))

;; Customization variables
(defcustom package-upgrade-guard-max-download-size (* 50 1024 1024)
  "Maximum number of bytes accepted for one downloaded package artifact."
  :type 'integer
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-max-review-files 5000
  "Maximum number of file entries compared during one package review."
  :type 'integer
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-max-total-diff-size (* 2 1024 1024)
  "Maximum total number of characters inserted into an archive diff buffer."
  :type 'integer
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-enabled t
  "Whether to perform security checks before installing packages."
  :type 'boolean
  :set #'package-upgrade-guard--set-enabled
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
`security', show the complete available diff and highlight text selected
by `package-upgrade-guard-security-diff-regexp-list'.  Filtering is never
used to hide unmatched changes."
  :type '(choice (const :tag "Show all diff content" all)
                 (const :tag "Conservative security review" security))
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-security-diff-regexp-list
  (list
   (rx symbol-start
       (or "eval" "eval-buffer" "eval-region" "eval-expression"
           "eval-after-load" "with-eval-after-load"
           "funcall" "apply" "command-execute" "call-interactively"
           "execute-kbd-macro"
            "load" "load-file" "load-library" "load-with-code-conversion"
            "load-theme" "require" "autoload" "module-load"
            "native-elisp-load"
            "native-compile" "byte-compile-file" "byte-code"
            "eval-and-compile" "eval-when-compile"
           "read" "read-from-string" "intern" "fset" "defalias"
           "run-hooks" "run-hook-with-args"
           "run-hook-with-args-until-failure"
           "run-hook-with-args-until-success"
           "org-babel-execute-src-block"
           "advice-add" "add-function" "defadvice" "define-advice"
           "add-hook" "remove-hook" "add-variable-watcher")
       symbol-end)
   (rx symbol-start
       (or "shell-command" "async-shell-command" "call-process"
            "shell-command-to-string" "shell-command-on-region"
            "call-process-shell-command" "call-process-region"
            "process-file" "process-file-region"
            "process-file-shell-command"
            "process-lines" "process-lines-ignore-status"
            "start-process" "start-process-shell-command"
            "start-file-process" "start-file-process-shell-command"
            "make-process" "make-pipe-process" "make-thread"
            "make-serial-process" "compilation-start"
            "executable-interpret"
            "set-process-filter" "set-process-sentinel"
            "process-send-string"
            "process-send-region" "process-send-eof" "comint-exec"
            "term-exec" "compile" "kill-emacs")
       symbol-end)
   (rx symbol-start
        (or "url-retrieve" "url-retrieve-synchronously" "url-queue-retrieve"
            "url-copy-file" "url-insert-file-contents" "request" "plz"
            "make-network-process"
            "open-network-stream" "network-stream-open-starttls"
            "open-network-stream-nowait" "gnutls-negotiate" "browse-url")
       symbol-end)
   (rx symbol-start
       (or "dbus-call-method" "dbus-call-method-asynchronously"
           "dbus-send-signal" "dbus-register-method"
           "dbus-register-signal")
       symbol-end)
   (rx symbol-start
       (or "insert-file-contents" "insert-file-contents-literally"
           "file-local-copy"
           "write-region" "append-to-file" "with-temp-file" "write-file"
           "save-buffer" "basic-save-buffer"
           "make-temp-file" "make-temp-directory"
           "delete-file" "delete-directory" "rename-file"
            "copy-file" "make-directory" "make-symbolic-link"
            "add-name-to-file" "set-file-modes" "set-file-times"
            "set-file-acl" "set-file-extended-attributes"
            "set-default-file-modes")
        symbol-end)
    (rx symbol-start
        (or "setenv" "customize-set-variable" "customize-set-value"
            "customize-save-variable"
            "customize-save-customized" "custom-save-all" "desktop-save"
            "define-key" "global-set-key" "local-set-key" "keymap-set"
            "keymap-global-set" "substitute-key-definition"
            "run-at-time" "run-with-timer" "run-with-idle-timer"
            "timer-set-function" "server-eval-at")
        symbol-end)
   (rx symbol-start
       (or "package-install" "package-delete" "package-vc-install"
           "package-vc-checkout" "package-refresh-contents"
           "straight-use-package" "quelpa")
       symbol-end)
   (rx (or "http://" "https://" "curl " "wget "))
   (rx symbol-start
       (or (seq (or "sh" "bash" "zsh" "fish")
                symbol-end (+ blank) "-c" symbol-end)
           (seq (or "python" "python3")
                symbol-end (+ blank) (or "-c" "-m") symbol-end)
           (seq (or "perl" "ruby" "node")
                symbol-end (+ blank) (or "-e" "--eval") symbol-end)
           (seq (or "powershell" "pwsh")
                symbol-end (+ blank)
                (or "-command" "-encodedcommand") symbol-end)))
   (rx "#." (* blank) "(")
   (rx line-start (* blank) "#+"
       (or "BIND:" "CALL:" "INCLUDE:" "SETUPFILE:"
           "PROPERTY:" "HEADER:" "HEADERS:"))
   (rx (or ";;;###autoload" "Package-Requires:"
           (seq "Local " "Variables:") "eval:"
           (seq "-*-" (*? nonl) "-*-"))))
  "Regexps highlighted by `package-upgrade-guard-diff-mode' value `security'.
These expressions identify review candidates; they never suppress unmatched
diff content."
  :type '(repeat regexp)
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-security-active-document-regexp-list
  (list
   (rx "-*-" (*? nonl) "-*-")
   (rx (seq "Local " "Variables:"))
   (rx line-start (* blank) "#+"
       (or "BIND:" "CALL:" "INCLUDE:" "SETUPFILE:"
           "PROPERTY:" "HEADER:" "HEADERS:"))
   (rx "[[" (or "elisp:" "shell:")))
  "Regexps for active document constructs that require manual review.
These expressions are checked against the complete resulting content of
recognized documentation files when that content is locally available."
  :type '(repeat regexp)
  :group 'package-upgrade-guard)

;; Internal variables
(defvar package-upgrade-guard--temp-dir nil
  "Actual temporary directory used for security checks.")

(defvar package-upgrade-guard--saved-package-review-policy nil
  "Previous value of `package-review-policy' before enabling guard.")

(defvar package-upgrade-guard--saved-package-review-policy-bound nil
  "Non-nil if `package-review-policy' was bound before enabling guard.")

(defvar package-upgrade-guard--built-in-review-active nil
  "Non-nil while this package owns the built-in package review policy.")

(defvar package-upgrade-guard--reviewed-artifact-digests
  (make-hash-table :test 'equal)
  "SHA-256 digests of package artifacts approved during the current review.")

(defvar package-upgrade-guard--installing-reviewed-artifacts nil
  "Non-nil while installing artifacts that must match reviewed digests.")

(defvar package-upgrade-guard--allowed-unreviewed-artifacts nil
  "Package full names allowed as explicit new installations.")

(defvar package-upgrade-guard--reviewed-vc-commits
  (make-hash-table :test 'equal)
  "Commit IDs approved for VC package upgrades.")

(provide 'package-upgrade-guard-constants)

;;; package-upgrade-guard-constants.el ends here
