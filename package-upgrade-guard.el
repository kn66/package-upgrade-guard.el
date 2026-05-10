;;; package-upgrade-guard.el --- Simple security checker for third-party packages -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Version: 1.2.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: convenience, packages, security

;;; Commentary:

;; Shows diff for all package upgrades/installations to help users review
;; changes before proceeding.  Supports both ELPA/MELPA archives and VC packages.

;;; Code:

(require 'cl-lib)
(require 'package)
(require 'package-upgrade-guard-constants)
(require 'package-upgrade-guard-utils)
(require 'package-upgrade-guard-exclusions)
(require 'package-upgrade-guard-tar)
(require 'package-upgrade-guard-diff)
(require 'package-upgrade-guard-ui)

(defvar package-review-policy)

;;;###autoload
(define-minor-mode package-upgrade-guard-mode
  "Enable security checking for third-party package upgrades."
  :global t
  :group 'package-upgrade-guard
  :init-value
  nil
  (if package-upgrade-guard-mode
      (package-upgrade-guard--enable)
    (package-upgrade-guard--disable)))

(defun package-upgrade-guard--built-in-review-available-p ()
  "Return non-nil when Emacs has built-in package review support."
  (and package-upgrade-guard-prefer-built-in-review
       (boundp 'package-review-policy)))

(defun package-upgrade-guard--built-in-review-policy ()
  "Build a `package-review-policy' value from guard settings."
  (if (not package-upgrade-guard-enabled)
      nil
    (let (selectors)
      (dolist (archive package-upgrade-guard-excluded-archives)
        (push (cons 'archive archive) selectors))
      (dolist (package package-upgrade-guard-excluded-packages)
        (push (cons 'package
                    (package-upgrade-guard--coerce-package-name package))
              selectors))
      (if selectors
          (cons 'not (nreverse selectors))
        t))))

(defun package-upgrade-guard--enable-built-in-review ()
  "Enable Emacs' built-in package review policy."
  (setq package-upgrade-guard--saved-package-review-policy-bound
        (boundp 'package-review-policy))
  (setq package-upgrade-guard--saved-package-review-policy
        (and package-upgrade-guard--saved-package-review-policy-bound
             (symbol-value 'package-review-policy)))
  (set 'package-review-policy
       (package-upgrade-guard--built-in-review-policy)))

(defun package-upgrade-guard--restore-built-in-review ()
  "Restore the previous built-in package review policy."
  (when (boundp 'package-review-policy)
    (if package-upgrade-guard--saved-package-review-policy-bound
        (set 'package-review-policy
             package-upgrade-guard--saved-package-review-policy)
      (makunbound 'package-review-policy)))
  (setq package-upgrade-guard--saved-package-review-policy nil)
  (setq package-upgrade-guard--saved-package-review-policy-bound nil))

(defun package-upgrade-guard--call-with-guard-disabled (function &rest args)
  "Call FUNCTION with ARGS while guard review is disabled."
  (let ((package-upgrade-guard-enabled nil))
    (apply function args)))

(defun package-upgrade-guard--approve-excluded-package
    (pkg-desc &optional action)
  "Return t after logging the exclusion reason for PKG-DESC.
When ACTION is non-nil, log an auto-approval message for ACTION."
  (let ((reason (package-upgrade-guard--get-exclusion-reason pkg-desc)))
    (if action
        (message "Auto-approving %s: %s" action reason)
      (message "Skipping security check: %s" reason)))
  t)

(defun package-upgrade-guard--review-vc-package
    (pkg-desc &optional action)
  "Return non-nil if VC package PKG-DESC is approved.
ACTION is used in the exclusion auto-approval message when non-nil."
  (if (package-upgrade-guard--package-excluded-p pkg-desc)
      (package-upgrade-guard--approve-excluded-package pkg-desc action)
    (package-upgrade-guard--show-vc-diff pkg-desc)))

(defun package-upgrade-guard--review-package-upgrade (package-name)
  "Return non-nil if upgrade of PACKAGE-NAME is approved."
  (let ((pkg-desc
         (package-upgrade-guard--package-desc package-name 'installed))
        (new-pkg-desc
         (package-upgrade-guard--package-desc package-name 'archive)))
    (cond
     ((package-upgrade-guard--package-excluded-p new-pkg-desc)
      (package-upgrade-guard--approve-excluded-package new-pkg-desc))
     ((and pkg-desc (package-vc-p pkg-desc))
      (package-upgrade-guard--review-vc-package pkg-desc))
     (new-pkg-desc
      (package-upgrade-guard--show-tarball-diff new-pkg-desc)))))

(defun package-upgrade-guard--enable ()
  "Enable security check advices."
  (if (package-upgrade-guard--built-in-review-available-p)
      (package-upgrade-guard--enable-built-in-review)
    (advice-add
     'package-upgrade
     :around #'package-upgrade-guard--advice-package-upgrade)
    (advice-add
     'package-upgrade-all
     :around #'package-upgrade-guard--advice-package-upgrade-all)
    (advice-add
     'package-menu-execute
     :around #'package-upgrade-guard--advice-package-menu-execute))
  (advice-add
   'package-vc-upgrade
   :around #'package-upgrade-guard--advice-package-vc-upgrade)
  (message
   (if (package-upgrade-guard--built-in-review-available-p)
       "Package diff guard enabled using built-in package review"
     "Package diff guard enabled")))

(defun package-upgrade-guard--disable ()
  "Disable security check advices."
  (advice-remove
   'package-upgrade #'package-upgrade-guard--advice-package-upgrade)
  (advice-remove
   'package-upgrade-all
   #'package-upgrade-guard--advice-package-upgrade-all)
  (advice-remove
   'package-menu-execute
   #'package-upgrade-guard--advice-package-menu-execute)
  (advice-remove
   'package-vc-upgrade
   #'package-upgrade-guard--advice-package-vc-upgrade)
  (package-upgrade-guard--restore-built-in-review)
  (package-upgrade-guard--cleanup-temp-dir)
  (package-upgrade-guard--cleanup-diff-buffers)
  (message "Package diff guard disabled"))

(defun package-upgrade-guard--advice-package-upgrade (orig-fun name)
  "Advise ORIG-FUN for `package-upgrade' on package NAME."
  (if (not package-upgrade-guard-enabled)
      (funcall orig-fun name)
    (let* ((package
            (package-upgrade-guard--coerce-package-name name))
           (approved nil))

      ;; Perform diff check for all packages
      (condition-case err
          (progn
            (setq approved
                  (package-upgrade-guard--review-package-upgrade
                   package))

            (if approved
                (progn
                  (message
                   "Diff check passed for %s. Proceeding with upgrade..."
                   package)
                  (package-upgrade-guard--call-with-guard-disabled
                   orig-fun name))
              (message
               "Diff check rejected for %s. Upgrade cancelled."
               package)))

        (error
         (message "Diff check failed for %s: %s"
                  package
                  (error-message-string err))
         (when
             (y-or-n-p
              (format
               "Continue with upgrade of %s despite diff check failure? "
               package))
           (package-upgrade-guard--call-with-guard-disabled
            orig-fun name)))))))

(defun package-upgrade-guard--advice-package-upgrade-all
    (orig-fun &optional query)
  "Advise ORIG-FUN for `package-upgrade-all' with optional QUERY."
  (if (not package-upgrade-guard-enabled)
      (funcall orig-fun query)
    (package-refresh-contents)
    (let ((upgradeable (package--upgradeable-packages))
          (upgraded 0))

      (if (not upgradeable)
          (message "No packages to upgrade")
        ;; Ask for overall confirmation first (like original package-upgrade-all)
        (when
            (and
             query
             (not
              (yes-or-no-p
               (format
                "Diff check %d package(s) individually and upgrade? "
                (length upgradeable)))))
          (user-error "Upgrade aborted"))

        (message "Proceeding with individual diff checks...")

        (let ((current-package 0))
          (dolist (package-name upgradeable)
            (setq current-package (1+ current-package))
            (message "Checking package %d/%d: %s"
                     current-package
                     (length upgradeable)
                     package-name)
            (condition-case err
                (when (package-upgrade-guard--upgrade-single-package
                       package-name)
                  (setq upgraded (1+ upgraded)))
              (error
               (message "Failed to upgrade %s: %s"
                        package-name
                        (error-message-string err))))))

        (message
         "Diff-checked upgrade completed: %d/%d packages upgraded"
         upgraded (length upgradeable))))))

(defun package-upgrade-guard--collect-menu-marked-packages ()
  "Return packages marked in the package menu as a cons cell."
  (let (install-list
        upgrade-list)
    (save-excursion
      (goto-char (point-min))
      (while (not (eobp))
        (let ((cmd (char-after))
              (pkg-desc (tabulated-list-get-id)))
          (when (and pkg-desc (eq cmd ?I))
            (push pkg-desc install-list))
          (when (and pkg-desc (eq cmd ?U))
            (push pkg-desc upgrade-list)))
        (forward-line)))
    (cons install-list upgrade-list)))

(defun package-upgrade-guard--review-menu-install (pkg-desc)
  "Return non-nil if menu installation of PKG-DESC is approved."
  (let ((pkg-name (package-desc-name pkg-desc)))
    (message "Diff checking installation: %s" pkg-name)
    (if (package-upgrade-guard--package-excluded-p pkg-desc)
        (package-upgrade-guard--approve-excluded-package
         pkg-desc "installation")
      (package-upgrade-guard--show-tarball-diff pkg-desc))))

(defun package-upgrade-guard--review-menu-upgrade (pkg-desc)
  "Return non-nil if menu upgrade of PKG-DESC is approved."
  (let ((pkg-name (package-desc-name pkg-desc)))
    (message "Diff checking upgrade: %s" pkg-name)
    (if (package-vc-p pkg-desc)
        (package-upgrade-guard--review-vc-package pkg-desc "upgrade")
      (if (package-upgrade-guard--package-excluded-p pkg-desc)
          (package-upgrade-guard--approve-excluded-package
           pkg-desc "upgrade")
        (package-upgrade-guard--show-tarball-diff pkg-desc)))))

(defun package-upgrade-guard--review-menu-packages
    (install-list upgrade-list)
  "Return approved packages from INSTALL-LIST and UPGRADE-LIST.
The result is a cons cell (APPROVED-INSTALLS . APPROVED-UPGRADES)."
  (let (approved-installs
        approved-upgrades)
    (dolist (pkg-desc install-list)
      (when (package-upgrade-guard--review-menu-install pkg-desc)
        (push pkg-desc approved-installs)))
    (dolist (pkg-desc upgrade-list)
      (when (package-upgrade-guard--review-menu-upgrade pkg-desc)
        (push pkg-desc approved-upgrades)))
    (cons approved-installs approved-upgrades)))

(defun package-upgrade-guard--has-rejected-menu-packages-p
    (install-list approved-installs upgrade-list approved-upgrades)
  "Return non-nil if menu package review rejected any package.
INSTALL-LIST and UPGRADE-LIST are all marked packages.
APPROVED-INSTALLS and APPROVED-UPGRADES are the approved packages."
  (or (< (length approved-installs)
         (length install-list))
      (< (length approved-upgrades)
         (length upgrade-list))))

(defun package-upgrade-guard--package-name-summary (packages)
  "Return a comma-separated package name summary for PACKAGES."
  (mapconcat (lambda (pkg)
               (symbol-name (package-desc-name pkg)))
             packages
             ", "))

(defun package-upgrade-guard--message-approved-menu-packages
    (approved-installs approved-upgrades)
  "Message a summary of APPROVED-INSTALLS and APPROVED-UPGRADES."
  (let ((total-approved
         (+ (length approved-installs)
            (length approved-upgrades))))
    (when (> total-approved 0)
      (message "Proceeding with %d approved package(s):"
               total-approved)
      (when approved-installs
        (message "  Installing: %s"
                 (package-upgrade-guard--package-name-summary
                  approved-installs)))
      (when approved-upgrades
        (message "  Upgrading: %s"
                 (package-upgrade-guard--package-name-summary
                  approved-upgrades))))))

(defun package-upgrade-guard--advice-package-menu-execute
    (orig-fun &optional noquery)
  "Advise ORIG-FUN for `package-menu-execute' with optional NOQUERY."
  (if (not package-upgrade-guard-enabled)
      (funcall orig-fun noquery)
    (let* ((marked (package-upgrade-guard--collect-menu-marked-packages))
           (install-list (car marked))
           (upgrade-list (cdr marked)))
      (if (not (or install-list upgrade-list))
          (funcall orig-fun noquery)
        (let* ((approved
                (package-upgrade-guard--review-menu-packages
                 install-list upgrade-list))
               (approved-installs (car approved))
               (approved-upgrades (cdr approved)))
          (when (package-upgrade-guard--has-rejected-menu-packages-p
                 install-list approved-installs upgrade-list approved-upgrades)
            (package-upgrade-guard--unmark-unapproved-packages
             install-list
             approved-installs
             upgrade-list
             approved-upgrades))

          (package-upgrade-guard--message-approved-menu-packages
           approved-installs approved-upgrades)

          ;; Proceed with execution (only approved packages will be processed).
          (package-upgrade-guard--call-with-guard-disabled
           orig-fun noquery))))))

(defun package-upgrade-guard--unmark-unapproved-packages
    (all-installs approved-installs all-upgrades approved-upgrades)
  "Unmark packages that were not approved during security review.
ALL-INSTALLS and ALL-UPGRADES are the marked packages.
APPROVED-INSTALLS and APPROVED-UPGRADES are approved packages."
  (let ((unapproved-installs
         (cl-set-difference all-installs approved-installs))
        (unapproved-upgrades
         (cl-set-difference all-upgrades approved-upgrades)))

    (save-excursion
      (goto-char (point-min))
      (while (not (eobp))
        (let ((cmd (char-after))
              (pkg-desc (tabulated-list-get-id)))
          (when (and pkg-desc
                     (or (and (eq cmd ?I)
                              (member pkg-desc unapproved-installs))
                         (and (eq cmd ?U)
                              (member pkg-desc unapproved-upgrades))))
            ;; Unmark this package
            (tabulated-list-put-tag " " t)))
        (forward-line)))

    (when (or unapproved-installs unapproved-upgrades)
      (let ((unapproved-names
             (append
              (mapcar
               (lambda (pkg)
                 (symbol-name (package-desc-name pkg)))
               unapproved-installs)
              (mapcar
               (lambda (pkg)
                 (symbol-name (package-desc-name pkg)))
               unapproved-upgrades))))
        (message "Skipped %d rejected package(s): %s"
                 (+ (length unapproved-installs)
                    (length unapproved-upgrades))
                 (mapconcat 'identity unapproved-names ", "))))))

(defun package-upgrade-guard--upgrade-single-package (package-name)
  "Upgrade single package PACKAGE-NAME with diff check."
  (when (package-upgrade-guard--review-package-upgrade package-name)
    ;; Call package-upgrade directly without advice to avoid double prompting.
    (package-upgrade-guard--call-with-guard-disabled
     #'package-upgrade package-name)
    t))

(defun package-upgrade-guard--package-vc-upgrade-desc (pkg-name)
  "Return package descriptor for `package-vc-upgrade' argument PKG-NAME."
  (cond
   ;; If pkg-name is already a package-desc, use it directly
   ((and pkg-name (package-desc-p pkg-name))
    pkg-name)
   ;; If pkg-name is a symbol or string, find the package-desc
   (pkg-name
    (package-upgrade-guard--package-desc
     pkg-name 'installed))
   ;; Interactive calls should pass the original interactive arg.
   (t
    nil)))

(defun package-upgrade-guard--review-package-vc-upgrade (pkg-desc)
  "Return non-nil if VC upgrade for PKG-DESC is approved."
  (let ((package-name (package-desc-name pkg-desc)))
    (condition-case err
        (package-upgrade-guard--review-vc-package pkg-desc)
      (error
       (message "Diff check failed for VC package %s: %s"
                package-name
                (error-message-string err))
       (when
           (y-or-n-p
            (format
             "Continue with upgrade of %s despite diff check failure? "
             package-name))
         t)))))

(defun package-upgrade-guard--run-approved-package-vc-upgrade
    (orig-fun pkg-desc)
  "Call ORIG-FUN to upgrade PKG-DESC when review approves it."
  (let ((package-name (package-desc-name pkg-desc)))
    (if (package-upgrade-guard--review-package-vc-upgrade pkg-desc)
        (progn
          (message
           "Diff check passed for VC package %s. Proceeding with upgrade..."
           package-name)
          ;; Call the original function with package-upgrade-guard disabled.
          (package-upgrade-guard--call-with-guard-disabled
           orig-fun pkg-desc))
      (message
       "Diff check rejected for VC package %s. Upgrade cancelled."
       package-name))))

(defun package-upgrade-guard--advice-package-vc-upgrade
    (orig-fun &optional pkg-name)
  "Advise ORIG-FUN for `package-vc-upgrade' with optional PKG-NAME."
  (if (not package-upgrade-guard-enabled)
      (funcall orig-fun pkg-name)
    (let ((pkg-desc
           (package-upgrade-guard--package-vc-upgrade-desc pkg-name)))
      (when (package-desc-p pkg-desc)
        (package-upgrade-guard--run-approved-package-vc-upgrade
         orig-fun pkg-desc)))))

(provide 'package-upgrade-guard)

;;; package-upgrade-guard.el ends here
