;;; package-upgrade-guard.el --- Simple security checker for third-party packages -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; URL: https://github.com/kn66/package-upgrade-guard.el
;; Version: 1.3.0
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

(defun package-upgrade-guard--package-install-target (pkg)
  "Return the package descriptor or name that `package-install' will use for PKG."
  (let ((name (if (package-desc-p pkg)
                  (package-desc-name pkg)
                pkg)))
    (if (and (or current-prefix-arg
                 (bound-and-true-p package-install-upgrade-built-in))
             (fboundp 'package--active-built-in-p)
             (package--active-built-in-p pkg))
        (or (cadr (assq name package-archive-contents)) pkg)
      pkg)))

(defun package-upgrade-guard--install-transaction (pkg)
  "Return the package installation transaction for PKG."
  (when (fboundp 'package--archives-initialize)
    (package--archives-initialize))
  (let ((target (package-upgrade-guard--package-install-target pkg)))
    (cond
     ((package-desc-p target)
      (unless (package-installed-p target)
        (package-compute-transaction
         (list target)
         (package-desc-reqs target))))
     ((symbolp target)
      (package-compute-transaction nil (list (list target)))))))

(defun package-upgrade-guard--review-install-package (pkg-desc)
  "Return non-nil if installing PKG-DESC is approved."
  (let ((pkg-name (package-desc-name pkg-desc)))
    (condition-case err
        (progn
          (message "Diff checking installation: %s" pkg-name)
          (if (package-upgrade-guard--package-excluded-p pkg-desc)
              (package-upgrade-guard--approve-excluded-package
               pkg-desc "installation")
            (package-upgrade-guard--show-tarball-diff pkg-desc)))
      (error
       (message "Diff check failed for installation of %s: %s"
                pkg-name
                (error-message-string err))
       (when
           (y-or-n-p
            (format
             "Continue with installation of %s despite diff check failure? "
             pkg-name))
         t)))))

(defun package-upgrade-guard--review-install-transaction
    (transaction &optional reviewed)
  "Return non-nil if every package in TRANSACTION is approved.
REVIEWED is an optional hash table that caches decisions by full
package name."
  (let ((approved t)
        (reviewed (or reviewed (make-hash-table :test 'equal))))
    (dolist (pkg-desc transaction approved)
      (let* ((key (package-desc-full-name pkg-desc))
             (state (gethash key reviewed :missing)))
        (cond
         ((eq state :approved))
         ((eq state :rejected)
          (setq approved nil))
         ((package-upgrade-guard--review-install-package pkg-desc)
          (puthash key :approved reviewed))
         (t
          (puthash key :rejected reviewed)
          (setq approved nil)))))))

(defun package-upgrade-guard--review-package-upgrade (package-name)
  "Return non-nil if upgrade of PACKAGE-NAME is approved."
  (let ((pkg-desc
         (package-upgrade-guard--package-desc package-name 'installed))
        (new-pkg-desc
         (package-upgrade-guard--package-desc package-name 'archive)))
    (cond
     ((and pkg-desc
           (package-upgrade-guard--package-vc-p pkg-desc))
      (package-upgrade-guard--review-vc-package pkg-desc))
     (new-pkg-desc
      (package-upgrade-guard--review-install-transaction
       (package-upgrade-guard--install-transaction new-pkg-desc))))))

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
     'package-install
     :around #'package-upgrade-guard--advice-package-install)
    (advice-add
     'package-menu-execute
     :around #'package-upgrade-guard--advice-package-menu-execute))
  (when (fboundp 'package-vc-upgrade)
    (advice-add
     'package-vc-upgrade
     :around #'package-upgrade-guard--advice-package-vc-upgrade))
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
   'package-install #'package-upgrade-guard--advice-package-install)
  (advice-remove
   'package-menu-execute
   #'package-upgrade-guard--advice-package-menu-execute)
  (when (fboundp 'package-vc-upgrade)
    (advice-remove
     'package-vc-upgrade
     #'package-upgrade-guard--advice-package-vc-upgrade))
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

(defun package-upgrade-guard--advice-package-install
    (orig-fun pkg &optional dont-select)
  "Advise ORIG-FUN for `package-install' on package PKG.
DONT-SELECT is passed through to ORIG-FUN."
  (if (not package-upgrade-guard-enabled)
      (funcall orig-fun pkg dont-select)
    (let* ((name (if (package-desc-p pkg)
                     (package-desc-name pkg)
                   pkg))
           (transaction
            (package-upgrade-guard--install-transaction pkg)))
      (if (package-upgrade-guard--review-install-transaction transaction)
          (progn
            (when transaction
              (message
               "Diff check passed for %s. Proceeding with installation..."
               name))
            (package-upgrade-guard--call-with-guard-disabled
             orig-fun pkg dont-select))
        (message
         "Diff check rejected for %s. Installation cancelled."
         name)))))

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
  "Return marked package menu entries as (INSTALL-LIST . DELETE-LIST)."
  (let (install-list
        delete-list)
    (save-excursion
      (goto-char (point-min))
      (while (not (eobp))
        (let ((cmd (char-after))
              (pkg-desc (tabulated-list-get-id)))
          (when (and pkg-desc (eq cmd ?I))
            (push pkg-desc install-list))
          (when (and pkg-desc (eq cmd ?D))
            (push pkg-desc delete-list)))
        (forward-line)))
    (cons install-list delete-list)))

(defun package-upgrade-guard--menu-default-transaction ()
  "Return the package menu default transaction as (INSTALL . DELETE)."
  (unless (and (tabulated-list-get-id)
               (bound-and-true-p package-menu-use-current-if-no-marks))
    (user-error "No operations specified"))
  (let ((pkg-desc (tabulated-list-get-id))
        (status (package-menu-get-status)))
    (cond
     ((member status '("installed"))
      (cons nil (list pkg-desc)))
     ((member status '("available" "avail-obso" "new" "dependency"))
      (cons (list pkg-desc) nil))
     (t
      (user-error "No default action available for status: %s"
                  status)))))

(defun package-upgrade-guard--partition-menu-transaction
    (install-list delete-list)
  "Partition package menu INSTALL-LIST and DELETE-LIST."
  (if (fboundp 'package-menu--partition-transaction)
      (package-menu--partition-transaction install-list delete-list)
    (let* ((upgrades
            (cl-intersection
             install-list delete-list :key #'package-desc-name))
           (installs
            (cl-set-difference
             install-list upgrades :key #'package-desc-name))
           (deletes
            (cl-set-difference
             delete-list upgrades :key #'package-desc-name)))
      `((delete . ,deletes)
        (install . ,installs)
        (upgrade . ,upgrades)))))

(defun package-upgrade-guard--review-menu-package-list
    (packages reviewed)
  "Return packages from PACKAGES approved for menu execution.
REVIEWED caches package decisions across package transactions."
  (let (approved)
    (dolist (pkg-desc packages (nreverse approved))
      (when (package-upgrade-guard--review-install-transaction
             (package-upgrade-guard--install-transaction pkg-desc)
             reviewed)
        (push pkg-desc approved)))))

(defun package-upgrade-guard--review-menu-packages
    (install-list upgrade-list)
  "Return approved packages from INSTALL-LIST and UPGRADE-LIST.
The result is a cons cell (APPROVED-INSTALLS . APPROVED-UPGRADES)."
  (let ((reviewed (make-hash-table :test 'equal)))
    (cons
     (package-upgrade-guard--review-menu-package-list
      install-list reviewed)
     (package-upgrade-guard--review-menu-package-list
      upgrade-list reviewed))))

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
    (let ((menu-buffer (current-buffer))
          (menu-point (point-marker)))
      (unwind-protect
          (let* ((marked (package-upgrade-guard--collect-menu-marked-packages))
                 (had-marks (or (car marked) (cdr marked)))
                 (raw-transaction
                  (if had-marks
                      marked
                    (package-upgrade-guard--menu-default-transaction)))
                 (install-list (car raw-transaction))
                 (delete-list (cdr raw-transaction)))
            (if (not install-list)
                (with-current-buffer menu-buffer
                  (goto-char menu-point)
                  (package-upgrade-guard--call-with-guard-disabled
                   orig-fun noquery))
              (let* ((partition
                      (package-upgrade-guard--partition-menu-transaction
                       install-list delete-list))
                     (pure-installs (alist-get 'install partition))
                     (pure-deletes (alist-get 'delete partition))
                     (upgrades (alist-get 'upgrade partition))
                     (approved
                      (package-upgrade-guard--review-menu-packages
                       pure-installs upgrades))
                     (approved-installs (car approved))
                     (approved-upgrades (cdr approved)))
                (when (and had-marks
                           (package-upgrade-guard--has-rejected-menu-packages-p
                            pure-installs approved-installs
                            upgrades approved-upgrades))
                  (with-current-buffer menu-buffer
                    (package-upgrade-guard--unmark-unapproved-packages
                     pure-installs
                     approved-installs
                     upgrades
                     approved-upgrades)))

                (package-upgrade-guard--message-approved-menu-packages
                 approved-installs approved-upgrades)

                (if (or approved-installs approved-upgrades pure-deletes)
                    ;; Proceed with execution; rejected installs/upgrades were unmarked.
                    (with-current-buffer menu-buffer
                      (goto-char menu-point)
                      (package-upgrade-guard--call-with-guard-disabled
                       orig-fun noquery))
                  (message "No approved package menu operations to execute")))))
        (set-marker menu-point nil)))))

(defun package-upgrade-guard--unapproved-menu-entry-p
    (cmd pkg-desc unapproved-installs unapproved-upgrades
         unapproved-upgrade-names)
  "Return non-nil when menu entry CMD for PKG-DESC should be unmarked.
UNAPPROVED-INSTALLS and UNAPPROVED-UPGRADES are package
descriptors rejected by review.  UNAPPROVED-UPGRADE-NAMES is the
list of package names for UNAPPROVED-UPGRADES."
  (and pkg-desc
       (or (and (eq cmd ?I)
                (or (member pkg-desc unapproved-installs)
                    (member pkg-desc unapproved-upgrades)))
           (and (eq cmd ?D)
                (memq (package-desc-name pkg-desc)
                      unapproved-upgrade-names)))))

(defun package-upgrade-guard--unmark-unapproved-packages
    (all-installs approved-installs all-upgrades approved-upgrades)
  "Unmark packages that were not approved during security review.
ALL-INSTALLS and ALL-UPGRADES are the marked packages.
APPROVED-INSTALLS and APPROVED-UPGRADES are approved packages."
  (let ((unapproved-installs
         (cl-set-difference all-installs approved-installs))
        (unapproved-upgrades
         (cl-set-difference all-upgrades approved-upgrades))
        (unapproved-upgrade-names nil))
    (setq unapproved-upgrade-names
          (mapcar #'package-desc-name unapproved-upgrades))

    (save-excursion
      (goto-char (point-min))
      (while (not (eobp))
        (let ((cmd (char-after))
              (pkg-desc (tabulated-list-get-id)))
          (when (package-upgrade-guard--unapproved-menu-entry-p
                 cmd pkg-desc unapproved-installs unapproved-upgrades
                 unapproved-upgrade-names)
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
      (if (package-desc-p pkg-desc)
          (package-upgrade-guard--run-approved-package-vc-upgrade
           orig-fun pkg-desc)
        (funcall orig-fun pkg-name)))))

(provide 'package-upgrade-guard)

;;; package-upgrade-guard.el ends here
