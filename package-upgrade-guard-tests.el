;;; package-upgrade-guard-tests.el --- Tests for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;;; Commentary:

;; Unit tests for package-upgrade-guard.

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'package-upgrade-guard)

(defun package-upgrade-guard-test--desc (name version &optional dir)
  "Return a package descriptor named NAME at VERSION.
DIR is used as the descriptor's installed directory when non-nil."
  (package-desc-create
   :name name
   :version version
   :summary "test package"
   :reqs nil
   :kind 'tar
   :archive "test"
   :dir dir))

(ert-deftest package-upgrade-guard-install-advice-rejects-without-installing ()
  "Rejected direct `package-install' reviews must not call the original install."
  (let ((pkg-desc
         (package-upgrade-guard-test--desc 'pkg '(1 0)))
        (package-upgrade-guard-enabled t)
        (called nil))
    (cl-letf (((symbol-function
                'package-upgrade-guard--install-transaction)
               (lambda (_pkg) (list pkg-desc)))
              ((symbol-function
                'package-upgrade-guard--review-install-transaction)
               (lambda (_transaction &optional _reviewed) nil)))
      (package-upgrade-guard--advice-package-install
       (lambda (&rest _args)
         (setq called t))
       pkg-desc)
      (should-not called))))

(ert-deftest package-upgrade-guard-upgrade-reviews-install-transaction ()
  "Package upgrades should review the full install transaction."
  (let ((old-desc
         (package-upgrade-guard-test--desc 'pkg '(1 0) "/tmp/pkg-1.0"))
        (new-desc
         (package-upgrade-guard-test--desc 'pkg '(2 0)))
        (dep-desc
         (package-upgrade-guard-test--desc 'dep '(1 0)))
        reviewed-transaction)
    (cl-letf (((symbol-function 'package-upgrade-guard--package-desc)
               (lambda (_pkg-name source)
                 (pcase source
                   ('installed old-desc)
                   ('archive new-desc))))
              ((symbol-function 'package-upgrade-guard--package-vc-p)
               (lambda (_pkg-desc) nil))
              ((symbol-function 'package-upgrade-guard--install-transaction)
               (lambda (_pkg-desc) (list new-desc dep-desc)))
              ((symbol-function
                'package-upgrade-guard--review-install-transaction)
               (lambda (transaction &optional _reviewed)
                 (setq reviewed-transaction transaction)
                 t)))
      (should (package-upgrade-guard--review-package-upgrade 'pkg))
      (should (equal reviewed-transaction (list new-desc dep-desc))))))

(ert-deftest package-upgrade-guard-temp-cleanup-preserves-base-directory ()
  "Cleaning up temporary files must not delete the configured base directory."
  (let* ((base-dir (make-temp-file "package-upgrade-guard-test-" t))
         (sentinel (expand-file-name "keep" base-dir))
         (package-upgrade-guard-temp-dir base-dir)
         (package-upgrade-guard--temp-dir nil)
         session-dir)
    (unwind-protect
        (progn
          (write-region "keep" nil sentinel nil 'silent)
          (setq session-dir (package-upgrade-guard--get-temp-dir))
          (should (file-directory-p session-dir))
          (should (string-prefix-p
                   (file-name-as-directory (expand-file-name base-dir))
                   (expand-file-name session-dir)))
          (package-upgrade-guard--cleanup-temp-dir)
          (should (file-directory-p base-dir))
          (should (file-exists-p sentinel))
          (should-not (file-exists-p session-dir)))
      (when (file-exists-p base-dir)
        (delete-directory base-dir t)))))

(ert-deftest package-upgrade-guard-menu-rejected-upgrade-does-not-execute ()
  "Rejected package-menu upgrades must not fall through to deletion."
  (let ((old-desc
         (package-upgrade-guard-test--desc 'pkg '(1 0) "/tmp/pkg-1.0"))
        (new-desc
         (package-upgrade-guard-test--desc 'pkg '(2 0)))
        (package-upgrade-guard-enabled t)
        (called nil)
        (unmark-args nil))
    (cl-letf (((symbol-function
                'package-upgrade-guard--collect-menu-marked-packages)
               (lambda () (cons (list new-desc) (list old-desc))))
              ((symbol-function
                'package-upgrade-guard--partition-menu-transaction)
               (lambda (_install-list _delete-list)
                 `((delete . nil)
                   (install . nil)
                   (upgrade . (,new-desc)))))
              ((symbol-function
                'package-upgrade-guard--review-menu-packages)
               (lambda (_install-list _upgrade-list)
                 (cons nil nil)))
              ((symbol-function
                'package-upgrade-guard--unmark-unapproved-packages)
               (lambda (&rest args)
                 (setq unmark-args args))))
      (package-upgrade-guard--advice-package-menu-execute
       (lambda (&optional _noquery)
         (setq called t)))
      (should-not called)
      (should (equal unmark-args
                     (list nil nil (list new-desc) nil))))))

(ert-deftest package-upgrade-guard-menu-pure-delete-still-executes ()
  "Pure package-menu deletes are not review targets and should still run."
  (let ((old-desc
         (package-upgrade-guard-test--desc 'pkg '(1 0) "/tmp/pkg-1.0"))
        (package-upgrade-guard-enabled t)
        (called nil))
    (cl-letf (((symbol-function
                'package-upgrade-guard--collect-menu-marked-packages)
               (lambda () (cons nil (list old-desc)))))
      (package-upgrade-guard--advice-package-menu-execute
       (lambda (&optional _noquery)
         (setq called t)))
      (should called))))

(ert-deftest package-upgrade-guard-detects-both-sides-of-rejected-upgrade ()
  "Rejected upgrades should mark both install and delete menu entries."
  (let ((old-desc
         (package-upgrade-guard-test--desc 'pkg '(1 0) "/tmp/pkg-1.0"))
        (new-desc
         (package-upgrade-guard-test--desc 'pkg '(2 0)))
        (other-desc
         (package-upgrade-guard-test--desc 'other '(1 0))))
    (should
     (package-upgrade-guard--unapproved-menu-entry-p
      ?I new-desc nil (list new-desc) '(pkg)))
    (should
     (package-upgrade-guard--unapproved-menu-entry-p
      ?D old-desc nil (list new-desc) '(pkg)))
    (should-not
     (package-upgrade-guard--unapproved-menu-entry-p
      ?I other-desc nil (list new-desc) '(pkg)))
    (should-not
     (package-upgrade-guard--unapproved-menu-entry-p
      ?D other-desc nil (list new-desc) '(pkg)))))

(provide 'package-upgrade-guard-tests)

;;; package-upgrade-guard-tests.el ends here
