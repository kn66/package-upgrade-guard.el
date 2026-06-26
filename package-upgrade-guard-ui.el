;;; package-upgrade-guard-ui.el --- User interface functions for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains user interface and display functions for package-upgrade-guard.

;;; Code:

(require 'diff)
(require 'subr-x)
(require 'vc-git)
(require 'package-upgrade-guard-constants)
(require 'package-upgrade-guard-utils)
(require 'package-upgrade-guard-exclusions)
(require 'package-upgrade-guard-tar)
(require 'package-upgrade-guard-diff)

(defun package-upgrade-guard--git-output (directory &rest args)
  "Return trimmed git output for ARGS in DIRECTORY, or nil on failure."
  (let ((default-directory directory))
    (with-temp-buffer
      (when (equal 0 (apply #'call-process "git" nil t nil args))
        (string-trim (buffer-string))))))

(defun package-upgrade-guard--git-upstream (directory)
  "Return the upstream revision for DIRECTORY, or nil if none is set."
  (let ((upstream
         (package-upgrade-guard--git-output
          directory
          "rev-parse"
          "--abbrev-ref"
          "--symbolic-full-name"
          "@{upstream}")))
    (or (and upstream
             (not (string-empty-p upstream))
             upstream)
        (let ((remote-head
               (package-upgrade-guard--git-output
                directory
                "symbolic-ref"
                "--short"
                "refs/remotes/origin/HEAD")))
          (and remote-head
               (not (string-empty-p remote-head))
               remote-head)))))

(defun package-upgrade-guard--insert-git-command
    (directory empty-message &rest args)
  "Run git ARGS in DIRECTORY and insert output.
When the command succeeds without output, insert EMPTY-MESSAGE if
it is non-nil.  Return non-nil on success."
  (let ((default-directory directory)
        (start (point)))
    (let ((status (apply #'call-process "git" nil t nil args)))
      (cond
       ((equal status 0)
        (when (and empty-message (= start (point)))
          (insert empty-message "\n"))
        t)
       (t
        (insert
         (format "\n[git %s exited with status %s]\n"
                 (mapconcat #'identity args " ")
                 status))
        nil)))))

(defun package-upgrade-guard--show-tarball-diff (pkg-desc)
  "Show diff for tarball package PKG-DESC."
  (let* ((pkg-name (package-desc-name pkg-desc))
         (old-dir
          (package-upgrade-guard--find-installed-package-dir
           pkg-name))
         (temp-dir
          (package-upgrade-guard--download-package-safely pkg-desc)))

    (if (not old-dir)
        ;; New package - show contents
        (progn
          (message "New package %s - showing contents..." pkg-name)
          (package-upgrade-guard--show-package-contents temp-dir)
          (package-upgrade-guard--ask-user-approval
           pkg-desc "install new package"))
      ;; Existing package - show diff
      (let ((diff-buffer
             (get-buffer-create "*Package Security Diff*"))
            (old-version
             (package-upgrade-guard--get-version-from-dir old-dir))
            (new-version
             (package-version-join (package-desc-version pkg-desc)))
            matching-files)
        (with-current-buffer diff-buffer
          (let ((inhibit-read-only t))
            (erase-buffer))
          (insert (format "Diff for package %s:\n" pkg-name))
          (insert
           (format "Old version: %s\n" (or old-version "unknown")))
          (insert (format "New version: %s\n\n" new-version))

          ;; Generate diff
          (setq matching-files
                (package-upgrade-guard--generate-diff old-dir temp-dir))

          (diff-mode)
          (read-only-mode 1)
          (goto-char (point-min)))

        (if (and (package-upgrade-guard--security-diff-only-p)
                 (numberp matching-files)
                 (zerop matching-files))
            (progn
              (package-upgrade-guard--cleanup-diff-buffers)
              (message
               "Security check: auto-approved %s; no sensitive hunks found"
               pkg-name)
              t)
          (display-buffer diff-buffer)
          (package-upgrade-guard--ask-user-approval
           pkg-desc "upgrade package"))))))

(defun package-upgrade-guard--show-vc-diff (pkg-desc)
  "Show git diff for VC package PKG-DESC.
Returns t if user approves, nil if rejected."
  (let* ((pkg-dir (package-desc-dir pkg-desc))
         (pkg-name (package-desc-name pkg-desc))
         (default-directory pkg-dir))

    (unless (and pkg-dir (file-directory-p pkg-dir))
      (error "VC package directory not found: %s" pkg-dir))

    (unless (file-exists-p (expand-file-name ".git" pkg-dir))
      (error "Not a git repository: %s" pkg-dir))

    (let ((diff-buffer (get-buffer-create "*Package VC Diff*"))
          (fetch-succeeded t)
          (security-review-clear nil))
      (with-current-buffer diff-buffer
        (let ((inhibit-read-only t))
          (erase-buffer))
        (insert (format "Git diff for VC package %s:\n" pkg-name))
        (insert (format "Repository: %s\n\n" pkg-dir))

        ;; Show current status
        (insert "=== Git Status ===\n")
        (condition-case err
            (package-upgrade-guard--insert-git-command
             pkg-dir "Working tree clean" "status" "--short" "--branch")
          (error
           (insert (format "Error getting git status: %s\n" err))))

        ;; Fetch latest changes
        (insert "\n=== Fetching latest changes ===\n")
        (condition-case err
            (unless (package-upgrade-guard--insert-git-command
                     pkg-dir "Fetch completed" "fetch")
              (setq fetch-succeeded nil))
          (error
           (setq fetch-succeeded nil)
           (insert (format "Error fetching: %s\n" err))))

        (let ((upstream
               (package-upgrade-guard--git-upstream pkg-dir)))
          (if (not upstream)
              (insert
               "\nNo upstream branch found; cannot compute incoming diff.\n")
            ;; Show what commits will be pulled
            (insert
             (format "\n=== New commits to be pulled from %s ===\n"
                     upstream))
            (condition-case err
                (package-upgrade-guard--insert-git-command
                 pkg-dir "No new commits" "log" "--oneline"
                 (format "HEAD..%s" upstream))
              (error
               (insert (format "Error getting commit log: %s\n" err))))

            ;; Show detailed diff
            (insert "\n=== Detailed diff ===\n")
            (when (package-upgrade-guard--security-diff-only-p)
              (insert "Diff mode: security-sensitive hunks only\n"))
            (condition-case err
                (if (package-upgrade-guard--security-diff-only-p)
                    (let* ((diff-content
                            (package-upgrade-guard--git-output
                             pkg-dir "diff" (format "HEAD..%s" upstream)))
                           (filtered
                            (and diff-content
                                 (package-upgrade-guard--filter-security-unified-diff
                                  diff-content))))
                      (cond
                       ((null diff-content)
                        (insert "Error getting diff\n"))
                       ((not (string-empty-p filtered))
                        (insert filtered "\n"))
                       (t
                        (insert "No security-sensitive hunks matched current patterns\n")
                        (when fetch-succeeded
                          (setq security-review-clear t)))))
                  (package-upgrade-guard--insert-git-command
                   pkg-dir "No changes in diff" "diff"
                   (format "HEAD..%s" upstream)))
              (error
               (insert (format "Error getting diff: %s\n" err))))))

        (diff-mode)
        (read-only-mode 1)
        (font-lock-ensure)
        (goto-char (point-min)))

      (if security-review-clear
          (progn
            (package-upgrade-guard--cleanup-diff-buffers)
            (message
             "Security check: auto-approved %s; no sensitive hunks found"
             pkg-name)
            t)
        (display-buffer diff-buffer)
        (package-upgrade-guard--ask-user-approval
         pkg-desc "upgrade VC package")))))

(defun package-upgrade-guard--show-package-contents (pkg-dir)
  "Show contents of package directory PKG-DIR."
  (let ((contents-buffer (get-buffer-create "*Package Contents*")))
    (with-current-buffer contents-buffer
      (erase-buffer)
      (insert (format "Contents of new package in %s:\n\n" pkg-dir))

      ;; List files
      (insert "Files:\n")
      (condition-case nil
          (dolist (file (directory-files-recursively pkg-dir ".*"))
            (insert
             (format "  %s\n" (file-relative-name file pkg-dir))))
        (error
         (insert "  [Error listing files]\n")))

      ;; Show main .el file if it exists
      (let ((main-el-files
             (condition-case nil
                 (directory-files pkg-dir nil "\\.el\\'")
               (error
                nil))))
        (when main-el-files
          (insert "\n--- Main .el file preview ---\n")
          (let ((main-file
                 (expand-file-name (car main-el-files) pkg-dir)))
            (let ((content
                   (package-upgrade-guard--safe-read-file
                    main-file
                    package-upgrade-guard--file-preview-size)))
              (insert content)
              (when (and (not (string-prefix-p "[Error" content))
                         (> (nth 7 (file-attributes main-file))
                            package-upgrade-guard--file-preview-size))
                (insert "\n... [truncated] ...")))))))

    (display-buffer contents-buffer)))

(defun package-upgrade-guard--ask-user-approval (pkg-desc action)
  "Ask user for approval to ACTION on PKG-DESC.
Automatically cleans up diff buffers after approval/rejection."
  (let ((pkg-name (package-desc-name pkg-desc))
        (result nil))
    (unwind-protect
        (progn
          ;; Clear any pending input to avoid double input issues
          (discard-input)

          ;; Use yes-or-no-p for simpler input handling
          (let ((prompt
                 (format "Security check: Approve %s for %s? "
                         action
                         pkg-name)))
            (setq result (yes-or-no-p prompt))))

      ;; Cleanup diff buffers after decision
      (package-upgrade-guard--cleanup-diff-buffers))
    result))

(provide 'package-upgrade-guard-ui)

;;; package-upgrade-guard-ui.el ends here
