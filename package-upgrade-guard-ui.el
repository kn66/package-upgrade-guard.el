;;; package-upgrade-guard-ui.el --- User interface functions for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 kn66

;; Author: Package Security Check
;; Keywords: tools, convenience

;;; Commentary:

;; This file contains user interface and display functions for package-upgrade-guard.

;;; Code:

(require 'diff)
(require 'subr-x)
(require 'vc-git)
(require 'package-upgrade-guard-constants)
(require 'package-upgrade-guard-utils)
(require 'package-upgrade-guard-tar)
(require 'package-upgrade-guard-diff)

(defun package-upgrade-guard--security-font-lock-matcher (limit)
  "Find a security review candidate before LIMIT for font locking."
  (let (found)
    (while (and (not found) (< (point) limit))
      (let* ((beginning (line-beginning-position))
             (end (min (line-end-position) limit))
             (line (buffer-substring-no-properties beginning end))
             (content
              (if (and (> (length line) 0)
                       (memq (aref line 0) '(?\s ?+ ?-)))
                  (substring line 1)
                line)))
        (forward-line 1)
        (when (or (package-upgrade-guard--security-content-p content)
                  (package-upgrade-guard--security-active-document-p content))
          (set-match-data (list beginning end))
          (setq found t))))
    found))

(defun package-upgrade-guard--highlight-security-patterns ()
  "Highlight configured security review candidate lines in the current buffer."
  (when (package-upgrade-guard--security-diff-only-p)
    (font-lock-add-keywords
     nil
     '((package-upgrade-guard--security-font-lock-matcher
        0 font-lock-warning-face prepend))
     'append)
    (font-lock-flush)))

(defun package-upgrade-guard--git-output (directory &rest args)
  "Return trimmed git output for ARGS in DIRECTORY, or nil on failure."
  (let ((default-directory directory))
    (with-temp-buffer
      (when (equal 0 (apply #'call-process "git" nil t nil args))
        (string-trim (buffer-string))))))

(defun package-upgrade-guard--git-tracked-status (directory)
  "Return git status output for tracked changes in DIRECTORY.
Untracked files are ignored because `package-vc' leaves generated
package artifacts such as autoloads and byte-compiled files in the
repository checkout."
  (package-upgrade-guard--git-output
   directory "status" "--porcelain" "--untracked-files=no"))

(defun package-upgrade-guard--git-output-limited
    (directory limit &rest args)
  "Run git ARGS in DIRECTORY and return bounded output.
LIMIT is the maximum number of characters retained from stdout.  On
success, return a plist with `:output' and `:truncated'.  Return nil
when git exits unsuccessfully."
  (let ((default-directory (file-name-as-directory directory))
        (buffer (generate-new-buffer " *package-upgrade-guard-git-output*"))
        (stderr (generate-new-buffer " *package-upgrade-guard-git-error*"))
        (stored 0)
        truncated
        process
        status)
    (unwind-protect
        (progn
          (with-current-buffer buffer
            (setq default-directory (file-name-as-directory directory))
            (setq process
                  (make-process
                   :name "package-upgrade-guard-git"
                   :buffer nil
                   :command (cons "git" args)
                   :connection-type 'pipe
                   :noquery t
                   :stderr stderr
                   :filter
                   (lambda (_process string)
                     (let ((length (length string)))
                       (with-current-buffer buffer
                         (let ((remaining (- limit stored)))
                           (if (> remaining 0)
                               (let ((take (min remaining length)))
                                 (insert (substring string 0 take))
                                 (setq stored (+ stored take))
                                 (when (< take length)
                                   (setq truncated t)))
                             (setq truncated t)))))))))
          (while (memq (process-status process) '(run open))
            (accept-process-output process 0.1))
          (accept-process-output process 0.1)
          (setq status (process-exit-status process))
          (when (equal status 0)
            (with-current-buffer buffer
              (list :output (string-trim (buffer-string))
                    :truncated truncated))))
      (when (and process (process-live-p process))
        (delete-process process))
      (kill-buffer buffer)
      (kill-buffer stderr))))

(defun package-upgrade-guard--insert-vc-diff-content
    (diff-content truncated)
  "Insert DIFF-CONTENT and note when it was TRUNCATED during capture."
  (package-upgrade-guard--insert-truncated-content
   diff-content package-upgrade-guard--max-unified-diff-size)
  (when (and truncated
             (<= (length diff-content)
                 package-upgrade-guard--max-unified-diff-size))
    (insert
     (format "\n... [truncated after %d characters] ...\n"
             package-upgrade-guard--max-unified-diff-size))))

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

(defun package-upgrade-guard--git-active-document-review
    (directory revision name-status)
  "Inspect documentation in DIRECTORY at REVISION according to git NAME-STATUS.
Return a plist with `:complete' and `:reasons' entries."
  (let ((complete t)
        reasons)
    (dolist (line (split-string name-status "\n" t))
      (let* ((fields (split-string line "\t"))
             (status (car fields))
             (path (car (last fields))))
        (when (and (member status '("A" "M"))
                   path
                   (package-upgrade-guard--security-documentation-file-p path))
          (let ((content
                 (package-upgrade-guard--git-output
                  directory "show" (format "%s:%s" revision path))))
            (if (null content)
                (progn
                  (setq complete nil)
                  (push (format "could not inspect documentation: %s" path)
                        reasons))
              (when (package-upgrade-guard--security-active-document-p content)
                (push (format "active content in documentation: %s" path)
                      reasons)))))))
    (list :complete complete :reasons (nreverse reasons))))

(defun package-upgrade-guard--insert-vc-security-diff
    (pkg-dir upstream fetch-succeeded working-tree-clean reviewed-commit
             review-complete)
  "Insert a security-focused VC diff and return its review state.
PKG-DIR and UPSTREAM identify the comparison.  FETCH-SUCCEEDED,
WORKING-TREE-CLEAN, REVIEWED-COMMIT, and REVIEW-COMPLETE describe the
validation performed before the diff was generated."
  (let* ((range (format "HEAD..%s" upstream))
         (diff-result
          (package-upgrade-guard--git-output-limited
           pkg-dir package-upgrade-guard--max-unified-diff-size
           "diff" range))
         (diff-content (plist-get diff-result :output))
         (diff-truncated (plist-get diff-result :truncated))
         (name-status
          (package-upgrade-guard--git-output
           pkg-dir "diff" "--name-status" range))
         (numstat
          (package-upgrade-guard--git-output
           pkg-dir "diff" "--numstat" range))
         (classification
          (and name-status numstat
               (package-upgrade-guard--classify-git-security-changes
                name-status numstat diff-content)))
         (active-document-review
          (if (and classification (plist-get classification :safe))
              (package-upgrade-guard--git-active-document-review
               pkg-dir upstream name-status)
            '(:complete t :reasons nil)))
         (sensitive-hunks
          (and diff-content
               (package-upgrade-guard--filter-security-unified-diff
                diff-content)))
         (review
          (list
           :matches
           (if (and sensitive-hunks
                    (not (string-empty-p sensitive-hunks)))
               1
             0)
           :changes
           (max (length (split-string (or name-status "") "\n" t))
                (if (string-empty-p (or diff-content "")) 0 1))
           :complete
           (and diff-content name-status numstat
                (not diff-truncated)
                (plist-get active-document-review :complete))
           :reasons
           (append
            (and classification (plist-get classification :reasons))
            (plist-get active-document-review :reasons))))
         review-no-changes)
    (cond
     ((or (null diff-content) (null name-status) (null numstat))
      (setq review-complete nil)
      (insert "Error getting complete diff metadata\n"))
     (t
      (when (and sensitive-hunks
                 (not (string-empty-p sensitive-hunks)))
        (insert "WARNING: sensitive patterns detected; complete diff follows.\n"))
      (when (or diff-truncated
                (> (length diff-content)
                   package-upgrade-guard--max-unified-diff-size))
        (setq review-complete nil)
        (insert "Review aborted: VC diff exceeds the display limit.\n"))
      (package-upgrade-guard--insert-vc-diff-content
       diff-content diff-truncated)
      (insert "\n")))
    (when-let ((reasons (plist-get review :reasons)))
      (insert "Manual approval required:\n")
      (dolist (reason reasons)
        (insert (format "  - %s\n" reason))))
    (when (and fetch-succeeded review-complete working-tree-clean
               reviewed-commit
               (package-upgrade-guard--review-no-changes-p review))
      (setq review-no-changes t))
    (list :complete review-complete :no-changes review-no-changes)))

(defun package-upgrade-guard--insert-vc-normal-diff
    (pkg-dir upstream fetch-succeeded review-complete)
  "Insert a normal VC diff and return its review state."
  (let* ((diff-result
          (package-upgrade-guard--git-output-limited
           pkg-dir package-upgrade-guard--max-unified-diff-size
           "diff" (format "HEAD..%s" upstream)))
         (diff-content (plist-get diff-result :output))
         (diff-truncated (plist-get diff-result :truncated))
         review-no-changes)
    (cond
     ((null diff-content)
      (setq review-complete nil)
      (insert "Error getting complete diff\n"))
     ((string-empty-p diff-content)
      (insert "No changes in diff\n")
      (when fetch-succeeded
        (setq review-no-changes t)))
     (t
      (when (or diff-truncated
                (> (length diff-content)
                   package-upgrade-guard--max-unified-diff-size))
        (setq review-complete nil)
        (insert "Review aborted: VC diff exceeds the display limit.\n"))
      (package-upgrade-guard--insert-vc-diff-content
       diff-content diff-truncated)
      (insert "\n")))
    (list :complete review-complete :no-changes review-no-changes)))

(defun package-upgrade-guard--insert-vc-diff-review
    (pkg-dir upstream fetch-succeeded working-tree-clean reviewed-commit
             review-complete)
  "Insert the configured VC diff and return its review state."
  (condition-case err
      (if (package-upgrade-guard--security-diff-only-p)
          (package-upgrade-guard--insert-vc-security-diff
           pkg-dir upstream fetch-succeeded working-tree-clean
           reviewed-commit review-complete)
        (package-upgrade-guard--insert-vc-normal-diff
         pkg-dir upstream fetch-succeeded review-complete))
    (error
     (insert (format "Error getting diff: %s\n" err))
     '(:complete nil :no-changes nil))))

(defun package-upgrade-guard--approve-vc-review
    (pkg-desc diff-buffer review-complete review-no-changes pinnable
              reviewed-commit)
  "Ask for and record approval of a completed VC review."
  (let* ((pkg-name (package-desc-name pkg-desc))
         (key (package-desc-full-name pkg-desc))
         (approved
          (cond
           ((not review-complete)
            (display-buffer diff-buffer)
            (package-upgrade-guard--ask-user-approval
             pkg-desc
             (if pinnable
                 (concat "upgrade VC package at the pinned reviewed commit "
                         "despite an incomplete review")
               (concat "perform an unpinned VC upgrade despite an incomplete "
                       "review; the installed commit may differ from the "
                       "displayed review"))))
           (review-no-changes
            (package-upgrade-guard--cleanup-diff-buffers)
            (message
             "Package review: no differences found for %s; proceeding"
             pkg-name)
            t)
           (t
            (display-buffer diff-buffer)
            (package-upgrade-guard--ask-user-approval
             pkg-desc "upgrade VC package")))))
    (when approved
      (if pinnable
          (progn
            (puthash key reviewed-commit
                     package-upgrade-guard--reviewed-vc-commits)
            (remhash key
                     package-upgrade-guard--approved-incomplete-vc-reviews))
        (puthash key t package-upgrade-guard--approved-incomplete-vc-reviews)
        (remhash key package-upgrade-guard--reviewed-vc-commits)))
    approved))

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
         (pkg-full-name (package-desc-full-name pkg-desc))
         (old-dir
          (package-upgrade-guard--find-installed-package-dir
           pkg-name))
         (review-dir
          (expand-file-name pkg-full-name
                            (package-upgrade-guard--get-temp-dir)))
         temp-dir
         empty-dir
         approved)
    (unwind-protect
        (progn
          (setq temp-dir
                (package-upgrade-guard--download-package-safely pkg-desc))
          (setq empty-dir
                (unless old-dir
                  (make-temp-file "package-upgrade-guard-empty-" t)))
          (let ((diff-buffer
                 (get-buffer-create "*Package Security Diff*"))
                (old-version
                 (package-upgrade-guard--get-version-from-dir old-dir))
                (new-version
                 (package-version-join (package-desc-version pkg-desc)))
                (comparison-dir (or old-dir empty-dir))
                (action (if old-dir "upgrade package" "install new package"))
                review)
            (with-current-buffer diff-buffer
              (when buffer-read-only
                (read-only-mode -1))
              (erase-buffer)
              (insert (format "Diff for package %s:\n" pkg-name))
              (insert
               (format "Old version: %s\n" (or old-version "unknown")))
              (insert (format "New version: %s\n\n" new-version))

              ;; Generate diff
              (setq review
                    (package-upgrade-guard--generate-diff
                     comparison-dir temp-dir))

              (diff-mode)
              (package-upgrade-guard--highlight-security-patterns)
              (read-only-mode 1)
              (goto-char (point-min)))

            (setq approved
                  (cond
                   ((package-upgrade-guard--review-no-changes-p review)
                    (package-upgrade-guard--cleanup-diff-buffers)
                    (message
                     "Package review: no differences found for %s; proceeding"
                     pkg-name)
                    t)
                   ((not (plist-get review :complete))
                    (display-buffer diff-buffer)
                    (package-upgrade-guard--ask-user-approval
                     pkg-desc
                     (format "%s despite an incomplete review" action)))
                   (t
                    (display-buffer diff-buffer)
                    (package-upgrade-guard--ask-user-approval
                     pkg-desc action))))
            approved))
      (when empty-dir
        (delete-directory empty-dir t))
      (when (file-exists-p review-dir)
        (delete-directory review-dir t))
      (unless approved
        (remhash pkg-full-name
                 package-upgrade-guard--reviewed-artifact-digests)))))

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
          (review-complete t)
          (working-tree-clean nil)
          (review-no-changes nil)
          (reviewed-commit nil))
      (with-current-buffer diff-buffer
        (when buffer-read-only
          (read-only-mode -1))
        (erase-buffer)
        (insert (format "Git diff for VC package %s:\n" pkg-name))
        (insert (format "Repository: %s\n\n" pkg-dir))

        ;; Show current status
        (insert "=== Git Status ===\n")
        (let ((status
               (package-upgrade-guard--git-tracked-status pkg-dir)))
          (setq working-tree-clean
                (and status (string-empty-p status)))
          (unless working-tree-clean
            (setq review-complete nil)
            (insert "Working tree is not clean; review cannot continue safely.\n")))
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
              (setq fetch-succeeded nil
                    review-complete nil))
          (error
           (setq fetch-succeeded nil
                 review-complete nil)
           (insert (format "Error fetching: %s\n" err))))

        (let ((upstream
               (package-upgrade-guard--git-upstream pkg-dir)))
          (if (not upstream)
              (progn
                (setq review-complete nil)
                (insert
                 "\nNo upstream branch found; cannot compute incoming diff.\n"))
            (setq reviewed-commit
                  (package-upgrade-guard--git-output
                   pkg-dir "rev-parse" upstream))
            (unless (and reviewed-commit
                         (not (string-empty-p reviewed-commit)))
              (setq review-complete nil)
              (insert "Unable to resolve the reviewed upstream commit.\n"))
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
              (insert
               "Diff mode: complete available diff with sensitive-pattern highlighting\n"))
            (let ((review
                   (package-upgrade-guard--insert-vc-diff-review
                    pkg-dir upstream fetch-succeeded working-tree-clean
                    reviewed-commit review-complete)))
              (setq review-complete (plist-get review :complete)
                    review-no-changes (plist-get review :no-changes)))))

        (diff-mode)
        (package-upgrade-guard--highlight-security-patterns)
        (read-only-mode 1)
        (font-lock-ensure)
        (goto-char (point-min)))

      (package-upgrade-guard--approve-vc-review
       pkg-desc diff-buffer review-complete review-no-changes
       (and fetch-succeeded working-tree-clean reviewed-commit)
       reviewed-commit))))

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
