;;; package-upgrade-guard-utils.el --- Utility functions for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains utility functions for package-upgrade-guard.

;;; Code:

(require 'package)
(require 'subr-x)
(require 'package-upgrade-guard-constants)

;; Temporary directory management
(defun package-upgrade-guard--get-temp-dir ()
  "Return the temporary directory for security review."
  (unless package-upgrade-guard--temp-dir
    (setq package-upgrade-guard--temp-dir
          (or package-upgrade-guard-temp-dir
              (expand-file-name "package-upgrade-guard"
                                temporary-file-directory))))
  (condition-case err
      (progn
        (unless (file-exists-p package-upgrade-guard--temp-dir)
          (make-directory package-upgrade-guard--temp-dir t))
        package-upgrade-guard--temp-dir)
    (error
     (error
      "Failed to create temporary directory %s: %s"
      package-upgrade-guard--temp-dir
      (error-message-string err)))))

(defun package-upgrade-guard--cleanup-temp-dir ()
  "Clean up temporary directory."
  (when (and package-upgrade-guard--temp-dir
             (file-exists-p package-upgrade-guard--temp-dir))
    (condition-case err
        (delete-directory package-upgrade-guard--temp-dir t)
      (error
       (message "Warning: Failed to cleanup temp directory %s: %s"
                package-upgrade-guard--temp-dir
                (error-message-string err))))))

;; File handling utilities
(defun package-upgrade-guard--safe-read-file
    (file-path &optional max-size)
  "Read FILE-PATH with optional MAX-SIZE.
Return the file content, or an error message string."
  (condition-case err
      (with-temp-buffer
        (if max-size
            (insert-file-contents file-path nil nil max-size)
          (insert-file-contents file-path))
        (buffer-string))
    (error
     (format "[Error reading file: %s]" (error-message-string err)))))

;; Package directory utilities
(defun package-upgrade-guard--coerce-package-name (pkg-name)
  "Return PKG-NAME as a package symbol."
  (if (symbolp pkg-name)
      pkg-name
    (intern pkg-name)))

(defun package-upgrade-guard--package-desc (pkg-name source)
  "Return package descriptor for PKG-NAME from SOURCE.
SOURCE should be `installed' or `archive'."
  (let ((package-name
         (package-upgrade-guard--coerce-package-name pkg-name)))
    (or (when (fboundp 'package-get-descriptor)
          (let ((get-descriptor
                 (symbol-function 'package-get-descriptor)))
            (ignore-errors
              (funcall get-descriptor package-name source))))
        (pcase source
          ('installed
           (cadr (assq package-name package-alist)))
          ('archive
           (cadr (assq package-name package-archive-contents)))))))

(defun package-upgrade-guard--find-installed-package-dir (pkg-name)
  "Find installed third-party package directory for PKG-NAME."
  (let* ((package-name
          (package-upgrade-guard--coerce-package-name pkg-name))
         (pkg-desc
          (package-upgrade-guard--package-desc package-name 'installed))
         (pkg-dir
          (and pkg-desc (package-desc-dir pkg-desc)))
         (pkg-name-str (symbol-name package-name))
         (elpa-dirs (list package-user-dir)))

    (or (and (stringp pkg-dir)
             (file-directory-p pkg-dir)
             pkg-dir)
        (progn
          ;; Add system package directories if they exist.
          (when (boundp 'package-directory-list)
            (setq elpa-dirs (append elpa-dirs package-directory-list)))

          ;; Search for installed ELPA packages as a compatibility fallback.
          (catch 'found
            (dolist (elpa-dir elpa-dirs)
              (when (and elpa-dir (file-directory-p elpa-dir))
                (dolist (dir (directory-files elpa-dir t))
                  (when (and
                         (file-directory-p dir)
                         (not
                          (member (file-name-nondirectory dir) '("." "..")))
                         ;; Match package name at start of directory name.
                         (string-match
                          (concat
                           "^"
                           (regexp-quote pkg-name-str) "-[0-9]")
                          (file-name-nondirectory dir)))
                    (throw 'found dir))))))))))

(defun package-upgrade-guard--get-version-from-dir (pkg-dir)
  "Extract version from package directory name PKG-DIR."
  (when pkg-dir
    (let ((dir-name (file-name-nondirectory
                     (directory-file-name pkg-dir))))
      (when (string-match
             "-\\([0-9][^-]*\\)\\(?:-[0-9]+\\)?$" dir-name)
        (match-string 1 dir-name)))))

;; Buffer management utilities
(defun package-upgrade-guard--cleanup-diff-buffers ()
  "Clean up all package security check related buffers."
  (dolist (buffer-name package-upgrade-guard--buffer-names)
    (when-let ((buffer (get-buffer buffer-name)))
      (kill-buffer buffer))))

(provide 'package-upgrade-guard-utils)

;;; package-upgrade-guard-utils.el ends here
