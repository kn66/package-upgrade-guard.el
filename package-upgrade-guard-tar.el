;;; package-upgrade-guard-tar.el --- TAR extraction logic for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains TAR file extraction logic for package-upgrade-guard.

;;; Code:

(require 'package)
(require 'package-upgrade-guard-utils)

(declare-function package-untar-buffer "package" (dir))

(defun package-upgrade-guard--write-response-file (file)
  "Write the current response buffer to FILE without coding conversion."
  (let ((coding-system-for-write 'no-conversion)
        (write-region-inhibit-fsync t))
    (write-region (point-min) (point-max) file nil 'silent)))

(defun package-upgrade-guard--unpack-tar-response (pkg-desc temp-dir)
  "Unpack current tar response for PKG-DESC into TEMP-DIR."
  (let* ((pkg-full-name (package-desc-full-name pkg-desc))
         (default-directory (file-name-as-directory temp-dir)))
    (package-untar-buffer pkg-full-name)
    (expand-file-name pkg-full-name temp-dir)))

(defun package-upgrade-guard--download-package-safely (pkg-desc)
  "Download package PKG-DESC to temporary directory without installing."
  (let* ((temp-dir (package-upgrade-guard--get-temp-dir))
         (pkg-name (package-desc-name pkg-desc))
         (pkg-full-name (package-desc-full-name pkg-desc))
         (temp-pkg-dir (expand-file-name pkg-full-name temp-dir))
         (location (package-archive-base pkg-desc))
         (file
          (concat
           (package-desc-full-name pkg-desc)
           (package-desc-suffix pkg-desc))))

    ;; Clean up any existing temp directory
    (when (file-exists-p temp-pkg-dir)
      (delete-directory temp-pkg-dir t))

    ;; Download package.
    (package--with-response-buffer
      location
      :file file
      (pcase (package-desc-kind pkg-desc)
        ('tar
         (package-upgrade-guard--unpack-tar-response
          pkg-desc temp-dir))
        ('single
         (make-directory temp-pkg-dir t)
         (package-upgrade-guard--write-response-file
          (expand-file-name (format "%s.el" pkg-name) temp-pkg-dir))
         temp-pkg-dir)
        (_
         (error "Unsupported package format: %s" file))))))

(provide 'package-upgrade-guard-tar)

;;; package-upgrade-guard-tar.el ends here
