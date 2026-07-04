;;; package-upgrade-guard-tar.el --- TAR extraction logic for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 kn66

;; Author: Package Security Check
;; Keywords: tools, convenience

;;; Commentary:

;; This file contains TAR file extraction logic for package-upgrade-guard.

;;; Code:

(require 'package)
(require 'url)
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

(defun package-upgrade-guard--remote-content-length (location file)
  "Return the remote Content-Length for FILE at LOCATION, or nil if unknown."
  (when (and (stringp location)
             (string-match-p "\\`https?://" location))
    (let ((url-request-method "HEAD")
          (url (concat (file-name-as-directory location) file))
          buffer)
      (condition-case nil
          (progn
            (setq buffer (url-retrieve-synchronously url t t 10))
            (when buffer
              (unwind-protect
                  (with-current-buffer buffer
                    (goto-char (point-min))
                    (let ((case-fold-search t))
                      (when (re-search-forward
                             "^content-length:[ \t]*\\([0-9]+\\)" nil t)
                        (string-to-number (match-string 1)))))
                (when (and buffer (buffer-live-p buffer))
                  (kill-buffer buffer)))))
        (error
         (when (and buffer (buffer-live-p buffer))
           (kill-buffer buffer))
         nil)))))

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

    (let ((content-length
           (package-upgrade-guard--remote-content-length location file)))
      (when (and content-length
                 (> content-length package-upgrade-guard-max-download-size))
        (error "Package artifact exceeds review size limit: %s (%d bytes)"
               pkg-full-name
               content-length)))

    ;; Clean up any existing temp directory
    (when (file-exists-p temp-pkg-dir)
      (delete-directory temp-pkg-dir t))

    ;; Download package.
    (package--with-response-buffer
      location
      :file file
      (when (> (buffer-size) package-upgrade-guard-max-download-size)
        (error "Package artifact exceeds review size limit: %s (%d bytes)"
               pkg-full-name
               (buffer-size)))
      (puthash pkg-full-name
               (secure-hash 'sha256 (current-buffer))
               package-upgrade-guard--reviewed-artifact-digests)
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
