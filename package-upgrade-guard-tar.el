;;; package-upgrade-guard-tar.el --- TAR extraction logic for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 kn66

;; Author: Package Security Check
;; Keywords: tools, convenience

;;; Commentary:

;; This file contains TAR file extraction logic for package-upgrade-guard.

;;; Code:

(require 'package)
(require 'url)
(require 'url-http)
(require 'package-upgrade-guard-utils)

(declare-function package-untar-buffer "package" (dir))

(defconst package-upgrade-guard--max-http-header-size (* 64 1024)
  "Maximum HTTP header bytes tolerated while enforcing a download limit.")

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

(defun package-upgrade-guard--http-body-start ()
  "Return the current HTTP response body start position, or nil."
  (when (bound-and-true-p url-http-end-of-headers)
    (if (markerp url-http-end-of-headers)
        (marker-position url-http-end-of-headers)
      url-http-end-of-headers)))

(defun package-upgrade-guard--retrieve-url-limited (url max-size)
  "Retrieve URL and return a body-only buffer no larger than MAX-SIZE bytes.
Abort the network process when the response body exceeds MAX-SIZE or the
configured download timeout expires."
  (unless (and (numberp package-upgrade-guard-download-timeout)
               (> package-upgrade-guard-download-timeout 0))
    (error "Package download timeout must be a positive number"))
  (let ((deadline
         (+ (float-time) package-upgrade-guard-download-timeout))
        buffer done retrieval-status)
    (setq buffer
          (url-retrieve
           url
           (lambda (status)
             (setq retrieval-status status
                   done t))
           nil t t))
    (unless buffer
      (error "Could not start package download: %s" url))
    (condition-case err
        (progn
          (while (not done)
            (when (>= (float-time) deadline)
              (when-let ((process (get-buffer-process buffer)))
                (when (process-live-p process)
                  (delete-process process)))
              (error "Package download timed out after %s seconds"
                     package-upgrade-guard-download-timeout))
            (unless (buffer-live-p buffer)
              (error "Package download buffer disappeared: %s" url))
            (with-current-buffer buffer
              (let* ((body-start (package-upgrade-guard--http-body-start))
                     (received
                      (if body-start
                          (- (point-max) body-start)
                        (buffer-size)))
                     (limit
                      (if body-start
                          max-size
                        (+ max-size
                           package-upgrade-guard--max-http-header-size))))
                (when (> received limit)
                  (when-let ((process (get-buffer-process buffer)))
                    (delete-process process))
                  (error "Package artifact exceeds review size limit (%d bytes)"
                         max-size))))
            (unless done
              (let ((process (get-buffer-process buffer)))
                (unless (and process (process-live-p process))
                  (error "Package download ended before completion: %s" url))
                (accept-process-output process 0.1))))
          (with-current-buffer buffer
            (when-let ((url-error (plist-get retrieval-status :error)))
              (error "Package download failed: %S" url-error))
            (when (and (boundp 'url-http-response-status)
                       (integerp url-http-response-status)
                       (>= url-http-response-status 400))
              (error "Package download returned HTTP status %d"
                     url-http-response-status))
            (let ((body-start (package-upgrade-guard--http-body-start)))
              (unless body-start
                (error "Package download returned no HTTP body"))
              (when (> (- (point-max) body-start) max-size)
                (error "Package artifact exceeds review size limit (%d bytes)"
                       max-size))
              (delete-region (point-min) body-start)
              (set-buffer-multibyte nil))
            buffer))
      (error
       (when (buffer-live-p buffer)
         (when-let ((process (get-buffer-process buffer)))
           (when (process-live-p process)
             (delete-process process)))
         (kill-buffer buffer))
       (signal (car err) (cdr err))))))

(defun package-upgrade-guard--process-package-response (pkg-desc temp-dir)
  "Record and unpack the package response in the current buffer."
  (let ((pkg-name (package-desc-name pkg-desc))
        (pkg-full-name (package-desc-full-name pkg-desc))
        (temp-pkg-dir
         (expand-file-name (package-desc-full-name pkg-desc) temp-dir)))
    (when (> (buffer-size) package-upgrade-guard-max-download-size)
      (error "Package artifact exceeds review size limit: %s (%d bytes)"
             pkg-full-name
             (buffer-size)))
    (puthash pkg-full-name
             (secure-hash 'sha256 (current-buffer))
             package-upgrade-guard--reviewed-artifact-digests)
    (pcase (package-desc-kind pkg-desc)
      ('tar
       (package-upgrade-guard--unpack-tar-response pkg-desc temp-dir))
      ('single
       (make-directory temp-pkg-dir t)
       (package-upgrade-guard--write-response-file
        (expand-file-name (format "%s.el" pkg-name) temp-pkg-dir))
       temp-pkg-dir)
      (_
       (error "Unsupported package format: %s"
              (package-desc-suffix pkg-desc))))))

(defun package-upgrade-guard--download-package-safely (pkg-desc)
  "Download package PKG-DESC to temporary directory without installing."
  (let* ((temp-dir (package-upgrade-guard--get-temp-dir))
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

    ;; Download package.  HTTP responses are monitored while data arrives so
    ;; the configured limit is a resource bound, not just a post-download check.
    (if (and (stringp location)
             (string-match-p "\\`https?://" location))
        (let ((buffer
               (package-upgrade-guard--retrieve-url-limited
                (url-expand-file-name file location)
                package-upgrade-guard-max-download-size)))
          (unwind-protect
              (with-current-buffer buffer
                (package-upgrade-guard--process-package-response
                 pkg-desc temp-dir))
            (when (buffer-live-p buffer)
              (kill-buffer buffer))))
      (package--with-response-buffer
        location
        :file file
        (package-upgrade-guard--process-package-response
         pkg-desc temp-dir)))))

(provide 'package-upgrade-guard-tar)

;;; package-upgrade-guard-tar.el ends here
