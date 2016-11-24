;;; key.scm -- SSH keys management.

;; Copyright (C) 2013, 2014 Artyom V. Poptsov <poptsov.artyom@gmail.com>
;;
;; This file is a part of Guile-SSH.
;;
;; Guile-SSH is free software: you can redistribute it and/or
;; modify it under the terms of the GNU General Public License as
;; published by the Free Software Foundation, either version 3 of the
;; License, or (at your option) any later version.
;;
;; Guile-SSH is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with Guile-SSH.  If not, see <http://www.gnu.org/licenses/>.


;;; Commentary:

;; This module contains API that is used for SSH key management.
;;
;; These methods are exported:
;;
;;   key?
;;   public-key?
;;   private-key?
;;   make-keypair
;;   key-type
;;   public-key->string
;;   string->pubilc-key
;;   public-key-from-file
;;   private-key->public-key
;;   private-key-from-file
;;   private-key-to-file
;;   public-key-hash
;;   bytevector->hex-string


;;; Code:

(define-module (ssh key)
  #:use-module (ice-9 format)
  #:use-module (rnrs bytevectors)
  #:use-module (ssh log)
  #:export (key
            key?
            public-key?
            private-key?
            make-keypair
            key-type
            get-key-type                ; deprecated
            public-key->string
            string->public-key
            public-key-from-file
            private-key->public-key
            private-key-from-file
            private-key-to-file
            public-key-hash
            get-public-key-hash         ; deprecated
            bytevector->hex-string))

(define (bytevector->hex-string bv)
  "Convert bytevector BV to a colon separated hex string."
  (string-join (map (lambda (e) (format #f "~2,'0x" e))
                    (bytevector->u8-list bv))
               ":"))


(define (key-type key)
  "Get a symbol that represents the type of the SSH key KEY.
Possible types are: 'dss, 'rsa, 'rsa1, 'ecdsa, 'unknown"
  (%gssh-key-type key))

(define (get-key-type key)
  (issue-deprecation-warning "'get-key-type' is deprecated.  "
                             "Use 'key-type' instead.'")
  (%gssh-key-type key))


(define (public-key-hash key type)
  "Get hash of the public KEY as a bytevector.  Possible types are: 'sha1,
'md5.  Return a bytevector on success, #f on error."
  (%gssh-public-key-hash key type))

(define (get-public-key-hash key type)
  (issue-deprecation-warning "'get-public-key-hash' is deprecated.  "
                             "Use 'public-key-hash' instead.'")
  (%gssh-public-key-hash key type))


(load-extension "libguile-ssh" "init_key")

;;; key.scm ends here.
