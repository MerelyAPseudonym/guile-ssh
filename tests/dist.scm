;;; dist.scm -- Testing of the distributed forms

;; Copyright (C) 2015, 2016, 2017 Artyom V. Poptsov <poptsov.artyom@gmail.com>
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

(add-to-load-path (getenv "abs_top_srcdir"))

(use-modules (srfi srfi-64)
             (ice-9 receive)
             (ice-9 rdelim)
             (ssh  session)
             (ssh  key)
             (ssh  auth)
             (ssh  message)
             (ssh  server)
             (ssh  log)
             (ssh  dist)
             (ssh  dist job)
             (ssh  dist node)
             (tests common))

(test-begin-with-log "dist")

;;;


(test-assert "make-node"
  (let* ((s (make-session-for-test))
         (n (make-node s)))
    (and n
         (eq? (node-repl-port n) 37146)
         (eq? (node-session n)   s))))


(test-equal "split, 1"
  '((a b) (c d) (e f g))
  (split '(a b c d e f g) 3))

(test-equal "split, 2"
  '((a))
  (split '(a) 2))


(test-assert "make-job"
  (let* ((s (make-session-for-test))
         (n (make-node s))
         (data '(1 2 3))
         (proc '(lambda (n) (1+ n)))
         (j (make-job 'map n data proc)))
    (and (eq? (job-type j) 'map)
         (eq? (job-node j) n)
         (eq? (job-data j) data)
         (eq? (job-proc j) proc))))

(test-assert "set-job-node"
  (let* ((s    (make-session-for-test))
         (n1   (make-node s))
         (n2   (make-node s))
         (data '())
         (proc '(lambda (n) (1+ n)))
         (j1   (make-job 'map n1 data proc))
         (j2   (set-job-node j1 n2)))
    (and (not (eq? j1 j2))
         (eq? (job-type j1) (job-type j2))
         (eq? (job-node j1) n1)
         (eq? (job-node j2) n2)
         (eq? (job-data j1) (job-data j2))
         (eq? (job-proc j1) (job-proc j2)))))

(test-error-with-log "hand-out-job, invalid type"
  (let ((n (make-node (make-session-for-test))))
    (hand-out-job (make-job 'invalid-job n '() (const #t)))))


(test-assert "assign-eval"
  (let* ((s     (make-session-for-test))
         (nodes (make-list 2 (make-node s)))
         (exprs (make-list 10 '(lambda (x) (1+ x))))
         (jobs  (assign-eval nodes exprs)))
    (and (eq? (length jobs) 2)
         (eq? (job-type (car jobs)) 'eval)
         (eq? (length (job-proc (car jobs))) 5))))


;;; Testing of 'rrepl-get-result'.
;; These test cases are intended to test various inputs for 'rrepl-get-result'
;; procedure.

(test-assert "rrepl-get-result"
  (receive (result eval-num module-name lang)
      (call-with-input-string "scheme@(guile-user)> $0 = test"
                              rrepl-get-result)
    ;; (format (current-error-port)
    ;;         "\tresult: ~a\neval-num: ~a"
    (and (eq?      result      'test)
         (=        eval-num    0)
         (string=? module-name "(guile-user)")
         (string=? lang        "scheme"))))

(test-assert "rrepl-get-result, unspecified"
  (receive (result eval-num module-name lang)
      (call-with-input-string "scheme@(guile-user)> "
                              rrepl-get-result)
    (and (eq?      result      *unspecified*)
         (eq?      eval-num    *unspecified*)
         (string=? module-name "(guile-user)")
         (string=? lang        "scheme"))))

(test-error-with-log/= "rrepl-get-result, error"
  'node-repl-error "scheme@(guile-user)> ERROR: error."
  (call-with-input-string "scheme@(guile-user)> ERROR: error."
                          rrepl-get-result))

;; See <https://github.com/artyom-poptsov/guile-ssh/issues/3>.
(test-error-with-log/= "rrepl-get-result, compilation error"
  'node-repl-error "scheme@(guile-user)> While compiling expression:\nERROR: no code for module (module-that-doesnt-exist)"
  (call-with-input-string
   (string-append "scheme@(guile-user)> While compiling expression:\n"
                  "ERROR: no code for module (module-that-doesnt-exist)")
   rrepl-get-result))

(test-error-with-log/= "rrepl-get-result, unbound variable error"
  'node-repl-error "scheme@(guile-user)> ;;; socket:9:7: warning: \
possibly unbound variable `e'\nsocket:9:7: In procedure #<procedure \
1a44920 at socket:9:7 ()>:\nsocket:9:7: In procedure module-lookup: \
Unbound variable: e"
  (call-with-input-string
   (string-append (string-append
                   "scheme@(guile-user)> ;;; socket:9:7: warning: "
                   "possibly unbound variable `e'\nsocket:9:7: "
                   "In procedure #<procedure 1a44920 at socket:9:7 ()>:\n"
                   "socket:9:7: In procedure module-lookup: Unbound variable: e"))
   rrepl-get-result))

(test-error-with-log/= "rrepl-get-result, unknown # object error"
  'node-repl-error "Reader error: scm_lreadr: #<unknown port>:1:3: \
Unknown # object: (#\\<): scheme@(guile-user)> \
$4 = #<session #<undefined>@#<undefined>:22 (disconnected) 453fff>"
  (call-with-input-string
   (string-append  "scheme@(guile-user)> $4 = "
                   "#<session #<undefined>@#<undefined>:22 (disconnected) 453fff>")
   rrepl-get-result))

(test-assert "rrepl-get-result, elisp"
  (receive (result eval-num module-name lang)
      (call-with-input-string "elisp@(guile-user)> $0 = #nil"
                              rrepl-get-result)
    (and (eq?      result      '#nil)
         (=        eval-num    0)
         (string=? module-name "(guile-user)")
         (string=? lang        "elisp"))))

(test-assert "rrepl-get-result, multiple values"
  (receive (result eval-num module-name lang)
      (call-with-input-string "scheme@(guile-user)> $0 = v1\n$1 = v2"
                              rrepl-get-result)
    (and (vector? eval-num)
         (vector? result)
         (eq?      (vector-ref result 0)   'v1)
         (eq?      (vector-ref result 1)   'v2)
         (=        (vector-ref eval-num 0) 0)
         (=        (vector-ref eval-num 1) 1)
         (string=? module-name "(guile-user)")
         (string=? lang        "scheme"))))


(test-assert "rrepl-skip-to-prompt, valid input"
  (begin
    (call-with-input-string "Enter `,help' for help."
      (lambda (port)
        (rrepl-skip-to-prompt port)))
    #t))

(test-error-with-log "rrepl-skip-to-prompt, invalid input" 'node-error
  (call-with-input-string "invalid input"
                          (lambda (port)
                            (rrepl-skip-to-prompt port))))

(test-assert-with-log "node-guile-version, valid response"
  (run-client-test
   ;; Server
   start-server/exec
   ;; Client
   (lambda ()
     (call-with-connected-session
      (lambda (session)
        (authenticate-server session)
        (format-log/scm 'nolog "client" "session: ~a" session)
        (unless (equal? (userauth-none! session) 'success)
          (error "Could not authenticate with a server" session))

        (let ((n (make-node session #:start-repl-server? #f)))
          (string=? (node-guile-version n)
                    "guile (GNU Guile) 2.0.14")))))))


;;; Distributed forms.

;; The client uses distributed form 'with-ssh' to evaluate (+ 21 21).  The
;; server pretends to be a RREPL server and returns the evaluation "result",
;; 42.
(test-assert-with-log "with-ssh"
  (run-client-test
   ;; Server
   (lambda (server)
     (server-listen server)
     (server-set! server 'log-verbosity 'functions)
     (let ((session (server-accept server)))
       (server-handle-key-exchange session)
       (start-session-loop
        session
        (lambda (msg type)
          (format-log/scm 'nolog
                          "server"
                          "msg: ~a; type: ~a" msg type)
          (case (car type)
            ((request-channel-open)
             (let ((c (message-channel-request-open-reply-accept msg)))
               (format-log/scm 'nolog "server" "channel 0: ~a" c)
               ;; Write the last line of Guile REPL greeting message to
               ;; pretend that we're a REPL server.
               (write-line "Enter `,help' for help." c)
               (format-log/scm 'nolog "server" "channel 1: ~a" c)
               (usleep 100)
               (poll c
                     (lambda args
                       ;; Read expression
                       (let ((result (read-line c)))
                         (format-log/scm 'nolog "server"
                                         "sexp: ~a" result)
                         (or (string=? result "(begin (+ 21 21))")
                             (error "Wrong result 1" result)))

                       ;; Read newline
                       (let ((result (read-line c)))
                         (format-log/scm 'nolog "server"
                                         "sexp: ~a" result)
                         (or (string=? result "(newline)")
                             (error "Wrong result 2" result)))

                       (write-line "scheme@(guile-user)> $1 = 42\n" c)
                       (sleep 5)
                       (close c)
                       (while #t
                         (sleep 60))))))
            (else
             (message-reply-success msg)))))))
   ;; Client
   (lambda ()
     (call-with-connected-session
      (lambda (session)
        (authenticate-server session)
        (format-log/scm 'nolog "client" "session: ~a" session)
        (unless (equal? (userauth-none! session) 'success)
          (error "Could not authenticate with a server" session))

        (let ((n (make-node session #:start-repl-server? #f)))
          (= (with-ssh n
                       (+ 21 21))
             42)))))))

;;;


(test-end "dist")

(exit (= (test-runner-fail-count (test-runner-current)) 0))

;;; dist.scm ends here.
