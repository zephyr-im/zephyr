; zwgc.el
;
; This file is part of the Project Athena Zephyr Notification System.
; Created by: Mark W. Eichin <eichin@athena.mit.edu>
; $Source$
; $Author$
; Copyright (c) 1988 by the Massachusetts Institute of Technology.
; For copying and distribution information, see the file
; "mit-copyright.h". 
;
; Emacs mode for running zwgc in a sub process of emacs. It pops up a
; window for every new message; if you make bells appear between each
; message, it will be able to seperate them. If you move the mouse
; into the message window and hit `delete' it will delete the current
; message; if there are other messages, it will show them, if not, it
; will make the window go away.
;
; Invoke with M-x zwgc.
; 
; Also included is M-x zsend, which prompts for a user name and a
; message to send to them. If the message is blank, a buffer is popped
; up to edit the message in. If a prefix argument is given, zsend
; prompts for an instance instead. If the user name is blank, the last
; one is reused.
; 
; The following should be added to your .zephyr.desc file if you want
; to take advantage of the zwgc message seperation features:
;	does $mode
;	match tty
;		beep
;	endmatch
;	enddoes
;
(defvar zwgc_el-RCS-id)
(setq zwgc_el-RCS-id "$Id$")
;
;

(defun narrow-to-string (str)
  "narrow and put up a string..."
  (interactive "sString: ")
  (narrow-to-region (point) (point))
  (insert str))

(defvar zwgc-prog "/usr/etc/zwgc" 
  "*Program to run as the zwgc process. Should set it for the machine type.")

(defun zwgc-wakeup (proc string)
  "Procedure called when zwgc spits something out"
  (let (start-limit)
    (save-excursion (set-buffer (get-buffer "*zwgc*"))
		    (setq start-limit (point))
		    (goto-char (point-max))
		    (if (= 7 (string-to-char string))
			(progn
			  (ding 1)
			  (message "got one!")
			  (narrow-to-string string))
		      (insert string))
		    (search-backward "\007" start-limit t)
		    (while (search-forward "\015" (point-max) t) ;flush ^M's
		      (delete-backward-char 1)))
    (Special-pop-up-window (get-buffer "*zwgc*"))
    ))

(defun zwgc ()
  "emacs mode for running zwgc in a sub process of emacs. It pops up a
window for every new message; if you make bells appear between each
message, it will be able to seperate them. If you move the mouse into
the message window and hit `delete' it will delete the current
message; if there are other messages, it will show them, if not, it
will make the window go away."
  (interactive)
  (require 'shell)
  (let ((buffer (get-buffer-create "*zwgc*")) proc status)
    (setq proc (get-buffer-process buffer))
    (if proc
	(setq status (process-status proc)))
    (save-excursion
      (set-buffer buffer)
      (if (memq status '(run stop))
	  nil
	(if proc (delete-process proc))
	(setq proc (start-process "Zwgc" buffer 
				  zwgc-prog "-disable" "X"
				  "-default" "plain" "-nofork"))
	(set-process-filter proc 'zwgc-wakeup))
      (shell-mode)
      (local-set-key "\177" 'zwgc-punt)
      )
    ))


(defun Special-pop-up-window (buffer &optional max-height)
  "Pop up a window that is just big enough to hold the current buffer."
  (interactive "bBuffer to pop: ")
  (let* ((retwin (selected-window))
	 (pop-up-windows t)
	 (window-min-height 1))
    (pop-to-buffer buffer)
    (setq lines (1+ (count-lines (point-min) (point-max))))
    (enlarge-window (- lines (window-height (selected-window))))
    (goto-char (point-min))
    (other-window 1)
    ))

(defun zwgc-punt ()
  "Delete the current ZephyrGram from the *zwgc* buffer."
  (interactive)
  (let ((window-min-height 1))
    (display-buffer (get-buffer "*zwgc*"))
    (delete-region (point-min) (point-max))
    (widen)
    (if (not (search-backward "\007" nil t))
	(delete-windows-on "*zwgc*")
      (narrow-to-region (point) (point-max))
      (enlarge-window (- (1+ (count-lines (point-min) (point-max)))
			 (window-height (selected-window))))
      (goto-char (point-min))
      )))
;;
;; [eichin:19880309.2005EST]
;; zsend.el
;; Send zephyrgrams from emacs...
;;

(defvar *who* "" "last user sent to with zsend")

(defun zsend (&optional who message)
  "zsend prompts for a user name and a message to send to them as a
ZephyrGram. If the message is blank, a buffer is popped up to edit the
message in. If a prefix argument is given, zsend prompts for an
instance instead. If the user name is blank, the last one is reused."
  (interactive
   (list (if current-prefix-arg		; is this portable???
	     (cons 'instance (read-input "Instance:"))
	   (cons 'who (read-input "Who:")))
;	 (select-window (minibuffer-window))
;	 (enlarge-window 4)
	 (read-input "Message:")))
  (save-excursion
    (let ((tempbuf (get-buffer-create " *zephyr*send*")))
      (switch-to-buffer tempbuf)
      (local-set-key "\C-c\C-c" 'exit-recursive-edit)
      (erase-buffer)
      (if (and (equal (cdr who) "")
	       (equal *who* ""))
	  (message "Please specify user at least once.")
	(if (not (equal (cdr who) ""))
	    (setq *who* who)		; save *who* for next time
	  (setq who *who*))		; or, use the old value
	(if (not (equal message ""))
	    (progn
	      (insert message)
	      (zwrite who))
	  (progn
	    (recursive-edit)
	    (zwrite who)))))))


(defun zwrite (who)
  "Send a ZephyrGram to user WHO, zsend is the user interface to this."
  (if (eq 'who (car who))
      (call-process-region (point-min) (point-max) ;range
			   "/usr/athena/zwrite" ;process
			   t		;delete-p
			   t		;output-p
			   nil		;redisplay-p
			   "-q"		;args -- ignore server responses.
			   (cdr who))
    (call-process-region (point-min) (point-max) ;range
			   "/usr/athena/zwrite" ;process
			   t		;delete-p
			   t		;output-p
			   nil		;redisplay-p
			   "-q"		;args -- ignore server responses.
			   "-i"		;[eichin:19880312.0015EST]
			   (cdr who)))
  (if (not (equal (point-max) 1))
      (message (buffer-substring 1 (1- (point-max))))))

; suggested binding (control-meta-z)
;(global-set-key "\M-\C-z" 'zsend)


