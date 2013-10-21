#!/usr/bin/python
# This file is part of the Project Athena Zephyr Notification System.
# Simple/sexp zephyr client a la tzc.
#
#	Created by:	Karl Ramm
#
#	$Id$
#
#	Copyright (c) 2013 by the Massachusetts Institute of
#	Technology. For copying and distribution information, see the
#	file "mit-copyright.h".
#

import sys
import os
import time
import logging
import optparse
import select
import socket

import zephyr

def main():
    parser = optparse.OptionParser()
    parser.add_option(
        '-v','--verbose', action='count', default = 0, dest='verbose',
        help='increase verbosity')
    options, args = parser.parse_args()

    logLevel = max(logging.WARNING - options.verbose*10, logging.DEBUG)
    logFormat = ';;; %(asctime)s %(message)s'
    logging.basicConfig(level=logLevel, format=logFormat)
    log = logging.getLogger('szc')

    z = zephyr.Zephyr()
    delisp = delisper().input

    print '; SZC $Id$'
    log.debug('starting')
    output(
        ('tzcspew', 'start'),
        ('version', quoted('0')),
        ('pid', str(os.getpid())),
        ('zephyrid', quoted(z.sender)),
        ('exposure', quoted('NONE')), #XXX
        ('heartbeat', 'nil'),
        ('time', quoted(time.ctime())),
        ('features', llista()),
        )

    z.subscribe([]) # defaults for now

    try:
        while True:
            while z.pending:
                notice = z.receive_notice()
                now = time.time()
                log.debug('Z: %s', repr(notice))
                log.debug(
                    'now %s .time %s sec %d usec %d',
                    now,
                    notice.time,
                    notice.ZNotice.z_time.tv_sec,
                    notice.ZNotice.z_time.tv_usec)
                recipient = trim(notice.recipient, '@' + z.realm)
                sender = trim(notice.sender, '@' + z.realm)
                try:
                    hostname = socket.getnameinfo(
                        (notice.origin, 0),
                        socket.AI_CANONNAME)[0]
                except socket.gaierror:
                    hostname = notice.origin
                output(
                    ('tzcspew', 'message'),
#                   ('kind', notice.kind.lower()),#XXX
                    ('kind', 'acked'),
                    ('port', str(notice.port)),
                    ('class', symbol(notice.class_)),
                    ('instance', quoted(notice.instance)),
                    ('opcode', symbol(notice.opcode)),
                    ('sender', quoted(sender)),
                    ('recipient', quoted(recipient)),
                    ('auth', {
                        -1: 'failed',
                        0: 'no',
                        1: 'yes'}.get(notice.checked_auth, 'unknown')),
                    ('fromhost', quoted(hostname)),
                    ('time', quoted(time.ctime(notice.time))),
                    ('time-secs', llista(
                        str(int(now) >> 16),
                        str(int(now) & 0xffff),
                        str(int((now - int(now)) * 1000000)))),
                    ('latency', quoted('%.2f' % (now - notice.time))),
                    ('message', llist([quoted(s) for s in notice.message.split('\0')])),
                    )
            sys.stdout.flush()
            r, w, e = select.select([0, z], [], [])
            log.debug('input in %s', r)
            if 0 in r:
                buf = os.read(0, 4096)
                if buf == '':
                    break
                for sexp in delisp(buf):
                    log.debug('U: %s', repr(sexp))
                    if not hasattr(sexp, 'append'):
                        continue
                    if sexp[0] == ['tzcfodder', 'subscribe']:
                        z.subscribe(sexp[1:], False)
                        output(('tzcspew', 'subscribed'))
                    elif sexp[0] == ['tzcfodder', 'send']:
                        log.debug('starting send')
                        notice = zephyr.Notice()
                        authflag = False
                        recipients = []
                        for l in sexp[1:]:
                            if l[0] == 'auth':
                                if l[1] == 't':
                                    authflag = True
                            elif l[0] == 'class':
                                notice.class_ = l[1]
                            elif l[0] == 'recipients':
                                recipients = l[1:]
                            elif l[0] == 'message':
                                notice.message = '\0'.join(l[1:])
                        notice.default_format = 'http://zephyr.1ts.org/wiki/df'
                        for (instance, recipient) in recipients:
                            try:
                                notice.instance = instance
                                notice.recipient = recipient
                                z.send_notice(notice, authflag)
                                # this is not quite outputing it right
                                # but the lisp reader don't care
                                output(
                                    ('tzcspew', 'sent'),
                                    ('to', pair(quoted(instance),
                                                quoted(recipient))))
                            except zephyr.ZephyrError as e:
                                log.exception('sending notice')
                                output(
                                    ('tzcspew', 'not-sent'),
                                    ('to', pair(quoted(instance),
                                                quoted(recipient))))
                                continue
    except KeyboardInterrupt:
        pass

    print '; ALL DONE BYE BYE'

def quotec(c):
    if ord(c) == 1:
        return '\\1'
    elif c == '"' or c == "'":
        return '\\' + c
    return c
def quoted(s):
    return '"' + ''.join(quotec(c) for c in s) + '"'

def symbolc(c):
    if c in (
        '!$%&*+-/0123456789:<=>@ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        '^_abcdefghijklmnopqrstuvwxyz{}~'
        ):
        return c
    return '\\' + c

def symbol(s):
    if s == '':
        return 'nil'
    pre = ''
    if s[0] in '+-0123456789':
        pre = '\\'
    return pre + ''.join(symbolc(c) for c in s)

def pair(a, b):
    return '(' + a + ' . ' + b + ')'

def llist(l):
    return '(' + ' '.join(l) + ')'

def llista(*args):
    return llist(args)

def output(*args):
    print chr(1) + llist(pair(symbol(a), b) for (a, b) in args) + chr(0)

class delisper(object):
    # XXX symbol?
    source = {
        'start': {
            '\t\n ': ((), 'start'),
            '(': (('PUSH',), 'start'),
            ')': (('POP',), 'start'),
            '"': ((), 'string'),
            '\\': ((), 'symbol-backslash'),
            '1234567890': (('APPEND',), 'integer'),
            '.': (('APPEND',), 'dot'),
            None: (('APPEND',), 'symbol'),
            },
        'symbol': {
            '\t\n ': ((symbol,), 'start'),
            '\\': ((), 'symbol-backslash'),
            '"': ((symbol,), 'string'),
            '(': ((symbol, 'PUSH'), 'start'),
            ')': ((symbol, 'POP'), 'start'),
            None: (('APPEND',), 'symbol'),
            },
        'symbol-backlash': {
            None: (('APPEND',), 'symbol'),
            },
        'string': {
            '\\': ((), 'string-backslash'),
            '"': ((str,), 'start'),
            None: (('APPEND',), 'string'),
            },
        'string-backslash': {
            None: (('APPEND',), 'string'),
            },
        'dot': { # drop a dot by itself
            '1234567890': (('APPEND',), 'float'),
            '\t\n ': (('CLEAR',), 'start'),
            '(': (('CLEAR', 'PUSH'), 'start'),
            ')': (('CLEAR', 'POP'), 'start'),
            None: (('APPEND',), 'symbol'),
            },
        'integer': {
            '1234567890': (('APPEND',), 'integer'),
            '.': (('APPEND',), 'float'),
            '\\': ((), 'symbol-backslash'),
            '\t\n ': ((int,), 'start'),
            '(': ((int, 'PUSH'), 'start'),
            ')': ((int, 'POP'), 'start'),
            None: (('APPEND',), 'symbol'),
            },
        'float': {
            '1234567890': (('APPEND',), 'float'),
            '\\': ((), 'symbol-backslash'),
            '\t\n ': ((float,), 'start'),
            '(': ((float, 'PUSH'), 'start'),
            ')': ((float, 'POP'), 'start'),
            None: (('APPEND',), 'symbol'),
            },
        }

    def __init__(self):
        # munch the machine
        self.machine = {}
        for state in self.source:
            self.machine[state] = {}
            for inputset in self.source[state]:
                if inputset is None:
                    self.machine[state][None] = self.source[state][None]
                    continue
                for c in inputset:
                    self.machine[state][c] = self.source[state][inputset]
        self.stack = []
        self.word = ''
        self.state = 'start'
    def char(self, c):
        retval = None
        state = self.machine[self.state]
        todo, self.state = state.get(c, state[None])
        for action in todo:
            if callable(action):
                retval = action(self.word)
                self.word = ''
            elif action == 'APPEND':
                self.word += c
            elif action == 'PUSH':
                self.stack.append([])
            elif action == 'CLEAR':
                self.word = ''
            elif action == 'POP':
                if self.stack:
                    retval = self.stack[-1]
                    del self.stack[-1]
            if retval is not None and self.stack:
                self.stack[-1].append(retval)
                retval = None
        return retval
    def input(self, s):
        results = []
        for c in s:
            result = self.char(c)
            if result is not None:
                results.append(result)
        return results

def trim(s, postfix):
    length = len(postfix)
    if s[-length:] == postfix:
        return s[:-length]
    else:
        return s
if __name__ == '__main__':
    try:
        main()
    except Exception:
        logging.exception('at top level')
