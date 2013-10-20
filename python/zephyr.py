#!/usr/bin/python
# This file is part of the Project Athena Zephyr Notification System.
# python interface for libzephyr
#
#	Created by:	Karl Ramm
#
#	$Id$
#
#	Copyright (c) 2013 by the Massachusetts Institute of
#	Technology. For copying and distribution information, see the
#	file "mit-copyright.h".
#
'''
Zephyr interface for python
'''

import errno
import cffi

_ffi = cffi.FFI()

_ffi.cdef('''
typedef enum {
    UNSAFE = 0, UNACKED = 1, ACKED = 2, HMACK = 3, HMCTL = 4, SERVACK = 5,
    SERVNAK = 6, CLIENTACK = 7, STAT = 8
} ZNotice_Kind_t;
extern char * ZNoticeKinds[9];
typedef unsigned int ZChecksum_t;
struct _ZTimeval {
	int tv_sec;
	int tv_usec;
};
typedef uint32_t in_addr_t;
struct in_addr
  {
    in_addr_t s_addr;
  };

struct in6_addr
  {
    union
      {
        uint8_t __u6_addr8[16];
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
      } __in6_u;
  };


typedef unsigned short int sa_family_t;
struct sockaddr
  {
    sa_family_t sa_family;    /* Common data: address family and length.  */
    char sa_data[14];           /* Address data.  */
  };
typedef uint16_t in_port_t;
struct sockaddr_in
  {
    sa_family_t sin_family;
    in_port_t sin_port;                 /* Port number.  */
    struct in_addr sin_addr;            /* Internet address.  */

    /* Pad to size of struct sockaddr.  */
    unsigned char sin_zero[8];
  };

/* Ditto, for IPv6.  */
struct sockaddr_in6
  {
    sa_family_t sin6_family;
    in_port_t sin6_port;        /* Transport layer port # */
    uint32_t sin6_flowinfo;     /* IPv6 flow information */
    struct in6_addr sin6_addr;  /* IPv6 address */
    uint32_t sin6_scope_id;     /* IPv6 scope-id */
  };
typedef struct _ZUnique_Id_t {
    struct	in_addr zuid_addr;
    struct	_ZTimeval	tv;
} ZUnique_Id_t;
typedef struct _ZNotice_t {
    char		*z_packet;
    char		*z_version;
    ZNotice_Kind_t	z_kind;
    ZUnique_Id_t	z_uid;
    union {
	struct sockaddr		sa;
	struct sockaddr_in	ip4;
	struct sockaddr_in6	ip6;
    } z_sender_sockaddr;
    struct		_ZTimeval z_time;
    unsigned short      z_port;
    unsigned short	z_charset;
    int			z_auth;
    int			z_checked_auth;
    int			z_authent_len;
    char		*z_ascii_authent;
    char		*z_class;
    char		*z_class_inst;
    char		*z_opcode;
    char		*z_sender;
    char		*z_recipient;
    char		*z_default_format;
    char		*z_multinotice;
    ZUnique_Id_t	z_multiuid;
    ZChecksum_t		z_checksum;
    char                *z_ascii_checksum;
    int			z_num_other_fields;
    char		*z_other_fields[10]; /*Z_MAXOTHERFIELDS*/
    char                *z_message;
    int			z_message_len;
    int			z_num_hdr_fields;
    char                **z_hdr_fields;
} ZNotice_t;
typedef struct _ZSubscriptions_t {
    char	*zsub_recipient;
    char	*zsub_class;
    char	*zsub_classinst;
} ZSubscription_t;

typedef int Code_t;
Code_t ZInitialize(void);
Code_t ZMakeAuthentication(ZNotice_t*, char *,int, int*);
typedef Code_t (*Z_AuthProc)(ZNotice_t*, char *, int, int *);
/* Z_AuthProc ZMakeAuthentication; /*XXX*/
Code_t ZSendNotice(ZNotice_t *, Z_AuthProc);
Code_t ZReceiveNotice(ZNotice_t *notice, struct sockaddr_in *from);
Code_t ZFreeNotice(ZNotice_t *notice);
char const *error_message (long);
Code_t ZOpenPort(unsigned short *port);
Code_t ZSubscribeTo(ZSubscription_t *sublist, int nitems,
		    unsigned int port);
Code_t ZSubscribeToSansDefaults(ZSubscription_t *sublist, int nitems,
		    unsigned int port);
int ZGetFD (void);
int ZPending(void);
Code_t ZRetrieveSubscriptions(unsigned short, int*);
Code_t ZRetrieveDefaultSubscriptions(int *);
Code_t ZGetSubscriptions(ZSubscription_t *, int *);
char *ZGetSender(void);
const char *ZGetRealm(void);
''')

_C=_ffi.verify('''
#include <zephyr/zephyr.h>
''', libraries=['zephyr'])



class Notice(object):
    def __init__(self):
        self.ZNotice = _ffi.new("ZNotice_t *")

    class NoticeField(object):
        def __init__(self, field):
            self.field = field
        def __delete__(self, obj):
            raise AttributeError

    class NoticeStringField(NoticeField):
        def __get__(self, notice, type=None):
            val = getattr(notice.ZNotice, self.field)
            if val:
                return _ffi.string(val)
            return None
        def __set__(self, notice, value):
            self.stash = _ffi.new('char []', value)
            setattr(notice.ZNotice, self.field, self.stash)

    class NoticeIntField(NoticeField):
        def __get__(self, notice, type=None):
            return getattr(notice.ZNotice, self.field)
        def __set__(self, notice, value):
            setattr(notice.ZNotice, self.field, value)

    class NoticeBlobField(NoticeField):
        def __get__(self, notice, type=None):
            val = getattr(notice.ZNotice, self.field)
            return _ffi.buffer(_ffi.addressof(val),  _ffi.sizeof(val))[:]
        # No _set_ because these are opaqueish

    class NoticeVarStringField(NoticeField):
        def __init__(self, field, lengthfield):
            self.field = field
            self.lenf = lengthfield
        def __get__(self, notice, type=None):
            val = getattr(notice.ZNotice, self.field)
            if val:
                return _ffi.buffer(val, getattr(notice.ZNotice, self.lenf))[:]
            return None
        def __set__(self, notice, value):
            self.stash = _ffi.new('char []', value)
            setattr(notice.ZNotice, self.field, self.stash)
            setattr(notice.ZNotice, self.lenf, len(value))

    class NoticeTimevalField(NoticeField):
        def __get__(self, notice, type=None):
            field = getattr(notice.ZNotice, self.field)
            return field.tv_sec + (field.tv_usec * .000001)
        def __set__(self, notice, value):
            field = getattr(notice.ZNotice, self.field)
            field.tv_sec = int(value)
            field.tv_usec = int((value - int(value)) * 1000000)

    version = NoticeStringField('z_version')
    kind = NoticeIntField('z_kind') #XXX
    uid = NoticeBlobField('z_uid')
    origin = NoticeBlobField('z_sender_sockaddr') #XXX deopaque this
    time = NoticeTimevalField('z_time')
    port = NoticeIntField('z_port')
    charset = NoticeIntField('z_charset')
    auth = NoticeIntField('z_auth')
    checked_auth = NoticeIntField('z_checked_auth')
    authent_len = NoticeIntField('z_authent_len')
    authenticator = NoticeVarStringField('z_ascii_authent', 'z_authent_len')
    class_ = NoticeStringField('z_class')
    instance = NoticeStringField('z_class_inst')
    opcode = NoticeStringField('z_opcode')
    sender = NoticeStringField('z_sender')
    recipient = NoticeStringField('z_recipient')
    default_format = NoticeStringField('z_default_format')
    multinotice = NoticeStringField('z_multinotice')
    multiuid = NoticeBlobField('z_multiuid')
    int_checksum = NoticeIntField('z_checksum')
    checksum = NoticeStringField('z_ascii_checksum')
    num_other_fields = NoticeIntField('z_num_other_fields')
    #XXX z_other_fields
    message = NoticeVarStringField('z_message', 'z_message_len')
    message_len = NoticeIntField('z_message_len')
    num_hdr_fields = NoticeIntField('z_num_hdr_fields')

    def __repr__(self):
        return (
            '<Notice ' +
            ' '.join(f + '=' + repr(getattr(self, f)) for f in dir(self)
                     if isinstance(
                         self.__class__.__dict__.get(f, None),
                         Notice.NoticeField)) +
            '>')
    def __del__(self):
        _C.ZFreeNotice(self.ZNotice)

class ZephyrError(Exception):
    def __init__(self, context, val):
        super(ZephyrError, self).__init__(
            context + ': ' + _ffi.string(_C.error_message(val)))
        self.errno = val

class Zephyr(object):
    def __init__(self):
        _C.ZInitialize()
        self.port = None

    def send_notice(self, notice, authenticate=True):
        if authenticate:
            auth = _ffi.callback("Z_AuthProc", _C.ZMakeAuthentication)
        else:
            auth = _ffi.NULL

        retval = _C.ZSendNotice(notice.ZNotice, auth)

        if retval == 0:
            return

        raise ZephyrError('sending notice', retval)

    def open_port(self):
        if self.port is None:
            port = _ffi.new('unsigned short *')
            _C.ZOpenPort(port)
            self.port = port[0]

    def subscribe(self, triplets, defaults=True):
        self.open_port()

        if defaults:
            subscriber=_C.ZSubscribeTo
        else:
            subscriber=_C.ZSubscribeToSansDefaults

        subscriptions = _ffi.NULL
        if triplets:
            tripletses = [
                [_ffi.new('char[]', x) for x in triplet]
                for triplet in triplets
                ]
            subscriptions = _ffi.new('ZSubscription_t[]', len(triplets))
            for (i, (class_, instance, recipient)) in enumerate(tripletses):
                subscriptions[i].zsub_class = class_
                subscriptions[i].zsub_classinst = instance
                subscriptions[i].zsub_recipient = recipient

        retval = subscriber(subscriptions, len(triplets), self.port)

        if retval == 0:
            return

        raise ZephyrError('subscribing', retval)

    def retrieve_subscriptions(self):
        if self.port == 0:
            return

        iptr = _ffi.new('int *')

        retval = _C.ZRetrieveSubscriptions(z.port, iptr)
        if retval != 0:
            raise ZephyrError('retrieving subscriptions', retval)

        count = iptr[0]

        iptr[0] = 1
        subs = []
        subptr = _ffi.new('ZSubscription_t *')
        for i in xrange(count):
            retval = _C.ZGetSubscriptions(subptr, iptr)
            if retval != 0:
                raise ZephyrError('getting subscriptions', retval)

            subs.append(
                (_ffi.string(subptr[0].zsub_class),
                 _ffi.string(subptr[0].zsub_classinst),
                 _ffi.string(subptr[0].zsub_recipient)))

        return subs

    @property
    def pending(self):
        return _C.ZPending()

    def fileno(self):
        return _C.ZGetFD()

    @property
    def sender(self):
        return _ffi.string(_C.ZGetSender())

    @property
    def realm(self):
        return _ffi.string(_C.ZGetRealm())

    def receive_notice(self):
        while True:
            n = Notice()
            while True:
                retval = _C.ZReceiveNotice(n.ZNotice, _ffi.NULL)

                if retval == 0:
                    return n

                if retval == errno.ETIMEDOUT:
                    continue

                raise ZephyrError('receiving notice', retval)

def dorecv(z=None):
    if z is None:
        z=Zephyr()
    z=Zephyr()
    z.subscribe([('kcr-test', '*', '*')])
    recvloop(z)

def recvloop(z):
    while True:
        print z.receive_notice()

def dosend(z=None):
    if z is None:
        z=Zephyr()
    n = Notice()
    n.class_ = 'message'
    n.instance = 'personal'
    n.recipient = 'kcr'
    n.default_format = ''
    n.message = 'foo\0bar'

    z.send_notice(n)

#dorecv()
