#!/usr/bin/python

# zephyr test suite
#
#   Operates on libraries in the build tree.  To test purely internal
#   interfaces, stuff them in a testing library...


"""Test Suite for libzephyr"""

import optparse
import os
import ctypes
from ctypes import c_int, c_uint, c_ushort, c_char, c_ubyte
from ctypes import c_uint16, c_uint32
from ctypes import POINTER, c_void_p, c_char_p
from ctypes import Structure, Union, sizeof

__revision__ = "$Id 0 0 0 $"
__version__ = "%s/%s" % (__revision__.split()[3], __revision__.split()[2])

# TODO: pick some real framework later, we're just poking around for now
class TestSuite(object):
    """test collection and runner"""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class TestFailure(Exception):
    pass

# POSIX socket types...
class in_addr(Structure):
    _fields_ = [
        ("s_addr", c_uint32),
        ]

class _U_in6_u(Union):
    _fields_ = [
        ("u6_addr8", c_ubyte * 16),
        ("u6_addr16", c_uint16 * 8),
        ("u6_addr32", c_uint32 * 4),
        ]

class in6_addr(Structure):
    _fields_ = [
        ("in6_u", _U_in6_u),
        ]

class sockaddr(Structure):
    _fields_ = [
        ("sa_family", c_uint16),
        ("sa_data", c_char * 14),
        ]

class sockaddr_in(Structure):
    _fields_ = [
        ("sin_family", c_uint16),
        ("sin_port", c_uint16),
        ("sin_addr", in_addr),
        # hack from linux - do we actually need it?
        ("sin_zero", c_ubyte * (sizeof(sockaddr)-sizeof(c_uint16)-sizeof(c_uint16)-sizeof(in_addr))),
        ]
        
# RFC2553...
class sockaddr_in6(Structure):
    _fields_ = [
        ("sin6_family", c_uint16),
        ("sin6_port", c_uint16),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", in6_addr),
        ("sin6_scope_id", c_uint32),
        ]
        
# zephyr/zephyr.h
#define Z_MAXOTHERFIELDS	10	/* Max unknown fields in ZNotice_t */
Z_MAXOTHERFIELDS = 10
#define ZAUTH (ZMakeAuthentication)
#define ZCAUTH (ZMakeZcodeAuthentication)
#define ZNOAUTH ((Z_AuthProc)0)
ZNOAUTH = 0

# struct _ZTimeval {
class _ZTimeval(Structure):
    _fields_ = [
# 	int tv_sec;
        ("tv_sec", c_int),
# 	int tv_usec;
        ("tv_usec", c_int),
# };
        ]

# typedef struct _ZUnique_Id_t {
class ZUnique_Id_t(Structure):
    _fields_ = [
        #     struct	in_addr zuid_addr;
        ("zuid_addr", in_addr),
        #     struct	_ZTimeval	tv;
        ("tv", _ZTimeval),
        # } ZUnique_Id_t;
        ]

#     union {
class _U_z_sender_sockaddr(Union):
    _fields_ = [
        # 	struct sockaddr		sa;
        ("sa", sockaddr),
        # 	struct sockaddr_in	ip4;
        ("ip4", sockaddr_in),
        # 	struct sockaddr_in6	ip6;
        ("ip6", sockaddr_in6),
        #     } z_sender_sockaddr;
        ]

# typedef struct _ZNotice_t {
class ZNotice_t(Structure):
    _fields_ = [
        # char		*z_packet;
        ("z_packet", c_char_p),
        #     char		*z_version;
        ("z_version", c_char_p),
        #     ZNotice_Kind_t	z_kind;
        ("z_kind", c_int),        # no enums yet
        #     ZUnique_Id_t	z_uid;
        ("z_uid", ZUnique_Id_t),
        #     union {
        # 	struct sockaddr		sa;
        # 	struct sockaddr_in	ip4;
        # 	struct sockaddr_in6	ip6;
        #     } z_sender_sockaddr;
        ("z_sender_sockaddr", _U_z_sender_sockaddr),

        #     /* heavily deprecated: */
        # #define z_sender_addr	z_sender_sockaddr.ip4.sin_addr
        #     /* probably a bad idea?: */
        #     struct		_ZTimeval z_time;
        ("z_time", _ZTimeval),
        #     unsigned short      z_port;
        ("z_port", c_ushort),
        #     unsigned short	z_charset;
        ("z_charset", c_ushort),
        #     int			z_auth;
        ("z_auth", c_int),
        #     int			z_checked_auth;
        ("z_checked_auth", c_int),
        #     int			z_authent_len;
        ("z_authent_len", c_int),
        #     char		*z_ascii_authent;
        ("z_ascii_authent", c_char_p),
        #     char		*z_class;
        ("z_class", c_char_p),
        #     char		*z_class_inst;
        ("z_class_inst", c_char_p),
        #     char		*z_opcode;
        ("z_opcode", c_char_p),
        #     char		*z_sender;
        ("z_sender", c_char_p),
        #     char		*z_recipient;
        ("z_recipient", c_char_p),
        #     char		*z_default_format;
        ("z_default_format", c_char_p),
        #     char		*z_multinotice;
        ("z_multinotice", c_char_p),
        #     ZUnique_Id_t	z_multiuid;
        ("z_multiuid", ZUnique_Id_t),
        #     ZChecksum_t		z_checksum;
        ("z_checksum", c_uint),
        #     char                *z_ascii_checksum;
        ("z_ascii_checksum", c_char_p),
        #     int			z_num_other_fields;
        ("z_num_other_fields", c_int),
        #     char		*z_other_fields[Z_MAXOTHERFIELDS];
        ("z_other_fields", c_char_p * Z_MAXOTHERFIELDS),
        #     caddr_t		z_message;
        ("z_message", c_char_p), # not 1980
        #     int			z_message_len;
        ("z_message_len", c_int),
        #     int			z_num_hdr_fields;
        ("z_num_hdr_fields", c_int),
        #     char                **z_hdr_fields;
        ("z_hdr_fields", POINTER(c_char_p)),
        # } ZNotice_t;
        ]


class ZephyrTestSuite(TestSuite):
    """Tests for libzephyr"""
    testable_funcs = [
        "ZInitialize", 
        "ZGetFD", 
        "ZGetRealm",
        "ZGetSender",
        "Z_FormatRawHeader",
        "ZParseNotice",
        "ZFormatNotice",
        ]

    def setup(self):
        # find the library
        self._libzephyr_path = os.path.join(self.builddir, "libzephyr.so.4.0.0")
        # check for libtool...
        if not os.path.exists(self._libzephyr_path):
            self._libzephyr_path = os.path.join(self.builddir, ".libs", "libzephyr.so.4.0.0")
        self._libzephyr = ctypes.cdll.LoadLibrary(self._libzephyr_path)
        # generic bindings?
        for funcname in self.testable_funcs:
            setattr(self, funcname, getattr(self._libzephyr, funcname))

        # TODO: fix return types, caller types in a more generic way later
        #   (perhaps by parsing the headers or code)
        self.ZGetRealm.restype = ctypes.c_char_p
        self.ZGetSender.restype = ctypes.c_char_p
        
        # Code_t
        # Z_FormatRawHeader(ZNotice_t *notice,
	#	  char *buffer,
	#	  int buffer_len,
	#	  int *len,
	#	  char **cstart,
	#	  char **cend)
        # This stuffs a notice into a buffer; cstart/cend point into the checksum in buffer
        self.Z_FormatRawHeader.argtypes = [
            c_void_p,            # *notice
            c_char_p,            # *buffer
            c_int,               # buffer_len
            POINTER(c_int),      # *len
            POINTER(c_char_p),   # **cstart
            POINTER(c_char_p),   # **cend
            ]

        # Code_t
        # ZParseNotice(char *buffer,
        # 	     int len,
        # 	     ZNotice_t *notice)
        self.ZParseNotice.argtypes = [
            c_char_p,             # *buffer
            c_int,                # len
            POINTER(ZNotice_t),   # *notice
            ]

        # Code_t
        # ZFormatNotice(register ZNotice_t *notice,
        # 	      char **buffer,
        # 	      int *ret_len,
        # 	      Z_AuthProc cert_routine)
        self.ZFormatNotice.argtypes = [
            POINTER(ZNotice_t),         # *notice
            POINTER(c_char_p),          # **buffer
            POINTER(c_int),             # *ret_len
            c_void_p,                   # cert_routine
            ]

        # library-specific setup...
        self.ZInitialize()

    def run(self):
        tests = sorted([testname for testname in dir(self) 
                        if testname.startswith("test_")])
        failures = []
        for test in tests:
            try:
                getattr(self, test)()
            except TestFailure, tf:
                failures.append([test, tf])

        return failures

    def cleanup(self):
        # no cleanup needed yet
        pass

    def test_zinit(self):
        """test that ZInitialize did something"""
        print "fd", self.ZGetFD()
        realm = self.ZGetRealm()
        print "realm", realm
        if not realm or realm == "local-realm":
            raise TestFailure("useless realm %s" % realm)
        print self.ZGetSender()
        
    def test_notices(self):
        """test notice construct/destruct"""
        notice = ZNotice_t()
        print "sizeof ZNotice_t", sizeof(notice)
        zbuf = c_char_p(0)
        zbuflen = c_int(0)
        st = self.ZFormatNotice(notice, zbuf, zbuflen, ZNOAUTH)
        print "ZFormatNotice:", "retval", st
        print "\tzbuflen", zbuflen
        print "\tzbuf", repr(zbuf.value)
        new_notice = ZNotice_t()
        st = self.ZParseNotice(zbuf, zbuflen, new_notice)
        print "ZParseNotice:", "retval", st
        print "\tz_version", new_notice.z_version


if __name__ == "__main__":
    parser = optparse.OptionParser(usage=__doc__,
                                   version = "%%prog %s" % __version__)
    parser.add_option("--builddir", default="..", 
                      help="where to find the top of the build tree")
    opts, args = parser.parse_args()
    assert not args, "no args yet"

    tester = ZephyrTestSuite(builddir=os.path.join(opts.builddir, "lib"))
    tester.setup()
    failures = tester.run()
    tester.cleanup()
    for failure, exc in failures:
        print "FAIL:", failure, str(exc)
