#!/usr/bin/python

# zephyr test suite
#
#   Operates on libraries in the build tree.  To test purely internal
#   interfaces, stuff them in a testing library...


"""Test Suite for libzephyr"""

import optparse
import os
import socket
import struct
import ctypes
import ctypes.util
import time
from ctypes import c_int, c_uint, c_ushort, c_char, c_ubyte
from ctypes import c_uint16, c_uint32
from ctypes import POINTER, c_void_p, c_char_p
from ctypes import Structure, Union, sizeof

__revision__ = "$Id$"
try:
    __version__ = "%s/%s" % (__revision__.split()[3], __revision__.split()[2])
except IndexError:
    __version__ = "unknown"

def print_line_or_lines(results, indent):
    """short values on same line, multi-line on later ones..."""
    if len(results) == 1:
        print results[0]
    else:
        print
        for result in results:
            print indent + result

def ctypes_pprint(cstruct, indent=""):
    """pretty print a ctypes Structure or Union"""
    
    for field_name, field_ctype in cstruct._fields_:
        field_value = getattr(cstruct, field_name)
        print indent + field_name,
        next_indent = indent + "    "
        pprint_name = "pprint_%s" % field_name
        pformat_name = "pformat_%s" % field_name
        if hasattr(cstruct, pprint_name):
            # no longer used
            getattr(cstruct, pprint_name)(next_indent)
        elif hasattr(cstruct, pformat_name):
            # counted-array and other common cases
            print_line_or_lines(getattr(cstruct, pformat_name)(), next_indent)
        elif hasattr(field_value, "pformat"):
            # common for small compound types
            print_line_or_lines(field_value.pformat(), next_indent)
        elif hasattr(field_value, "pprint"):
            # useful for Union selectors
            field_value.pprint(next_indent)
        elif hasattr(field_value, "_fields_"):
            # generic recursion
            print
            ctypes_pprint(field_value, next_indent)
        else:
            # generic simple (or unknown/uninteresting) value
            print field_value

class Enum(c_int):
    def pformat(self):
        try:
            return ["%s(%d)" % (self._values_[self.value], self.value)]
        except IndexError:
            return ["unknown enum value(%d)" % (self.value)]

def populate_enum(cls):
    """make members for each of the enum values"""
    for value, tag in enumerate(cls._values_):
        setattr(cls, tag, cls(value))

# not really an enum, but we get a richer effect by treating it as one
class Enum_u16(c_uint16):
    def pformat(self):
        try:
            return ["%s(%d)" % (self._values_[self.value], self.value)]
        except IndexError:
            return ["unknown enum value(%d)" % (self.value)]


# TODO: pick some real framework later, we're just poking around for now
class TestSuite(object):
    """test collection and runner"""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def run(self):
        tests = sorted([testname for testname in dir(self) 
                        if testname.startswith("test_")])
        failures = []
        for test in tests:
            try:
                print "===", "starting", test, "==="
                getattr(self, test)()
                print "===", "done", test, "==="
            except TestFailure, tf:
                print "===", "FAILED", test, "==="
                failures.append([test, tf])

        return failures


class TestFailure(Exception):
    pass

# POSIX socket types...
class in_addr(Structure):
    _fields_ = [
        ("s_addr", c_uint32),
        ]
    def pformat(self):
        return [socket.inet_ntoa(struct.pack("<I", self.s_addr))]

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

class AF_(Enum_u16):
    _socket_af = dict([(v,n) for n,v in socket.__dict__.items() if n.startswith("AF_")])
    _values_ = [_socket_af.get(k, "unknown address family") for k in range(min(_socket_af), max(_socket_af)+1)]

populate_enum(AF_)

class sockaddr(Structure):
    _fields_ = [
        ("sa_family", AF_),
        ("sa_data", c_char * 14),
        ]

class sockaddr_in(Structure):
    _fields_ = [
        ("sin_family", AF_),
        ("sin_port", c_uint16),
        ("sin_addr", in_addr),
        # hack from linux - do we actually need it?
        ("sin_zero", c_ubyte * (sizeof(sockaddr)-sizeof(c_uint16)-sizeof(c_uint16)-sizeof(in_addr))),
        ]
    def pformat_sin_zero(self):
        return ["[ignored]"]
        
# RFC2553...
class sockaddr_in6(Structure):
    _fields_ = [
        ("sin6_family", AF_),
        ("sin6_port", c_uint16),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", in6_addr),
        ("sin6_scope_id", c_uint32),
        ]
        
# zephyr/zephyr.h
#define Z_MAXOTHERFIELDS        10      /* Max unknown fields in ZNotice_t */
Z_MAXOTHERFIELDS = 10
#define ZAUTH (ZMakeAuthentication)
#define ZCAUTH (ZMakeZcodeAuthentication)
#define ZNOAUTH ((Z_AuthProc)0)
ZNOAUTH = 0

# typedef enum {
#     UNSAFE, UNACKED, ACKED, HMACK, HMCTL, SERVACK, SERVNAK, CLIENTACK, STAT
# } ZNotice_Kind_t;
# extern const char *ZNoticeKinds[9];

class ZNotice_Kind_t(Enum):
    _values_ = [
        "UNSAFE", "UNACKED", "ACKED", "HMACK", "HMCTL", "SERVACK", "SERVNAK", "CLIENTACK", "STAT",
        ]
populate_enum(ZNotice_Kind_t)

def pformat_timeval(tv_sec, tv_usec):
    """format timeval parts as seconds and human-readable time"""
    try:
        timestr = time.ctime(tv_sec)
    except ValueError:
        timestr = "invalid unix time"
    if tv_usec >= 1000000 or tv_usec < 0:
        # invalid usec, still treat as numbers
        return ["%dsec, %dusec (bad) (%s)" % (tv_sec, tv_usec, timestr)]
    return ["%d.%06dsec (%s)" % (tv_sec, tv_usec, timestr)]

# struct _ZTimeval {
class _ZTimeval(Structure):
    _fields_ = [
#       int tv_sec;
        ("tv_sec", c_int),
#       int tv_usec;
        ("tv_usec", c_int),
# };
        ]
    def pformat(self):
        return pformat_timeval(self.tv_sec, self.tv_usec)


class _ZTimeval_Net(_ZTimeval):
    """When _ZTimeval is used in a ZUnique_Id_t, the time parts are
    stored in network byte order.  Handle this by faking up a different type."""
    def pformat(self):
        return pformat_timeval(socket.ntohl(self.tv_sec), socket.ntohl(self.tv_usec))

# typedef struct _ZUnique_Id_t {
class ZUnique_Id_t(Structure):
    _fields_ = [
        #     struct    in_addr zuid_addr;
        ("zuid_addr", in_addr),
        #     struct    _ZTimeval       tv;
        ("tv", _ZTimeval_Net),
        # } ZUnique_Id_t;
        ]

#     union {
class _U_z_sender_sockaddr(Union):
    _fields_ = [
        #       struct sockaddr         sa;
        ("sa", sockaddr),
        #       struct sockaddr_in      ip4;
        ("ip4", sockaddr_in),
        #       struct sockaddr_in6     ip6;
        ("ip6", sockaddr_in6),
        #     } z_sender_sockaddr;
        ]
    def pprint(self, indent):
        print
        if self.sa.sa_family.value == socket.AF_INET:
            ctypes_pprint(self.ip4, indent + ".ip4:")
        elif self.sa.sa_family.value == socket.AF_INET6:
            ctypes_pprint(self.ip6, indent + ".ip6:")
        else:
            ctypes_pprint(self.sa, indent + ".sa:")

# typedef struct _ZNotice_t {
class ZNotice_t(Structure):
    _fields_ = [
        # char          *z_packet;
        ("z_packet", c_char_p),
        #     char              *z_version;
        ("z_version", c_char_p),
        #     ZNotice_Kind_t    z_kind;
        ("z_kind", ZNotice_Kind_t),
        #     ZUnique_Id_t      z_uid;
        ("z_uid", ZUnique_Id_t),
        #     union {
        #       struct sockaddr         sa;
        #       struct sockaddr_in      ip4;
        #       struct sockaddr_in6     ip6;
        #     } z_sender_sockaddr;
        ("z_sender_sockaddr", _U_z_sender_sockaddr),

        #     /* heavily deprecated: */
        # #define z_sender_addr z_sender_sockaddr.ip4.sin_addr
        #     /* probably a bad idea?: */
        #     struct            _ZTimeval z_time;
        ("z_time", _ZTimeval),
        #     unsigned short      z_port;
        ("z_port", c_ushort),
        #     unsigned short    z_charset;
        ("z_charset", c_ushort),
        #     int                       z_auth;
        ("z_auth", c_int),
        #     int                       z_checked_auth;
        # TODO: fake enum, for display
        ("z_checked_auth", c_int),
        #     int                       z_authent_len;
        ("z_authent_len", c_int),
        #     char              *z_ascii_authent;
        ("z_ascii_authent", c_char_p),
        #     char              *z_class;
        ("z_class", c_char_p),
        #     char              *z_class_inst;
        ("z_class_inst", c_char_p),
        #     char              *z_opcode;
        ("z_opcode", c_char_p),
        #     char              *z_sender;
        ("z_sender", c_char_p),
        #     char              *z_recipient;
        ("z_recipient", c_char_p),
        #     char              *z_default_format;
        ("z_default_format", c_char_p),
        #     char              *z_multinotice;
        ("z_multinotice", c_char_p),
        #     ZUnique_Id_t      z_multiuid;
        ("z_multiuid", ZUnique_Id_t),
        #     ZChecksum_t               z_checksum;
        ("z_checksum", c_uint),
        #     char                *z_ascii_checksum;
        ("z_ascii_checksum", c_char_p),
        #     int                       z_num_other_fields;
        ("z_num_other_fields", c_int),
        #     char              *z_other_fields[Z_MAXOTHERFIELDS];
        ("z_other_fields", c_char_p * Z_MAXOTHERFIELDS),
        #     caddr_t           z_message;
        ("z_message", c_char_p), # not 1980
        #     int                       z_message_len;
        ("z_message_len", c_int),
        #     int                       z_num_hdr_fields;
        ("z_num_hdr_fields", c_int),
        #     char                **z_hdr_fields;
        ("z_hdr_fields", POINTER(c_char_p)),
        # } ZNotice_t;
        ]
    def pformat_z_other_fields(self):
        return ["%d: %s" % (n, self.z_other_fields[n])
                for n in range(Z_MAXOTHERFIELDS)]
    def pformat_z_hdr_fields(self):
        if not self.z_hdr_fields:
            return ["NULL"]
        return ["%d: %s" % (n, self.z_hdr_fields[n])
                for n in range(self.z_num_hdr_fields)]
        
class libZephyr(object):
    """wrappers for functions in libZephyr"""
    testable_funcs = [
        "ZInitialize", 
        "ZGetFD", 
        "ZGetRealm",
        "ZGetSender",
        "Z_FormatRawHeader",
        "ZParseNotice",
        "ZFormatNotice",
        "ZCompareUID",
        "ZExpandRealm",
        "ZGetCharsetString",
        "ZGetCharset",
        "ZCharsetToString",
        "ZTransliterate",
        "ZOpenPort",
        "ZClosePort",
        "ZMakeAscii",
        "ZMakeZcode",
        "ZGetDestAddr",
        "ZSetFD",
        "ZPending",
        ]
    def __init__(self, library_path=None):
        """connect to the library and build the wrappers"""
        if not library_path:
            library_path = ctypes.util.find_library("zephyr")
        self._lib = ctypes.cdll.LoadLibrary(library_path)

        # grab the Zauthtype variable
        self.Zauthtype = ctypes.c_int.in_dll(self._lib, 'Zauthtype').value
        
        # generic bindings?
        for funcname in self.testable_funcs:
            setattr(self, funcname, getattr(self._lib, funcname))

        # TODO: fix return types, caller types in a more generic way later
        #   (perhaps by parsing the headers or code)
        #   perhaps metaprogramming or decorators...
        self.ZGetRealm.restype = ctypes.c_char_p
        self.ZGetSender.restype = ctypes.c_char_p
        
        # Code_t
        # Z_FormatRawHeader(ZNotice_t *notice,
        #         char *buffer,
        #         int buffer_len,
        #         int *len,
        #         char **cstart,
        #         char **cend)
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
        #            int len,
        #            ZNotice_t *notice)
        self.ZParseNotice.argtypes = [
            c_char_p,             # *buffer
            c_int,                # len
            POINTER(ZNotice_t),   # *notice
            ]

        # Code_t
        # ZFormatNotice(register ZNotice_t *notice,
        #             char **buffer,
        #             int *ret_len,
        #             Z_AuthProc cert_routine)
        self.ZFormatNotice.argtypes = [
            POINTER(ZNotice_t),         # *notice
            POINTER(c_char_p),          # **buffer
            POINTER(c_int),             # *ret_len
            c_void_p,                   # cert_routine
            ]

        # int
        # ZCompareUID(ZUnique_Id_t *uid1,
        #             ZUnique_Id_t *uid2)
        self.ZCompareUID.argtypes = [
            POINTER(ZUnique_Id_t),      # *uid1
            POINTER(ZUnique_Id_t),      # *uid2
            ]

        # char *
        # ZExpandRealm(realm)
        # char *realm;  # mmm 80's
        self.ZExpandRealm.restype = c_char_p
        self.ZExpandRealm.argtypes = [
            c_char_p,           # realm
            ]

        # unsigned short
        # ZGetCharset(char *charset)
        self.ZGetCharset.restype = c_ushort
        self.ZGetCharset.argtypes = [
            c_char_p,		# charset
            ]

        # const char *
        # ZCharsetToString(unsigned short charset)
        self.ZCharsetToString.restype = c_char_p
        self.ZCharsetToString.argtypes = [
            c_ushort,		# charset
            ]

        # Code_t
        # ZTransliterate(char *in,
        #               int inlen,
        #               char *inset,
        #               char *outset,
        #               char **out,
        #               int *outlen)
        self.ZTransliterate.argtypes = [
            c_char_p,		# in
            c_int,		# inlnet,
            c_char_p,		# inset
            c_char_p,		# outset
            POINTER(c_char_p),	# out
            POINTER(c_int),	# outlen
            ]

        # Code_t ZOpenPort(u_short *port)
        self.ZOpenPort.argtypes = [
            POINTER(c_ushort),  # port
            ]

        # const char *
        # ZGetCharsetString(char *charset)
        self.ZGetCharsetString.restype = c_char_p
        self.ZGetCharsetString.argtypes = [
            c_char_p,		# charset
            ]

        # Code_t
        # ZMakeAscii(register char *ptr,
        # 	   int len,
        # 	   unsigned char *field,
        # 	   int num)
        self.ZMakeAscii.argtypes = [
            c_char_p,           # ptr
            c_int,              # len
            c_char_p,           # field; c_uchar_p?
            c_int,              # num
            ]

        # Code_t
        # ZMakeZcode(register char *ptr,
        # 	   int len,
        # 	   unsigned char *field,
        # 	   int num)
        self.ZMakeZcode.argtypes = [
            c_char_p,           # ptr
            c_int,              # len
            c_char_p,           # field; c_uchar_p?
            c_int,              # num
            ]

        # struct sockaddr_in ZGetDestAddr (void) {
        self.ZGetDestAddr.restype = sockaddr_in

        # library-specific setup...
        self.ZInitialize()

def py_make_ascii(input):
    """reference ZMakeAscii expressed as python..."""
    hexes = ["%02X" % ord(ch) for ch in input]
    output = []
    for i in range(0, len(hexes), 4):
        output.append("0x" + "".join(hexes[i:i+4]))
    return " ".join(output)

def py_make_zcode(input):
    """reference ZMakeZcode expressed as python..."""
    return "Z" + input.replace("\xff", "\xff\xf1").replace("\0", "\xff\xf0")


class ZephyrTestSuite(TestSuite):
    """Tests for libzephyr"""
    def setup(self):
        # find the library
        libzephyr_path = os.path.join(self.builddir, "libzephyr.so.4.0.0")
        # check for libtool...
        if not os.path.exists(libzephyr_path):
            libzephyr_path = os.path.join(self.builddir, ".libs", "libzephyr.so.4.0.0")
        self._libzephyr = libZephyr(libzephyr_path)

    def cleanup(self):
        # no cleanup needed yet
        pass

    def test_zinit(self):
        """test that ZInitialize did something"""
        print "fd", self._libzephyr.ZGetFD()
        realm = self._libzephyr.ZGetRealm()
        print "realm", realm
        if not realm:
            raise TestFailure("empty realm %s" % realm)
        if self._libzephyr.Zauthtype and realm == 'local-realm':
            raise TestFailure("useless realm %s" % realm)
        if self._libzephyr.Zauthtype == 0 and realm != 'local-realm':
            raise TestFailure("wrong realm %s (should be local-realm)" % realm)
        print self._libzephyr.ZGetSender()
        
    def test_notices(self):
        """test notice construct/destruct"""
        notice = ZNotice_t()
        print "sizeof ZNotice_t", sizeof(notice)
        zbuf = c_char_p(0)
        zbuflen = c_int(0)
        st = self._libzephyr.ZFormatNotice(notice, zbuf, zbuflen, ZNOAUTH)
        print "ZFormatNotice:", "retval", st
        print "\tzbuflen", zbuflen
        print "\tzbuf", repr(zbuf.value)
        new_notice = ZNotice_t()
        st = self._libzephyr.ZParseNotice(zbuf, zbuflen, new_notice)
        print "ZParseNotice:", "retval", st
        print "\tz_version", new_notice.z_version
        ctypes_pprint(new_notice)

    def test_z_compare_uid(self):
        """test ZCompareUID"""

        uid1 = ZUnique_Id_t()
        uid2 = ZUnique_Id_t()
        assert self._libzephyr.ZCompareUID(uid1, uid2), "null uids don't match"
        
        # there's no ZUnique_Id_t constructor - Z_FormatHeader and Z_NewFormatHeader initialize notice->z_uid directly
        notice1 = ZNotice_t()
        zbuf = c_char_p(0)
        zbuflen = c_int(0)
        st = self._libzephyr.ZFormatNotice(notice1, zbuf, zbuflen, ZNOAUTH)
        assert st == 0, "ZFormatNotice notice1 failed"

        notice2 = ZNotice_t()
        zbuf = c_char_p(0)
        zbuflen = c_int(0)
        st = self._libzephyr.ZFormatNotice(notice2, zbuf, zbuflen, ZNOAUTH)
        assert st == 0, "ZFormatNotice notice2 failed"

        assert not self._libzephyr.ZCompareUID(notice1.z_uid, notice2.z_uid), "distinct notices don't compare as distinct"
        # ctypes_pprint(notice1.z_uid)

    def test_zauthtype(self):
        """Make sure Zauthtype is an acceptable value"""
        assert self._libzephyr.Zauthtype in (0, 4, 5)

    def test_z_expand_realm(self):
        """test ZExpandRealm"""
        if self._libzephyr.Zauthtype:
            assert self._libzephyr.ZExpandRealm("") == ""
            assert self._libzephyr.ZExpandRealm("localhost") == ""
            assert self._libzephyr.ZExpandRealm("bitsy.mit.edu") == "ATHENA.MIT.EDU"
        else:
            assert self._libzephyr.ZExpandRealm("") == ""
            assert self._libzephyr.ZExpandRealm("localhost") == "LOCALHOST"
            assert self._libzephyr.ZExpandRealm("bitsy.mit.edu") == "BITSY.MIT.EDU"

def find_buildpath():
    parser = optparse.OptionParser(usage=__doc__,
                                   version = "%%prog %s" % __version__)
    parser.add_option("--builddir", default="..", 
                      help="where to find the top of the build tree")
    parser.add_option("--verbose", "-v", action="store_true",
                      help="pass through for doctest.testfile")
    opts, args = parser.parse_args()
    assert not args, "no args yet"

    return os.path.join(opts.builddir, "lib")

def getsockname(fd):
    """wrapped C lib getsocketname (works on raw fd)"""
    libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library("c"))

    call_getsockname = libc.getsockname
    call_getsockname.argtypes = [
        c_int,                 # int s
        POINTER(sockaddr),     # struct sockaddr *name
        POINTER(c_int),        # socklen_t *namelen
        ]
    name = sockaddr(0)
    namelen = c_int(sizeof(name))
    ret = call_getsockname(fd, name, namelen)
    if ret == 0:
        return name
    # we can't get at errno until python 2.6...
    print ret
    raise EnvironmentError("getsockname failed")


if __name__ == "__main__":
    tester = ZephyrTestSuite(builddir=find_buildpath())
    tester.setup()
    failures = tester.run()
    tester.cleanup()
    for failure, exc in failures:
        print "FAIL:", failure, str(exc)
