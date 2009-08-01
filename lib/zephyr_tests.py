#!/usr/bin/python

# zephyr test suite
#
#   Operates on libraries in the build tree.  To test purely internal
#   interfaces, stuff them in a testing library...


"""Test Suite for libzephyr"""

import optparse
import os
import socket
import ctypes
import ctypes.util
import time
from ctypes import c_int, c_char, POINTER, c_char_p, sizeof

from zephyr import *

__revision__ = "$Id$"
try:
    __version__ = "%s/%s" % (__revision__.split()[3], __revision__.split()[2])
except IndexError:
    __version__ = "unknown"

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
        libzephyr_paths = ['libzephyr.so', 'libzephyr.dylib']
        libzephyr_paths += [os.path.join('.libs', i) for i in libzephyr_paths]
        libzephyr_paths = [os.path.join(self.builddir, i) for i in libzephyr_paths]
        libzephyr_paths = [i for i in libzephyr_paths if os.path.exists(i)]
        libzephyr_path = libzephyr_paths[0]
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
            assert self._libzephyr.ZExpandRealm("localhost") == socket.getfqdn("localhost").upper()
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
