/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the server unit tests.
 *
 *	Created by:	Karl Ramm
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "zserver.h"

int ulogin_add_user(ZNotice_t *notice, Exposure_type exposure,
                    struct sockaddr_in *who);
Exposure_type ulogin_remove_user(ZNotice_t *notice,
                                 struct sockaddr_in *who,
                                 int *err_return);
int ulogin_find(char *user, struct in_addr *host,
                      unsigned int port);
int ulogin_find_user(char *user);
void ulogin_flush_user(ZNotice_t *notice);
extern Location *locations;

#define TEST(EXP) \
    do { \
        printf("%s:%d: %s: ", __FILE__, __LINE__, #EXP); \
        fflush(stdout); \
        if (EXP) {        \
            puts("PASS"); \
        } else {          \
            puts("FAIL"); \
            failures++; \
        } \
        fflush(stdout); \
    } while (0)

#define V(EXP) \
    do { \
        printf("%s:%d: %s\n", __FILE__, __LINE__, #EXP); \
        fflush(stdout); \
        EXP; \
    } while (0)

#define VI(EXP) \
    do { \
        int result; \
        printf("%s:%d: %s ->", __FILE__, __LINE__, #EXP); \
        fflush(stdout); \
        result=EXP; \
        printf(" %d\n", result); \
        fflush(stdout); \
    } while (0)

#define PP(s) \
    do { \
        printf("%s:%d: %s\n", __FILE__, __LINE__, s); \
        fflush(stdout); \
    } while (0)

#define P1(fmt, x)                               \
    do { \
        printf("%s:%d: " fmt "\n", __FILE__, __LINE__, x); \
        fflush(stdout); \
    } while (0)

int failures = 0;

void test_uloc(void);
void test_acl_files(void);

int
main(int argc, char **argv)
{
    int logopt = 0;
#if 0 && defined(LOG_PERROR)
    logopt = LOG_PERROR;
#endif
    openlog("test_server", logopt, LOG_USER);
    puts("Zephyr server testing");
    puts("");

    test_uloc();
    test_acl_files();

    if(failures)
        printf("\n%d FAILURES\n", failures);

    exit(!(failures == 0));
}

void
test_uloc(void)
{
    ZNotice_t z1, z2, z0, z4;
    String *s1, *s2, *s0, *s4;
    struct sockaddr_in who1, who2, who3, who0, who4;
    int ret;

    puts("uloc storage routines");

    TEST(ulogin_find_user("nonexistent") == -1);

    /* fake up just enough */
    who1.sin_family = AF_INET;
    who1.sin_port = 1;
    who1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    z1.z_class_inst = "user1";
    z1.z_port = 1;
    z1.z_message = "here\0now\0this\0";
    z1.z_message_len = 14;

    s1 = make_string(z1.z_class_inst, 0);

    TEST(ulogin_add_user(&z1, NET_ANN, &who1) == 0);
    TEST(ulogin_find_user("user1") != -1);

    who2.sin_family = AF_INET;
    who2.sin_port = 2;
    who2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    z2.z_class_inst = "user2";
    z2.z_port = 2;
    z2.z_message = "here\0now\0this\0";
    z2.z_message_len = 14;

    s2 = make_string(z2.z_class_inst, 0);

    TEST(ulogin_add_user(&z2, NET_ANN, &who2) == 0);
    TEST(ulogin_find_user("user2") != -1);
    TEST(locations[ulogin_find_user("user1")].user == s1);
    TEST(locations[ulogin_find_user("user2")].user == s2);
    TEST(ulogin_add_user(&z1, NET_ANN, &who1) == 0);
    TEST(locations[ulogin_find_user("user1")].user == s1);
    TEST(locations[ulogin_find_user("user2")].user == s2);

    who3.sin_family = AF_INET;
    who3.sin_port = 3;
    who3.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    TEST(ulogin_find("user1", &who3.sin_addr, 3) == -1);

    who0.sin_family = AF_INET;
    who0.sin_port = 3;
    who0.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    z0.z_class_inst = "user0";
    z0.z_port = 3;
    z0.z_message = "here\0now\0this\0";
    z0.z_message_len = 14;

    s0 = make_string(z0.z_class_inst, 0);

    TEST(ulogin_add_user(&z0, NET_ANN, &who0) == 0);
    TEST(ulogin_find_user("user0") != -1);
    TEST(locations[ulogin_find_user("user1")].user == s1);
    TEST(locations[ulogin_find_user("user2")].user == s2);

    TEST(ulogin_remove_user(&z0, &who0, &ret) == NET_ANN && ret == 0);
    /* 1 = NOLOC */
    TEST(ulogin_remove_user(&z0, &who0, &ret) == NONE && ret == 1);

    TEST(ulogin_add_user(&z0, NET_ANN, &who0) == 0);
    TEST(ulogin_remove_user(&z1, &who0, &ret) == NET_ANN && ret == 0);

    V(ulogin_flush_user(&z0));
    TEST(ulogin_find_user("user0") == -1);

    TEST(ulogin_add_user(&z0, NET_ANN, &who0) == 0);
    TEST(ulogin_add_user(&z1, NET_ANN, &who1) == 0);
    V(ulogin_flush_user(&z1));
    TEST(ulogin_find_user("user1") == -1);

    who4.sin_family = AF_INET;
    who4.sin_port = 4;
    who4.sin_addr.s_addr = htonl(INADDR_ANY);

    z4.z_class_inst = "user4";
    z4.z_port = 4;
    z4.z_message = "here\0now\0this\0";
    z4.z_message_len = 14;

    s4 = make_string(z4.z_class_inst, 0);

    TEST(ulogin_add_user(&z4, NET_ANN, &who4) == 0);

    V(uloc_flush_client(&who2));
    TEST(locations[ulogin_find_user("user0")].user == s0);
    TEST(ulogin_find_user("user1") == -1);
    TEST(ulogin_find_user("user2") == -1);
    TEST(locations[ulogin_find_user("user4")].user == s4);

    V(uloc_hflush(&who0.sin_addr));
    TEST(ulogin_find_user("user0") == -1);
    TEST(ulogin_find_user("user1") == -1);
    TEST(ulogin_find_user("user2") == -1);
    TEST(locations[ulogin_find_user("user4")].user == s4);
    puts("");
}

void
test_acl_files(){
    char filename[]="/tmp/test_server_acl.XXXXXX";
    int fd;
    int result;
    struct sockaddr_in who_zero;
    struct sockaddr_in who_localhost;
    struct sockaddr_in who_broadcast;

    memset(&who_zero, 0, sizeof(who_zero));
    memset(&who_localhost, 0, sizeof(who_localhost));
    memset(&who_broadcast, 0, sizeof(who_broadcast));

    who_localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    who_broadcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    puts("low-level acl routines");
    puts("");

    fd = mkstemp(filename);
    P1("acl file is %s", filename);

    PP("empty acl");

    TEST(acl_check(filename, NULL, NULL) == 0);
    TEST(acl_check(filename, "foo", NULL) == 0);

    write(fd, "*\n", 2);
    acl_cache_reset();
    PP("acl of *");

    TEST(acl_check(filename, NULL, NULL) == 0);
    TEST(acl_check(filename, "foo", NULL) == 1);
    TEST(acl_check(filename, "bar", NULL) == 1);

    lseek(fd, 0, SEEK_SET);
    write(fd, "foo\n", 4);
    acl_cache_reset();
    PP("acl of just foo");

    TEST(acl_check(filename, NULL, NULL) == 0);
    TEST(acl_check(filename, "foo", NULL) == 1);
    TEST(acl_check(filename, "bar", NULL) == 0);

    lseek(fd, 0, SEEK_SET);
    write(fd, "*@TIM.EDU\n", 10);
    acl_cache_reset();
    PP("acl of *@TIM.EDU");

    TEST(acl_check(filename, NULL, NULL) == 0);
    TEST(acl_check(filename, "foo", NULL) == 0);
    TEST(acl_check(filename, "bar", NULL) == 0);
    TEST(acl_check(filename, "foo@TIM.EDU", NULL) == 1);
    TEST(acl_check(filename, "bar@TIM.EDU", NULL) == 1);

    lseek(fd, 0, SEEK_SET);
    write(fd, "*.*@TIM.EDU\n", 12);
    acl_cache_reset();
    PP("acl of *.*@TIM.EDU");

    TEST(acl_check(filename, NULL, NULL) == 0);
    TEST(acl_check(filename, "foo", NULL) == 0);
    TEST(acl_check(filename, "bar", NULL) == 0);
    TEST(acl_check(filename, "foo@TIM.EDU", NULL) == 1);
    TEST(acl_check(filename, "bar@TIM.EDU", NULL) == 1);

    lseek(fd, 0, SEEK_SET);
    write(fd, "foo@TIM.EDU\n", 12);
    acl_cache_reset();
    PP("acl of foo@TIM.EDU");


    TEST(acl_check(filename, NULL, NULL) == 0);
    TEST(acl_check(filename, "foo", NULL) == 0);
    TEST(acl_check(filename, "bar", NULL) == 0);
    TEST(acl_check(filename, "foo@TIM.EDU", NULL) == 1);
    TEST(acl_check(filename, "f\\oo@TIM.EDU", NULL) == 0);
    TEST(acl_check(filename, "bar@TIM.EDU", NULL) == 0);

    lseek(fd, 0, SEEK_SET);
    write(fd, "!bar@TIM.EDU\n*@*\n", 17);
    acl_cache_reset();
    PP("acl of !bar@TIM.EDU, *@*");

    TEST(acl_check(filename, NULL, NULL) == 0);
    TEST(acl_check(filename, "foo", NULL) == 1);
    TEST(acl_check(filename, "bar", NULL) == 1);
    TEST(acl_check(filename, "foo@TIM.EDU", NULL) == 1);
    TEST(acl_check(filename, "f\\oo@TIM.EDU", NULL) == 1);
    TEST(acl_check(filename, "bar@TIM.EDU", NULL) == 0);

    TEST(acl_check(filename, NULL, &who_zero) == 0);
    TEST(acl_check(filename, NULL, &who_localhost) == 0);

    write(fd, "@0.0.0.0\n", 9);
    acl_cache_reset();
    PP("acl +@0.0.0.0");

    TEST(acl_check(filename, NULL, &who_zero) == 1);
    TEST(acl_check(filename, NULL, &who_localhost) == 0);
    TEST(acl_check(filename, "bar@TIM.EDU", &who_zero) == 0);

    lseek(fd, 0, SEEK_SET);
    ftruncate(fd, 0);
    write(fd, "*@*\n@0.0.0.0\n!@127.0.0.0/8\n", 27);
    acl_cache_reset();
    PP("acl *@*, @0.0.0.0, !@127/8");

    TEST(acl_check(filename, NULL, &who_zero) == 1);
    TEST(acl_check(filename, "bar@TIM.EDU", &who_zero) == 1);
    TEST(acl_check(filename, "bar@TIM.EDU", &who_localhost) == 0);

    lseek(fd, 0, SEEK_SET);
    ftruncate(fd, 0);
    write(fd, "*/root@TIM.EDU\n", 15);
    acl_cache_reset();
    PP("acl */root@TIM.EDU");
    TEST(acl_check(filename, NULL, NULL) == 0);
    TEST(acl_check(filename, "foo", NULL) == 0);
    TEST(acl_check(filename, "bar", NULL) == 0);
    TEST(acl_check(filename, "bar@TIM.EDU", NULL) == 0);
    TEST(acl_check(filename, "bar@TIM.EDU", NULL) == 0);
    TEST(acl_check(filename, "foo/root@TIM.EDU", NULL) == 1);
    TEST(acl_check(filename, "bar/root@TIM.EDU", NULL) == 1);

    lseek(fd, 0, SEEK_SET);
    ftruncate(fd, 0);
    write(fd, "foo/*@TIM.EDU\n", 14);
    acl_cache_reset();
    PP("acl foo/*@TIM.EDU");
    TEST(acl_check(filename, "foo@TIM.EDU", NULL) == 0);
    TEST(acl_check(filename, "bar@TIM.EDU", NULL) == 0);
    TEST(acl_check(filename, "foo/root@TIM.EDU", NULL) == 1);
    TEST(acl_check(filename, "bar/root@TIM.EDU", NULL) == 0);

    PP("check vs. nonexistent acl");
    TEST(acl_check("/nonexistent", "foo", NULL) == 0);
    unlink(filename);
    puts("");
}
