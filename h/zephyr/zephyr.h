#include <zephyr/mit-copyright.h>

/* $Source$ */
/* $Header$ */

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#define ZVERSION	0

/* Types */

	/* Packet */
typedef char ZPacket_t[BUFSIZ];

	/* Packet type */
typedef enum { REQUEST, INFORM, NOTIFY, ACKNOWLEDGE } ZNotice_Kind_t;

	/* Unique ID format */
typedef struct _ZUnique_Id_t {
	struct	in_addr zuid_addr;
	struct	timeval	tv;
} ZUnique_Id_t;

	/* Checksum */
typedef int ZChecksum_t[2];

	/* Notice definition */
typedef struct _ZNotice_t {
	ZNotice_Kind_t	z_kind;
	ZChecksum_t	z_checksum;
	ZUnique_Id_t	z_uid;
#define z_sender_addr	z_uid.zuid_addr;
	short		z_port;
	char		*z_class;
	char		*z_class_inst;
	char		*z_opcode;
	char		*z_sender;
	char		*z_recipient;
	caddr_t		*z_message;
	int		z_message_len;
} ZNotice_t;

	/* Function return code */
typedef int Code_t;

	/* Socket file descriptor */
extern int __Zephyr_fd;

	/* Port number */
extern int __Zephyr_port;

	/* ZGetFD() macro */
#define ZGetFD() (__Zephyr_fd)

	/* Maximum packet length */
#define Z_MAXPKTLEN		576

	/* External UNIX errors */
extern int errno;

/* Error codes */

#define ZERR_NONE		0

#define ZERR_UNIX		999

#define ZERR_FIRST		1000

#define ZERR_PKTLEN		1000	/* Packet too long/buffer too small */
#define ZERR_ILLVAL		1001	/* Illegal parameter */
#define ZERR_HMPORT		1002	/* Can't get host manager port */
#define ZERR_NOMEM		1003	/* No memory */
#define ZERR_PORTINUSE		1004	/* Can't assign port */
#define ZERR_BADPKT		1005	/* Bad incoming packet */
#define ZERR_VERS		1006	/* Bad version # in packet */
#define ZERR_NOPORT		1007	/* No port opened */

#define	ZERR_S_FIRST		2000	/* internal server error codes */
#define	ZERR_S_LAST		3000
