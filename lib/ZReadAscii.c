/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZParseNotice function.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

int ZReadAscii(ptr,temp,num)
	char *ptr;
	char *temp;
	int num;
{
	int i;
	char bfr[3];

	for (i=0;i<num;i++) {
		if (*ptr == ' ')
			ptr++;
		if (ptr[0] == '0' && ptr[1] == 'x')
			ptr += 2;
		bfr[0] = ptr[0];
		bfr[1] = ptr[1];
		bfr[2] = '\0';
		if (!bfr[0] || !bfr[1])
			return (ZERR_BADFIELD);
		sscanf(bfr,"%x",temp+i);
		ptr += 2;
	}

	if (*ptr)
		return (ZERR_BADFIELD);

	return (ZERR_NONE);
}
