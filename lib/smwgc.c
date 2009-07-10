/*	Copyright (c) 1988 by the Massachusetts Institute of Technology.
 *	All Rights Reserved.
 */
#include <zephyr/zephyr.h>

main()
{
    FILE *fp;
    char buf[512],*ptr;
    int auth,retval;
    u_short port;
    ZNotice_t notice;
    ZSubscription_t sub;
    struct sockaddr_in from;
	
    if ((retval = ZInitialize()) != ZERR_NONE) {
	com_err("foo",retval,"initing");
	exit(1);
    } 

    port = 0;
    if ((retval = ZOpenPort(&port)) != ZERR_NONE) {
	com_err("foo",retval,"opening port");
	exit(1);
    }
    printf("Using port %d\n",(int)port);
    sprintf(buf,"/tmp/wg.%d",getuid());
    fp = fopen(buf,"w");
    if (!fp) {
	com_err("foo",errno,"opening file");
	exit(1);
    } 
    fprintf(fp,"%d\n",(int)port);
    fclose(fp);

    printf("All ready...\n");

    sub.class = "MESSAGE";
    sub.classinst = "PERSONAL";
    sub.recipient = ZGetSender();

    if ((retval = ZSubscribeTo(&sub,1,port)) != ZERR_NONE) {
	com_err("foo",retval,"subscribing");
	exit(1);
    } 
    for (;;) {
	if ((retval = ZReceiveNotice(&notice,&from)) != ZERR_NONE) {
	    com_err("foo",retval,"receiving packet");
	    continue;
	}
	auth = ZCheckAuthentication(&notice,&from);
	printf("Class = %s Instance = %s Sender = %s\nTime = %s Auth = %d\n",
	       notice.z_class,notice.z_class_inst,notice.z_sender,
	       ctime(&notice.z_time.tv_sec),auth);
	printf("Len = %d\n",notice.z_message_len);
/*	ptr = notice.z_message;
	for (;ptr<notice.z_message+notice.z_message_len;) {
	    printf("%s\n",ptr);
	    ptr += strlen(ptr)+1;
	}
	printf("\n");*/
	ZFreeNotice(&notice);
    }
}
