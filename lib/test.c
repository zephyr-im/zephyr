/*gcc -g -I../h -I/usr/local/include test.c -o test -L/usr/local/lib libzephyr.a -lkrb5 -lasn1 -lkrb -ldes -lcom_err*/
#include <zephyr/zephyr.h>

Z_AuthProc auth;

#define MSLEN 300

main(){
  static ZNotice_t notice;
  int result;
  int len=MSLEN;
  char bar[512] = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901";
  char *foo=(char *)malloc((unsigned)len*4);
  char *qux=(char *)malloc((unsigned)len*4);
  Code_t retval;
  ZNotice_t newnotice;
  char *buffer;
  int tauth;
  struct sockaddr_in from;

  ZInitialize();

  notice.z_kind = ACKED;
  notice.z_port = 0;
  notice.z_class = "message";
  notice.z_class_inst = "personal";
  notice.z_opcode = "PING";
  notice.z_sender = 0;
  notice.z_default_format = "Class $class, Instance $instance:\nTo: @bold($recipient) at $time $date\n$message";
  notice.z_message = bar;
  notice.z_message_len = MSLEN;
  notice.z_recipient = "shadow@DEMENTIA.ORG";
  auth = ZMakeZcodeAuthentication;

  if ((result = ZNewFormatNotice(&notice, &buffer, &len, 
			      auth)) != ZERR_NONE)
    return (result);

    {
      int i;
        printf("Z_FormatRawHeader output:\n");
        for (i = 0; i < len; i += 16) {
            int i2;
            printf("%03d:", i);
            for (i2 = i; i2 < i+16 && i2 < len; i2++)
                printf(" %02x", buffer[i2] & 0xff);
            for (; i2 < i+16; i2++)
                printf("   ");
            printf("  ");
            for (i2 = i; i2 < i+16 && i2 < len; i2++)
                printf("%c",
                       ((buffer[i2] > 0 && buffer[i2] < 127 && isprint(buffer[i2]))
                        ? buffer[i2]
                        : '.'));
            printf("\n");
        }
    }

  printf("first len %d %s\n", len, buffer);

  if ((retval = ZParseNotice(buffer, len, &newnotice)) != ZERR_NONE)
    return (retval);

  tauth = ZCheckZcodeAuthentication(&newnotice,&from);
  printf("Class = %s Instance = %s Sender = %s\nTime = %s Auth = %d\n",
	 newnotice.z_class,newnotice.z_class_inst,newnotice.z_sender,
	 ctime(&newnotice.z_time.tv_sec),tauth);
  printf("Len = %d\n",newnotice.z_message_len);
  printf("%s\n",newnotice.z_message);

  len = MSLEN;
  if ((result = ZMakeZcode(foo,
			   len*3,
			   bar,
			   len)) != ZERR_NONE) {
    free(foo);
    return result;
  }

  printf("len %d %s\n", len, foo);
  len=MSLEN*3;
  if ((result = ZReadZcode(foo, qux, len, &len)) != ZERR_NONE) {
    free(qux);
    return result;
  }
  printf("len %d Z%s\n", len, qux);
}
