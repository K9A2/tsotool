#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/sockios.h>

#include "rxclass.c"

#include "internal.h"
#include "modules.c"
#include "dependencies.c"

/* 
    Test demo. Run it in console with "./tsotool". No superuser privilege needed 
    to show status, but required to set it. 
*/
int main(int argc, char **argp)
{

    struct cmd_context ctx;

    ctx.devname = "wlp2s0";
    ctx.fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ctx.ifr, 0, sizeof(ctx.ifr));
    strcpy(ctx.ifr.ifr_name, ctx.devname);
    ctx.argc = 0;
    ctx.argp = 0;

    return do_gfeatures(&ctx);

}
