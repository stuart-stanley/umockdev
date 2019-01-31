#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "debug.h"

unsigned debug_categories = 0;

void
init_debug(void)
{
    const char *d = getenv("UMOCKDEV_DEBUG");
    char *d_copy, *token;
    if (d == NULL)
	return;
    d_copy = strdup(d);
    for (token = strtok(d_copy, " ,"); token; token = strtok(NULL, " ,")) {
	if (strcmp (token, "all") == 0)
	    debug_categories = ~0;
	else if (strcmp (token, "path") == 0)
	    debug_categories |= DBG_PATH;
	else if (strcmp (token, "netlink") == 0)
	    debug_categories |= DBG_NETLINK;
	else if (strcmp (token, "script") == 0)
	    debug_categories |= DBG_SCRIPT;
	else if (strcmp (token, "ioctl") == 0)
	    debug_categories |= DBG_IOCTL;
	else if (strcmp (token, "ioctl-tree") == 0)
	    debug_categories |= DBG_IOCTL_TREE;
	else if (strcmp (token, "pysim") == 0)
	    debug_categories |= DBG_PSI;
	else if (strcmp (token, "mmap") == 0)
	    debug_categories |= DBG_MMAP;
	else if (strcmp (token, "gf") == 0)
	    debug_categories |= DBG_GF;
	else if (strcmp (token, "thread") == 0)
	    debug_categories |= DBG_GF;
	else {
	    fprintf(stderr, "Invalid UMOCKDEV_DEBUG category %s. Valid values are: path netlink ioctl ioctl-tree script pysim mmap gf thread all\n", token);
	    abort();
	}
    }
    free(d_copy);
}
