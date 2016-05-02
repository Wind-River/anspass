#ifndef ANSPASS_H
#define ANSPASS_H

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "anspass-lib.h"

int wait_for_reply(char *msg);
struct anspass_info info;


#endif
