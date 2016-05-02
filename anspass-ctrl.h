#ifndef ANSPASS_H
#define ANSPASS_H

#include "anspass-lib.h"
#include "errno.h"


void print_help(int context);
int handle_add(char *info);
int handle_del(char *info);
int handle_update(char *info);
int handle_reset(char *info);

int wait_ack_reply();

struct anspass_info info;
#endif
