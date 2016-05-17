/* anspass-ctrl: utility to add/delete/update/reset password database for
 *               the anspassd server and anspass client.
 *
 * Copyright (C) 2016 Wind River Systems, Inc.
 * Written by Liam R. Howlett <Liam.Howlett@Windriver.com>
 *
 * This file is part of anspass
 *
 * anspass is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * anspass is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

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
