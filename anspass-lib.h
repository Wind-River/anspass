/* anspass-lib: Library for common anspass functions used in anspassd, anspass,
 * and anspass-ctrl
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

#ifndef ANSPASSLIBH
#define ANSPASSLIBH

#include <stdlib.h>
#include <stdint.h>

#include "gcrypt.h"

#define ANSPASS_ENV             "ANSPASS_PATH"
#define ANSPASS_TOKEN           "ANSPASS_TOKEN"

#define MAX_PASSWD_ATTEMPT      3
#define MAX_MSG_LENGTH          1024
#define SOCKET_NAME             "/socket"

#define TOKEN_LEN               16

#define QUERY                   1
#define ADD                     2
#define DEL                     3
#define UPDATE                  4
#define RESET                   5
#define PASSWD_UPDATE           6
#define SHUTDOWN                7
#define ACK                     104

struct anspass_packet {
	int socket;
	struct timeval *to;
	int type;
	int ret;                        /* To return errno code */
	char msg[MAX_MSG_LENGTH];
	char user[MAX_MSG_LENGTH];
	char passwd[MAX_MSG_LENGTH];
	char token[TOKEN_LEN];

} __attribute__((__packed__));

struct anspass_info {
	char *token;
	struct sockaddr_un *s_name;
	int socket;
	int running;
	char *env_path;
};

int is_env_set();
int is_token_set();
int get_header(struct anspass_packet *packet);
int check_for_data(struct anspass_packet *packet);
int get_data(struct anspass_packet *packet);
int info_check_env_path(struct anspass_info *info, int create);
int put_data(struct anspass_packet *packet);
int send_request(struct anspass_info *info, int type, char *msg);
int setup_socket();
unsigned char* string_to_hex(char * str);

int get_secret(unsigned char* text, const uint max, const int echo);
void print_env(const char* missing);
#endif
