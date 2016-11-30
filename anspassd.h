/*
 * anspassd: Daemon to answer anspass queries and anspass-ctrl requests.
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
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include "anspass-lib.h"

#define SYSLOG_NAME             "anspassd"

#define WAIT_TIME               2

#define DB1_VERSION             1
#define DB1_NAME                "conf.db"

#define DB2_VERSION             1
#define DB2_NAME                "secret.db"

#define MAX_PASSWD_LEN          256


#define KEY_LEN                 16 /* 128 bits / 8 = 16 bytes */
#define BLK_LEN                 8
#define GCRY_CIPHER             GCRY_CIPHER_CAST5
#define GCRY_MODE               GCRY_CIPHER_MODE_CBC

#define USERNAME_STR            "Username for "
#define PASSWORD_STR            "Password for "

/** Structures **/
/* DB1 structs */
struct enc_data {
	unsigned char salt[16];
	unsigned char iv[16];
} __attribute__((__packed__));

struct db1 {
	uint64_t version;
	struct enc_data passwd;
	struct enc_data global;
	unsigned char enc_rand[64];
	uint64_t entries;
} __attribute__((__packed__));

/* Exists in case more meta information is needed */
struct db1_meta {
	char* path;
};

/* db1 entries are encrypted sha256 sums of (credential + dec_rand)*/
struct db1_entry {
	unsigned char sum[32];
	struct db1_entry *next;
} __attribute__((__packed__));

/* End of DB1 structure definitions */

/* DB2 structs */
struct db2 {
	uint64_t version;
	uint64_t entries;
} __attribute__((__packed__));

struct db2_entry {
	unsigned char sum[32];
	unsigned char enc[MAX_PASSWD_LEN];
	uint64_t len;
	struct db2_entry *next;

} __attribute__((__packed__));

/* Global vars */
struct anspass_info info;
struct db1 db1;
struct db2 db2;
struct enc_data dec_global;
unsigned char passwd_hash[KEY_LEN];
unsigned char dec_rand[64];
struct db1_entry *db1_first;
struct db1_entry *db1_last;
struct db2_entry *db2_first;
struct db2_entry *db2_last;


/* Database setup, etc */
int handle_db1();
int create_db1(const struct db1_meta *db1m);
int load_db1(const struct db1_meta *db1m);
int set_db_passwd(int newdb);
int get_existing_passwd(char password[]);
int get_newdb_passwd(char password[]);
int check_passwd(unsigned char* passwd);
void set_passwd(char* passwd);
void print_passwd_fail(int attempt);



/* Database 1 helpers */
int create_db1_entry(const char *credential, struct db1_entry **e);
int create_db1_entry_unsigned(const unsigned char *credential, uint len,
		struct db1_entry **e);
int add_db1_entry(struct db1_entry *e);
int write_db1_file();
int read_db1_file(const struct db1_meta *db1m);
int free_all_db1_entry();
int get_db1_entry(const char *cred, struct db1_entry **e);
int get_db1_entry_unsigned(const unsigned char *credential, uint len,
		struct db1_entry **e);

/* Database 2 setup, etc */
int handle_db2();
int create_db2();
int load_db2(char *fn);
int free_all_db2_entry();

/* Database 2 helpers */
int add_db2_entry(struct db2_entry *e);
int get_db2_entry(const unsigned char *sum, struct db2_entry **e);
int get_db2_cred(const unsigned char *sum, char *ans);
int del_db2_cred(const struct db1_entry *e);
int write_db2_file();


/* libgcrypt helpers */
int load_gcrypt(unsigned char * cast_sym_key, struct enc_data* ed,
		struct enc_data* in, struct enc_data* out);
int create_gcrypt(unsigned char * cast_sym_key, struct enc_data* ed,
		struct enc_data* in, struct enc_data* out);

void print_gcry_err(const char *func, const char *call, gcry_error_t e);
int create_db2_entry(struct db1_entry *e, const char *secret);

/* Connection helpers */
int setup_socket();
int check_for_request();
int is_request_valid(struct anspass_packet *packet);
void process_request(struct anspass_packet *packet);

/* Process request types */
void process_query(struct anspass_packet *in);
void process_add(struct anspass_packet *in);
void process_del(struct anspass_packet *in);
void process_reset(struct anspass_packet *in);
void process_update(struct anspass_packet *in);
void process_shutdown(struct anspass_packet *in);


/* Daemon and signal control */
void anspass_daemon();
void stop();
void reinit();
void sig_handler(int sig);
