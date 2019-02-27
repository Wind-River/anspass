/* anspassd: Daemon to answer anspass queries and anspass-ctrl requests.
 *
 * Copyright (C) 2016-2017 Wind River Systems, Inc.
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

#include "anspassd.h"
#include "anspass-lib.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>



int main(int argv, char *argc[]) {
	int ret = -EINVAL;
	int i = 0;
	unsigned char *p;
	unsigned char *token;
	umask(0077);
	if (!is_env_set())
	{
		printf("Error: Please specify the path for anspass in %s\n",
				ANSPASS_ENV);
		goto no_env;
	}

	char *path = getenv(ANSPASS_ENV);
	ret = -ENOMEM;
	info.env_path= (char*)calloc(1, sizeof(char)*strlen(path)+1);
	if (!info.env_path)
		goto no_env_path;
	strcpy(info.env_path, path);

	ret = info_check_env_path(&info, 1);
	if (ret)
	{
		printf("Error: Failed to create %s: %d\n", info.env_path, ret);
		goto env_path_dne;
	}

	info.old_path = getcwd(NULL, 0);
	if (!info.old_path)
		goto no_old_path;

        if (chdir((const char *)info.env_path) < 0)
	{
		printf("Change dir %s failed: %s\n", info.env_path, strerror(errno));
		goto chdir_fail;
	}

	info.token = (char*)calloc(1, sizeof(char)*TOKEN_LEN+1);
	if (!info.token)
		goto no_token;

	token = (unsigned char*)calloc(1, sizeof(char)*TOKEN_LEN+1);
	if (!token)
		goto no_tmp_token;

	gcry_check_version(0);

	/* Create random string */
	gcry_randomize (token, sizeof(info.token), GCRY_STRONG_RANDOM);
	for(i = 0; i < sizeof(info.token); i++) {
		p = (unsigned char*)(token+i);
		sprintf(info.token+i*2, "%02X", *p);
	}

	/* Read db1 */
	ret = handle_db1();
	if (ret) {
		if (ret == -EACCES)
			printf("Error: Failed maximum password attempts.\n");
		else
			printf("Error handling db1: %d\n", ret);
		goto db1_fail;
	}

	ret = handle_db2();
	if (ret)
		goto db2_fail;

	ret = setup_socket(&info);
	if (ret) {
		printf("Error: Socket failed: %d\n", ret);
		goto socket_fail;
	}


	if (bind(info.socket, (struct sockaddr*)info.s_name,
				sizeof(struct sockaddr_un)))
	{
		ret = errno;
		printf("Error: Socket bind failure %d\n", ret);
		goto bind_fail;
	}

	(void) signal(SIGTERM,sig_handler);
	(void) signal(SIGHUP,sig_handler);
	info.running = 1;

	/* Print the Token after expected errors... */
	printf("Token: %s\n", info.token);

	anspass_daemon();


	close(info.socket);
bind_fail:
	unlink(info.s_name->sun_path);
	free(info.s_name);
socket_fail:
	free_all_db2_entry();
db2_fail:
	free_all_db1_entry();
db1_fail:
	free(token);
no_tmp_token:
	free(info.token);
no_token:
	if (chdir((const char *)info.old_path))
		perror("chdir");
chdir_fail:
	free(info.old_path);
no_old_path:
env_path_dne:
	free(info.env_path);
no_env_path:
	/* Fall-through expected */
no_env:
	return ret;
}

int handle_db1() {
	int ret = -EIO;
	struct db1_meta *db1m;
	uint len = strlen(info.env_path) + strlen(DB1_NAME) + 2;

	db1m = (struct db1_meta*)calloc(1, sizeof(struct db1_meta));
	if (!db1m)
		goto no_db1m;

	db1m->path = (char*)calloc(1, sizeof(char)* len);
	if (!db1m->path)
		goto no_path;

	sprintf(db1m->path, "%s/%s", info.env_path, DB1_NAME);

	if (access(db1m->path, F_OK) != -1)
	{
		ret = load_db1(db1m);
	}
	else
	{
		ret = create_db1(db1m);
	}


	free(db1m->path);
no_path:
	free(db1m);
no_db1m:
	return ret;
}
/** DB 1 **/
int create_db1(const struct db1_meta *db1m) {
	int ret = 0;
	db1.version = DB1_VERSION;
	db1.entries = 0;
	int size;
	unsigned char *unhashed = (unsigned char*)calloc(1, sizeof(char) *
			MAX_PASSWD_LEN);
	if (!unhashed)
		goto no_mem;

	/* Create random encryption string */
	gcry_randomize (dec_rand, sizeof(dec_rand), GCRY_STRONG_RANDOM);


	/* GCRY_CIPHER_CAST5 setup. */
	/* Create the global info first since that's encrypted for storage. */
	/* It's okay that passwd_hash is blank.  It's not used. */
	create_gcrypt(passwd_hash, &dec_global, NULL, NULL);

	/* Get the password */
	printf("Please enter a password for unlocking credentials\n");
	printf("(max of %d characters)\n", MAX_PASSWD_LEN);
	printf("Password:");
	size = get_secret(unhashed, MAX_PASSWD_LEN, 0);
	gcry_md_hash_buffer(GCRY_MD_MD5, (void*) passwd_hash, (const void*)
			unhashed, size);
	/* Just to be sure, overwrite unhashed in memory */
	memset(unhashed, 0, size);

	printf("\n");

	/* Encrypt the global info with the passwd */
	create_gcrypt(passwd_hash, &db1.passwd, &dec_global, &db1.global);


	struct db1_entry *e = NULL;
	ret = create_db1_entry_unsigned(dec_rand, sizeof(dec_rand), &e);
	if (ret)
		goto db1_entry_fail;

	ret = write_db1_file();
	if(ret)
		goto write_fail;

write_fail:
db1_entry_fail:
	free(unhashed);
no_mem:
	return ret;

}
int write_db1_file() {
	int ret = -ENOMEM;
	char * fn = (char*)calloc(1, sizeof(char) * (strlen(info.env_path) +
				strlen(DB1_NAME) + 2));
	if (!fn)
		goto oom;

	sprintf(fn, "%s/%s", info.env_path, DB1_NAME);

	ret = -EINVAL;
	FILE* fd = fopen(fn, "w");
	if (!fd) {
		ret = errno;
		goto fopen_fail;
	}
	ret = -EIO;
	/* Write header */
	if (!fwrite(&db1, sizeof(struct db1), 1, fd))
	{
		ret = errno;
		printf("db1: error writing %s\n", fn);
		goto fwrite_fail;
	}
	ret = 0;

	struct db1_entry* entry = db1_first;
	while(entry)
	{

		fwrite(entry, sizeof(struct db1_entry), 1, fd);
		entry = entry->next;
	}

fwrite_fail:
	fclose(fd);
fopen_fail:
oom:
	return ret;
}

int read_db1_file(const struct db1_meta *db1m) {
	int ret = -EIO;
	FILE *fd = fopen(db1m->path, "r");

	if (!fd)
	{
		ret = errno;
		printf("db1: error opening %s: %d\n", db1m->path, ret);
		goto fd_fail;
	}

	ret = -EIO;
	if (!fread(&db1, sizeof(struct db1), 1, fd))
	{
		ret = errno;
		printf("db1: error reading %s\n", db1m->path);
		goto fread_fail;
	}

	struct db1_entry *e;
	uint64_t cnt = db1.entries;
	db1.entries = 0;
	while(cnt)
	{
		cnt--;
		e = (struct db1_entry*)calloc(1, sizeof(struct db1_entry));
		if (!e)
			goto oom;
		if (!fread(e, sizeof(struct db1_entry), 1, fd))
		{
			printf("db1: error in fread.  db1.entries count mismatch?");
			free(e);
			goto entry_fail;
		}
		add_db1_entry(e);
	}
	ret = 0;

entry_fail:
	/* Fall-through expected */
oom:
	/* Fall-through expected */
fread_fail:
	fclose(fd);
fd_fail:
	return ret;
}

int load_db1(const struct db1_meta *db1m)
{
	int ret = -ENOMEM;
	int size;

	unsigned char *unhashed = (unsigned char*)calloc(1, sizeof(char) *
			MAX_PASSWD_LEN);
	if (!unhashed)
		goto nomem;

	ret = -EACCES;
	ret = read_db1_file(db1m);
	if (ret)
		goto fread_fail;

	/* Check blank password for zero prompt run */
	gcry_md_hash_buffer(GCRY_MD_MD5, (void *)passwd_hash, (const void*)
			'\0', 1);
	load_gcrypt(passwd_hash, &db1.passwd, &db1.global, &dec_global);

	/* Request passwd if password isn't blank */
	int fail = MAX_PASSWD_ATTEMPT;
	while ((ret = check_passwd(passwd_hash)) && fail > 0) {
		if (fail != MAX_PASSWD_ATTEMPT)
			printf("Incorrect password. (%d more attempts)\n",
					fail);

		printf("Password:");
		size = get_secret(unhashed, MAX_PASSWD_LEN, 0);
		printf("\n");
		gcry_md_hash_buffer(GCRY_MD_MD5, (void *)passwd_hash,
				(const void*) unhashed, size);

		/* Decrypt the global info with the passwd */
		load_gcrypt(passwd_hash, &db1.passwd, &db1.global, &dec_global);
		fail--;
	}

	free(unhashed);
nomem:
fread_fail:
	return ret;

}

int set_db_passwd(int newdb)
{
	int ret = 0;
	return ret;
}

int get_existing_passwd(char password[])
{
	int ret = 0;
	return ret;
}
int get_newdb_passwd(char password[])
{
	int ret = 0;
	return ret;
}


int check_passwd(unsigned char* passwd) {
	/* Check dec_rand against first db1 entry */
	struct db1_entry *e = NULL;

	int ret = get_db1_entry_unsigned(dec_rand, 64, &e);
	if (ret == -ENOENT)
		ret = -EACCES;

	return ret;
}

void set_passwd(char passwd[]) {
}
void print_passwd_fail(int attempt) {
}

/** END of  DB 1 **/

/* libgcrypt helpers. */
int load_gcrypt(unsigned char * cast_sym_key, struct enc_data* ed,
		struct enc_data* in, struct enc_data* out) {

	int ret = -EINVAL;
	gcry_error_t gce;
	gcry_cipher_hd_t gcry_c;

	/* Open the cipher. */
	gce = gcry_cipher_open( &gcry_c, GCRY_CIPHER, GCRY_MODE, 0);
	if (gce)
	{
		print_gcry_err(__func__, "open", gce);
		goto open_fail;
	}

	/* Set the key. */
	gce = gcry_cipher_setkey(gcry_c, cast_sym_key, KEY_LEN);
	if (gce)
	{
		print_gcry_err(__func__, "set key", gce);
		goto setkey_fail;
	}

	gce = gcry_cipher_setiv(gcry_c, ed->iv, BLK_LEN);
	if (gce)
	{
		print_gcry_err(__func__, "set iv", gce);
		goto setiv_fail;
	}

	/* Set the ctr */
	gce = gcry_cipher_setctr(gcry_c, ed->salt, BLK_LEN);
	if (gce)
	{
		print_gcry_err(__func__, "set iv", gce);
		goto setiv_fail;
	}

	if (!in || !out)
		goto no_dec;

	/* recover iv */
	gce = gcry_cipher_decrypt(gcry_c, out->iv, sizeof(out->iv),
			in->iv, sizeof(in->iv));
	if (gce)
	{
		print_gcry_err(__func__, "decrypt iv", gce);
		goto dec_iv_fail;
	}

	/* recover salt */
	gce = gcry_cipher_decrypt(gcry_c, out->salt, sizeof(out->salt),
			in->salt, sizeof(in->salt));
	if (gce)
	{
		print_gcry_err(__func__, "encrypt salt", gce);
		goto dec_salt_fail;
	}

	/* recover rand */
	gce = gcry_cipher_decrypt(gcry_c, dec_rand, sizeof(dec_rand),
			db1.enc_rand, sizeof(db1.enc_rand));
	if (gce) {
		print_gcry_err(__func__, "rand", gce);
		goto dec_rand_fail;
	}


dec_rand_fail:
	/* Fall-through expected */
dec_salt_fail:
	/* Fall-through expected */
dec_iv_fail:
	/* Fall-through expected */
no_dec:
	/* Fall-through expected */
setiv_fail:
	/* Fall-through expected */
setkey_fail:
	gcry_cipher_close(gcry_c);
open_fail:
	return ret;
}
int create_gcrypt(unsigned char * cast_sym_key, struct enc_data* ed,
		struct enc_data* in, struct enc_data* out) {

	int ret = -ENOMEM;
	gcry_error_t     gce;
	gcry_cipher_hd_t gcry_c;
	gcry_randomize (ed->iv, sizeof(ed->iv), GCRY_STRONG_RANDOM);
	gcry_randomize (ed->salt, sizeof(ed->salt), GCRY_STRONG_RANDOM);

	ret = -EINVAL;
	/* Open the cipher. */
	gce = gcry_cipher_open(
			&gcry_c,
			GCRY_CIPHER,
			GCRY_MODE,
			0);
	if (gce)
	{
		print_gcry_err(__func__, "open", gce);
		goto open_fail;
	}

	/* Set the key. */
	gce = gcry_cipher_setkey(gcry_c, cast_sym_key, KEY_LEN);
	if (gce)
	{
		print_gcry_err(__func__, "set key", gce);
		goto setkey_fail;
	}

	/* Set the IV */
	gce = gcry_cipher_setiv(gcry_c, ed->iv, BLK_LEN);
	if (gce)
	{
		print_gcry_err(__func__, "set iv", gce);
		goto setiv_fail;
	}

	/* Set the ctr */
	gce = gcry_cipher_setctr(gcry_c, ed->salt, BLK_LEN);
	if (gce)
	{
		print_gcry_err(__func__, "set iv", gce);
		goto setiv_fail;
	}

	if (!in || !out)
		goto no_enc;


	gce = gcry_cipher_encrypt(gcry_c, out->iv, sizeof(out->iv),
			in->iv, sizeof(in->iv));
	if (gce)
	{
		print_gcry_err(__func__, "encrypt iv", gce);
		goto enc_iv_fail;
	}

	gce = gcry_cipher_encrypt(gcry_c, out->salt, sizeof(out->salt),
			in->salt, sizeof(in->salt));
	if (gce)
	{
		print_gcry_err(__func__, "encrypt salt", gce);
		goto enc_salt_fail;
	}

	gce = gcry_cipher_encrypt(gcry_c, db1.enc_rand, sizeof(db1.enc_rand),
			dec_rand, sizeof(dec_rand));
	if (gce) {
		print_gcry_err(__func__, "rand", gce);
		goto rand_enc_fail;
	}



rand_enc_fail:
	/* Fall-through expected */
enc_salt_fail:
	/* Fall-through expected */
enc_iv_fail:
	/* Fall-through expected */
no_enc:
	/* Fall-through expected */
setiv_fail:
	/* Fall-through expected */
setkey_fail:
	gcry_cipher_close(gcry_c);
open_fail:
	return ret;
}

void print_gcry_err(const char* func, const char *call, gcry_error_t e) {
		syslog(LOG_PID | LOG_ERR, "%s, libgcrypt %s error: %s : %s",
				func, call, gcry_strsource(e),
				gcry_strerror(e));
}

int free_all_db1_entry() {
	struct db1_entry* entry = db1_first;
	while(entry)
	{
		db1_first = entry->next;
		free(entry);
		entry = db1_first;
	}
	/* TODO: Use tdelete to cleanup entries */
	return 0;
}

int add_db1_entry(struct db1_entry *e) {
	int ret = 0;
	struct db1_entry* last = db1_last;

	/* TODO: Use tsearch to add entries. */
	if (!db1_last)
		db1_first = e;
	else
		last->next = e;

	db1_last = e;
	e->next = NULL;
	db1.entries++;

	return ret;
}

int check_entry(struct db1_entry *e, const unsigned char *cred) {
	int ret = -ENOENT;

	if ( !memcmp(e->sum, cred, sizeof(e->sum)) )
		ret = 0;
	return ret;
}
int del_db1_entry(struct db1_entry *e) {
	int ret = -EINVAL;
	struct db1_entry *entry, *last;
	entry = db1_first;
	last = (struct db1_entry*)NULL;

	if (!e)
		goto empty;
	/* TODO: Use tdelete to delete entries. */
	if (!entry)
		goto empty;

	while(entry)
	{
		if (!check_entry(entry, e->sum))
		{
			if (entry == db1_first)
			{
				db1_first = NULL;
				if (entry->next)
					db1_first = entry->next;
			}
			if (entry == db1_last)
			{
				db1_last = db1_first;
				if (last)
					db1_last = last;
			}
			if (last)
				last->next = entry->next;

			free(entry);
			db1.entries--;
			ret = 0;
			break;
		}
		last = entry;
		entry = entry->next;
	}

empty:
	return ret;
}

int sha256_sum(const char *input, size_t len, unsigned char *output) {
	int ret = -EBADE;

	unsigned char *out;
	gcry_error_t gce;
	gcry_md_hd_t gcry_m;

	gce = gcry_md_open(&gcry_m, GCRY_MD_SHA256, 0);
	if (gce)
		goto md_open_fail;

	gcry_md_write(gcry_m, (unsigned char*)input, len);

	gcry_md_final(gcry_m);
	out = gcry_md_read(gcry_m, GCRY_MD_SHA256);
	memcpy(output, out, gcry_md_get_algo_dlen(GCRY_MD_SHA256));
	gcry_md_close(gcry_m);

	ret = 0;

md_open_fail:
	return ret;
}

int set_db1_entry_sum(const unsigned char *credential, uint len, struct
		db1_entry *e) {
	int ret = -ENOMEM;
	char *cred = (char*)calloc(1, sizeof(char) * (len + 64));
	if (!cred)
		goto no_mem_cred;

	memcpy(cred, credential, len);
	memcpy(cred+len, dec_rand, sizeof(dec_rand));

	sha256_sum(cred, len + 64, e->sum);
	memset(cred, 0, len+64);
	ret = 0;

	free(cred);
no_mem_cred:
	return ret;
}

int create_db1_entry(const char *credential, struct db1_entry **entry) {
	return create_db1_entry_unsigned((unsigned char*)credential,
			strlen(credential), entry);
}

int create_db1_entry_unsigned(const unsigned char *credential, uint len,
		struct db1_entry **entry) {
	int ret = -ENOMEM;
	struct db1_entry* e = (struct db1_entry*)calloc(1, sizeof(struct
				db1_entry));
	if (!e)
		goto no_mem_e;

	ret = set_db1_entry_sum(credential, len, e);
	if (ret)
		goto not_set;

	ret = add_db1_entry(e);
	if (ret)
		goto add_fail;

	/* Success path */
	*entry = e;
	return ret;

	/* Failure path */
add_fail:
not_set:
	free(e);
no_mem_e:
	return ret;
}

int get_db1_entry(const char *cred, struct db1_entry **e) {
	return get_db1_entry_unsigned((unsigned char *) cred, strlen(cred), e);
}

int get_db1_entry_unsigned(const unsigned char *credential, uint len,
		struct db1_entry **entry) {

	struct db1_entry *e = db1_first;
	int ret = -ENOMEM;

	char *cred = (char*)calloc(1, sizeof(char) * (len + 64));
	if (!cred)
		goto no_mem_cred;

	unsigned char *sum = (unsigned char*)calloc(1, sizeof(unsigned char) *
			gcry_md_get_algo_dlen(GCRY_MD_SHA256));
	if (!sum)
		goto no_mem_sum;

	memcpy(cred, credential, len);
	memcpy(cred+len, dec_rand, sizeof(dec_rand));
	sha256_sum(cred, len + 64,  sum);
	memset(cred, 0, len+64);

	ret = -ENOENT;
	/* TODO: Use tfind to find entries. */
	while(e)
	{
		ret = check_entry(e, sum);
		if (!ret) {
			*entry = e;
			break;
		}
		e = e->next;
	}

	free(sum);
no_mem_sum:
	free(cred);
no_mem_cred:
	return ret;

}

/* DB2 functions */

/* Database 2 setup, etc */
int handle_db2() {
	int ret = -ENOMEM;
	uint len = strlen(info.env_path) + strlen(DB2_NAME) + 2;

	char *db2_fn = (char *) calloc(1, len);
	if (!db2_fn)
		goto no_mem;

	sprintf(db2_fn, "%s/%s", info.env_path, DB2_NAME);

	if (access(db2_fn, F_OK) != -1)
		ret = load_db2(db2_fn);
	else
		ret = create_db2();

	free(db2_fn);
no_mem:
	return ret;
}

int create_db2() {
	int ret = 0;

	db2.version = DB2_VERSION;
	db2.entries = 0;
	
	ret = write_db2_file();

	return ret;
}
int load_db2(char * fn) {
	int ret = -EIO;
	FILE *fd = fopen(fn, "r");

	if (!fd)
	{
		ret = errno;
		printf("Error: cannot open db2 %s: %d", fn, ret);
		goto fd_fail;
	}

	ret = -EIO;
	if (!fread(&db2, sizeof(struct db2), 1, fd))
	{
		ret = errno;
		printf("Error reading db2: %s\n", fn);
		goto fread_fail;
	}

	struct db2_entry *e;
	uint64_t cnt = db2.entries;
	db2.entries = 0;
	while(cnt)
	{
		cnt--;
		ret = -ENOMEM;
		e = (struct db2_entry*)malloc(sizeof(struct db2_entry));
		memset(e, 0, sizeof(struct db2_entry));
		if (!e)
			goto oom;
		if (!fread(e, sizeof(struct db2_entry), 1, fd)) {
			ret = errno;
			free(e);
			goto entry_fail;
		}
		add_db2_entry(e);
	}
	ret = 0;

entry_fail:
	/* Fall-through expected */
oom:
	/* Fall-through expected */
fread_fail:
	fclose(fd);
fd_fail:
	return ret;
}
int free_all_db2_entry() {
	int ret = 0;
	return ret;
}

int create_db2_entry(struct db1_entry *e, const char *secret) {
	int ret = -ENOMEM;
	gcry_error_t gce;
	gcry_cipher_hd_t gcry_c;
	uint len = strlen(secret) * sizeof(char);
	uint len_pad = sizeof(dec_rand);
	unsigned char *padded = NULL;

	struct db2_entry *new = (struct db2_entry*)calloc(1,
			sizeof(struct db2_entry));
	if (!new)
		goto no_mem_new;

	padded = (unsigned char *)calloc(1, len+len_pad);
	if (!padded)
		goto no_mem_new;

	/* Copy the string */
	memcpy(padded, secret, len);

	/* Copy padding (64 bytes)*/
	memcpy(padded+len, dec_rand, len_pad);

	memcpy(new->sum, e->sum, sizeof(new->sum));
	ret = -EINVAL;
	gce = gcry_cipher_open( &gcry_c, GCRY_CIPHER, GCRY_MODE,
			GCRY_CIPHER_CBC_CTS);
	if (gce)
		goto gcry_open_fail;

	gce = gcry_cipher_setkey(gcry_c, passwd_hash, KEY_LEN);
	if (gce)
		goto gcry_setk_fail;

	gce = gcry_cipher_setiv(gcry_c, db1.passwd.iv, BLK_LEN);
	if(gce)
		goto gcry_setiv_fail;

	gce = gcry_cipher_setctr(gcry_c, db1.passwd.salt, BLK_LEN);
	if (gce)
		goto gcry_setctr_fail;

	gce = gcry_cipher_encrypt(gcry_c, new->enc, sizeof(new->enc), padded,
			len+len_pad);
	if (gce)
		goto encrypt_fail;

	new->len = len;
	ret = add_db2_entry(new);

encrypt_fail:
gcry_setctr_fail:
	/* Fall-through expected */
gcry_setiv_fail:
	/* Fall-through expected */
gcry_setk_fail:
	gcry_cipher_close(gcry_c);
gcry_open_fail:
	/* Fall-through expected */
	free(padded);
no_mem_new:
	return ret;
}

/* Database 2 helpers */
int add_db2_entry(struct db2_entry *e) {
	int ret = 0;
	struct db2_entry* last = db2_last;

	if (!db2_last)
		db2_first = e;
	else
		last->next = e;
	db2_last = e;
	e->next = NULL;
	db2.entries++;
	return ret;
}

int get_db2_entry(const unsigned char *sum, struct db2_entry **e) {
	int ret = -ENOENT;
	struct db2_entry *node = db2_first;

	while(node)
	{
		if (!memcmp(node->sum, sum, sizeof(node->sum))) {
			ret = 0;
			*e = node;
			break;
		}
		node = node->next;
	}
	return ret;
}
int get_db2_cred(const unsigned char *sum, char *ans) {
	int ret = -ENOENT;
	struct db2_entry *e = NULL;
	gcry_error_t gce;
	gcry_cipher_hd_t gcry_c;

	int len_pad;
	ret = get_db2_entry(sum, &e);
	if (ret)
		goto not_found;

	len_pad = e->len + sizeof(dec_rand);
	unsigned char *padded = (unsigned char *)calloc(1, len_pad);


	ret = -EINVAL;
	gce = gcry_cipher_open( &gcry_c, GCRY_CIPHER, GCRY_MODE,
			GCRY_CIPHER_CBC_CTS);
	if (gce)
		goto gcry_open_fail;

	gce = gcry_cipher_setkey(gcry_c, passwd_hash, KEY_LEN);
	if (gce)
		goto gcry_setk_fail;

	gce = gcry_cipher_setiv(gcry_c, db1.passwd.iv, BLK_LEN);
	if(gce)
		goto gcry_setiv_fail;

	gce = gcry_cipher_setctr(gcry_c, db1.passwd.salt, BLK_LEN);
	if (gce)
		goto gcry_setctr_fail;

	gce = gcry_cipher_decrypt(gcry_c, padded, len_pad,
			e->enc, len_pad);
	if (gce){
		goto decrypt_fail;
	}


	memcpy(ans, padded, e->len);
	memset(ans+e->len, '\0', 1);
	ret = 0;


decrypt_fail:
gcry_setctr_fail:
	/* Fall-through expected */
gcry_setiv_fail:
	/* Fall-through expected */
gcry_setk_fail:
	gcry_cipher_close(gcry_c);
gcry_open_fail:
	/* Fall-through expected */
not_found:
	return ret;
}
int del_db2_cred(const struct db1_entry *e) {
	int ret = -EINVAL;
	struct db2_entry *entry, *last;
	entry = db2_first;
	last = (struct db2_entry*)NULL;

	if (!entry)
		goto empty;

	while(entry)
	{
		if (!memcmp(entry->sum, e->sum, sizeof(e->sum)))
		{
			if (entry == db2_first)
			{
				db2_first = NULL;
				if (entry->next)
					db2_first = entry->next;
			}
			if (entry == db2_last)
			{
				db2_last = db2_first;
				if (last)
					db2_last = last;
			}
			if (last)
				last->next = entry->next;

			free(entry);
			db2.entries--;
			ret = 0;
			break;
		}
		last = entry;
		entry = entry->next;
	}

empty:
	return ret;
}

int write_db2_file() {
	int ret = -ENOMEM;
	char * fn = (char*)calloc(1, sizeof(char) * (strlen(info.env_path) +
				strlen(DB2_NAME) + 2));
	if (!fn)
		goto oom;

	sprintf(fn, "%s/%s", info.env_path, DB2_NAME);

	ret = -EINVAL;
	FILE* fd = fopen(fn, "w");
	if (!fd) {
		ret = errno;
		goto fopen_fail;
	}
	ret = -EIO;
	/* Write header */
	if (!fwrite(&db2, sizeof(struct db2), 1, fd))
	{
		ret = errno;
		printf("db2: error writing %s\n", fn);
		goto fwrite_fail;
	}
	ret = 0;

	struct db2_entry* entry = db2_first;
	while(entry)
	{
		fwrite(entry, sizeof(struct db2_entry), 1, fd);
		entry = entry->next;
	}


fwrite_fail:
	fclose(fd);
fopen_fail:
oom:
	return ret;

}


/* Connection helpers. */
int check_for_request() {
	int ret = -ENOMEM;
	int socket;
	struct anspass_packet *pkt =
		(struct anspass_packet*)malloc(sizeof(struct anspass_packet));
	if (!pkt)
		goto no_pkt_mem;

	struct timeval *to = (struct timeval*)calloc(1, sizeof(struct timeval));
	if (!to)
		goto no_to_mem;

	/* Wait for a packet for 1s */
	to->tv_sec = 1;
	to->tv_usec = 500*1000;

	pkt->socket = info.socket;
	pkt->to = to;

	ret = check_for_data(pkt);
	if (!ret)
		goto no_data;

	if (ret < 0)
		goto error_data;


	socklen_t addr_size = sizeof(struct sockaddr_un);
	socket = accept(info.socket, (struct sockaddr*)info.s_name,
			&addr_size);
	if (socket == -1)
	{
		ret = -errno;
		goto accept_fail;
	}

	pkt->socket = socket;
	ret = get_data(pkt);

	if (!ret)
		goto no_packet;

	if (ret == -1)
	{
		ret = -errno;
		goto error_recv;
	}


	pkt->socket = socket;
	if (is_request_valid(pkt))
		process_request(pkt);

error_recv:
no_packet:
	close(socket);
accept_fail:
error_data:
no_data:
	free(to);
no_to_mem:
	free(pkt);
no_pkt_mem:
	return ret;
}

int is_request_valid(struct anspass_packet *packet) {
	int ret = 0;
	if (!memcmp(packet->token, info.token, strlen(info.token)))
		ret = 1;

	return ret;
}

static inline int get_passwd_len(char *msg, char *user) {
	return sizeof(char) * (strlen(msg) + strlen(user) +
			strlen(PASSWORD_STR) + 12);
}

static inline void get_passwd_str(char *passwd, struct anspass_packet *in) {
	char *token;
	char *d = "/";

	char *msg = (char*)calloc(1, strlen(in->msg) + 1);
	if (!msg)
		goto oom;
	memcpy(msg, in->msg, strlen(in->msg) + 1);

	token = strtok(msg, d);
	sprintf(passwd, "%s'%s//", PASSWORD_STR, token);
	strcat(passwd, in->user);
	strcat(passwd, "@");
	token = strtok(NULL, d);
	if(token)
		strcat(passwd, token);
	token = strtok(NULL, d);
	while(token) {
		strcat(passwd, "/");
		strcat(passwd, token);
		token = strtok(NULL, d);
	}
	strcat(passwd, "': ");
	free(msg);
oom:
	return;
}

void process_request(struct anspass_packet *in) {

	syslog(LOG_PID | LOG_DEBUG, "Received packet: \"%s\"\n", in->msg);

	switch(in->type) {
	case QUERY:
		process_query(in);
		break;
	case ADD:
		process_add(in);
		break;
	case DEL:
		process_del(in);
		break;
	case UPDATE:
		process_update(in);
		break;
	case RESET:
		process_reset(in);
		break;
	case SHUTDOWN:
		process_shutdown(in);
		break;
	case PASSWD_UPDATE:
		//process_passwd_update(in);
		break;

	}

	return;
}

void process_query(struct anspass_packet *in) {

	int ret = -ENOENT;
	struct db1_entry *e = NULL;
	struct anspass_packet *out =
		(struct anspass_packet*)calloc(1, sizeof(struct anspass_packet));
	if (!out)
		goto no_out_mem;

	char * answer = (char*)calloc(1, sizeof(char) * MAX_PASSWD_LEN);
	if (!answer)
		goto no_ans_mem;

	out->socket = in->socket;
	out->type = ACK;

	/* contrary to add/delete, the in->msg will contain USERNAME_STR and
	 * PASSWORD_STR already.
	 */
	ret = get_db1_entry(in->msg, &e);
	if (ret)
		goto dne;

	ret = get_db2_cred(e->sum, answer);
	if (ret)
		goto dne;
	memcpy(out->msg, answer, strlen(answer));

dne:
	if (ret)
		syslog(LOG_PID | LOG_DEBUG, "%s: %d\n", __func__, ret);
	out->ret = ret;
	ret = put_data(out);
	if (ret)
		syslog(LOG_PID | LOG_ERR, "Cannot send packet: %d\n", ret);

	free(answer);
no_ans_mem:
	free(out);
no_out_mem:
	return;
}

int del (struct anspass_packet *in){
	int ret = 0;
	struct db1_entry *e_user = NULL;
	struct db1_entry *e_passwd = NULL;


	char* passwd = (char*)calloc(1, get_passwd_len(in->msg, in->user));
	if (!passwd)
		goto no_passwd_mem;
	char* user = (char*)calloc(1, sizeof(char) * (strlen(in->msg) +
				strlen(USERNAME_STR) + 5));
	if (!user)
		goto no_user_mem;

	/* Username string is easy */
	sprintf(user, "%s'%s': ", USERNAME_STR, in->msg);

	/* Passwd has to insert username into the URI */
	get_passwd_str(passwd, in);

	ret = get_db1_entry(user, &e_user);
	if (ret)
		goto user_dne;

	ret = get_db1_entry(passwd, &e_passwd);
	if (ret)
		goto passwd_dne;

	ret = del_db2_cred(e_user);
	if (ret)
		goto del_db2_user_fail;

	ret = del_db1_entry(e_user);
	if (ret)
		goto del_user_fail;
	e_user = NULL;

	ret = del_db2_cred(e_passwd);
	if (ret)
		goto del_db2_passwd_fail;

	ret = del_db1_entry(e_passwd);
	if (ret)
		goto del_passwd_fail;
	e_passwd = NULL;

	ret = 0;

	/* Un-roll. */
del_passwd_fail:
	/* Fall-through expected */
del_db2_passwd_fail:
	if (e_passwd) {
		del_db2_cred(e_passwd);
		del_db1_entry(e_passwd);
		e_passwd = NULL;
	}

del_user_fail:
	if (e_user) {
		del_db1_entry(e_user);
		e_user = NULL;
	}

del_db2_user_fail:
	/* Fall-through expected */
passwd_dne:
	/* Fall-through expected */
user_dne:

	free(user);
no_user_mem:
	free(passwd);
no_passwd_mem:
	return ret;
}
void process_del(struct anspass_packet *in){
	int ret = 0;
	struct anspass_packet *out =
		(struct anspass_packet*)calloc(1, sizeof(struct anspass_packet));
	if (!out)
		goto no_out_mem;
	syslog(LOG_PID | LOG_DEBUG, "Deleting %s (%s)\n", in->msg, in->user);

	out->socket = in->socket;
	out->type = ACK;
	out->ret = del(in);
	ret = put_data(out);
	if (ret)
		syslog(LOG_PID | LOG_ERR, "Cannot send packet: %d\n", ret);
	free(out);
no_out_mem:
	return;
}


	/* Must add two entries (username/password) */
int add(struct anspass_packet *in) {
	int ret = -ENOMEM;
	struct db1_entry *e_user = NULL;
	struct db1_entry *e_passwd = NULL;
	char* passwd = (char*)calloc(1, get_passwd_len(in->msg, in->user));
	if (!passwd)
		goto no_passwd_mem;


	char* user = (char*)calloc(1, sizeof(char) * (strlen(in->msg) +
				strlen(USERNAME_STR) + 5));
	if (!user)
		goto no_user_mem;
	/* Username string is easy */
	sprintf(user, "%s'%s': ", USERNAME_STR, in->msg);

	/* Passwd has to insert username into the URI */
	get_passwd_str(passwd, in);


	ret = get_db1_entry(user, &e_user);
	if (!ret)
	{
		ret = -EEXIST;
		goto user_exists;
	}

	ret = get_db1_entry(passwd, &e_passwd);
	if (!ret)
	{
		ret = -EEXIST;
		goto passwd_exists;
	}

	ret = create_db1_entry(user, &e_user);
	if (ret)
		goto create_user_fail;

	ret = create_db2_entry(e_user, in->user);
	if (ret)
		goto create_db2_user_fail;

	ret = create_db1_entry(passwd, &e_passwd);
	if (ret)
		goto create_passwd_fail;

	ret = create_db2_entry(e_passwd, in->passwd);
	if (ret)
		goto create_db2_passwd_fail;




	/* Un-roll & answer. */

	if (ret)
		del_db2_cred(e_passwd);
create_db2_passwd_fail:
	if (ret)
		del_db1_entry(e_passwd);
create_passwd_fail:
	if (ret)
		del_db2_cred(e_user);
create_db2_user_fail:
	if (ret)
		del_db1_entry(e_user);
create_user_fail:
	/* Fall-through expected */
passwd_exists:
	/* Fall-through expected */
user_exists:
	free(user);
no_user_mem:
	free(passwd);
no_passwd_mem:
	return ret;
}
void process_add(struct anspass_packet *in) {
	int ret = 0;

	struct anspass_packet *out =
		(struct anspass_packet*)calloc(1, sizeof(struct anspass_packet));
	if (!out)
		goto no_out_mem;
	syslog(LOG_PID | LOG_DEBUG , "Adding %s (%s)\n", in->msg, in->user);

	out->socket = in->socket;
	out->type = ACK;
	out->ret = add(in);

	ret = put_data(out);
	if (ret)
		syslog(LOG_PID, "Cannot send packet: %d\n", ret);
	free(out);
no_out_mem:
	return;
}

void process_update(struct anspass_packet *in) {
	int ret;
	struct anspass_packet *out =
		(struct anspass_packet*)calloc(1, sizeof(struct anspass_packet));
	if (!out)
		goto no_out_mem;

	ret = del(in);
	syslog(LOG_PID | LOG_DEBUG , "Deleting %s (%s)\n", in->msg, in->user);
	if (ret)
		goto del_fail;

	out->socket = in->socket;
	out->type = ACK;
	out->ret = add(in);
	syslog(LOG_PID | LOG_DEBUG , "Adding %s (%s)\n", in->msg, in->user);

	ret = put_data(out);
	if (ret)
		syslog(LOG_PID | LOG_ERR, "Cannot send packet: %d\n", ret);
	free(out);

del_fail:
no_out_mem:
	return;
	
}
void process_reset(struct anspass_packet *in) {

	int ret = 0;
	struct anspass_packet *out =
		(struct anspass_packet*)calloc(1, sizeof(struct anspass_packet));
	if (!out)
		goto no_out_mem;

	syslog(LOG_PID | LOG_INFO, "Resetting databases\n");

	if (db1.entries <= 1)
		goto done;

	struct db1_entry *db1_e = db1_first->next;
	struct db1_entry *db1_e_runner = db1_e->next;

	while(db1_e)
	{
		del_db2_cred(db1_e);
		db1_e = db1_e_runner;
		if (db1_e)
			db1_e_runner = db1_e->next;
	}

	db1_e = db1_first->next;
	while(db1_e)
	{
		del_db1_entry(db1_e);
		db1_e = db1_first->next;
	}


done:
	out->socket = in->socket;
	out->type = ACK;
	out->ret = 0;
	syslog(LOG_PID | LOG_DEBUG, "Reset complete.\n");

	ret = put_data(out);
	if (ret)
		syslog(LOG_PID | LOG_ERR, "Cannot send packet: %d\n", ret);

	free(out);
no_out_mem:
	return;
}

void process_shutdown(struct anspass_packet *in) {
	int ret = 0;
	struct anspass_packet *out =
		(struct anspass_packet*)calloc(1, sizeof(struct anspass_packet));
	if (!out)
		goto no_out_mem;

	info.running = 0;

	out->socket = in->socket;
	out->type = ACK;
	out->ret = 0;
	syslog(LOG_PID | LOG_DEBUG, "Shutdown requested.\n");

	ret = put_data(out);
	if (ret)
		syslog(LOG_PID | LOG_ERR, "Cannot send packet: %d\n", ret);

	free(out);
no_out_mem:
	return;
}

/* Daemon and signal control */
void anspass_daemon() {

	pid_t pid, sid;
	int ret;

	/* Fork the child */
	pid = fork();
	if (pid < 0)
	{
		exit(-1);
	}

	/* Parent exits */
	if (pid > 0)
	{
		exit(0);
	}

	/* Change the file mode mask */
	umask(0);

	/* Open syslog */
	openlog (SYSLOG_NAME, LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_PID | LOG_INFO, "Started.");

	syslog(LOG_PID | LOG_DEBUG, "DB1 loaded at %s/%s with %lu entries.\n",
			info.env_path, DB1_NAME, db1.entries);
	syslog(LOG_PID | LOG_DEBUG, "DB2 loaded at %s/%s with %lu entries.\n",
			info.env_path, DB2_NAME, db2.entries);

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0)
	{
		printf("setsid failed\n");
		exit(-1);
	}

	/* Close fds. */
	close(0);
	close(1);
	close(2);

	char *path = getenv(ANSPASS_ENV);

	/* Change the current working directory */
	if ((chdir(path)) < 0)
	{
		printf("Error: Cannot find path %s\n", path);
		exit(-1);
	}


	/* Start listening */
	if (listen(info.socket, 64) < 0)
	{
		ret = -errno;
		printf("Error: Cannot listen for connections: %d\n", ret);
		goto not_listening;
	}

	/* Release the hounds! */
	while (info.running)
	{
		ret = check_for_request();
		if (ret < 0)
		{
			syslog(LOG_PID | LOG_ERR, "Error: checking for request: %d\n",
					ret);
			info.running = 0;
		}
	}
	syslog(LOG_PID | LOG_INFO, "Stopped.\n");
	write_db1_file();
	write_db2_file();
not_listening:
	closelog();
}

void stop() {
	info.running = 0;
}


void reinit() {
	/* Be sure the daemon isn't exiting. */
	if (!info.running)
		return;
	syslog(LOG_PID | LOG_DEBUG, "re-init not supported yet\n");
}

void sig_handler(int sig) {
	switch(sig) {
	case SIGTERM:
		stop();
		break;
	case SIGHUP:
		reinit();
		break;
	default:
		break;
	}
}

