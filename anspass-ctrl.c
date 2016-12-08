#include "anspass-ctrl.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>

#ifndef VERSION
#define VERSION "dev"
#endif

int main(int argc, char *argv[]) {
	int ret = -EINVAL;
	int (*cmd)(char*) = NULL;
	char *url, *env;
	int c;

	int inval = 0;
	if (!is_env_set())
	{
		print_env(ANSPASS_ENV);
		inval = 1;
	}

	if (!is_token_set())
	{
		print_env(ANSPASS_TOKEN);
		inval = 1;
	}

	if (argc != 2 && argc != 3)
	{
		print_help(1);
		inval = 1;
	}
	if (inval)
		goto missing_options;


	ret = -ENOMEM;
	url = (char*)calloc(1, sizeof(char)*MAX_MSG_LENGTH);
	if (!url)
		goto no_url_mem;

	ret = -EINVAL;
	static struct option long_options[] =
	{
		{"add",     required_argument, 0, 'a'},
		{"delete",  required_argument, 0, 'd'},
		{"update",  required_argument, 0, 'u'},
		{"reset",   no_argument,       0, 'r'},
		{"quit",    no_argument,       0, 'q'},
		{"help",    no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};
	int option_index = 0;
	while((c = getopt_long (argc, argv, "a:d:u:rqh", long_options,
					&option_index)) != -1)
	{
		if (optarg && strlen(optarg) > MAX_MSG_LENGTH - 1)
		{
			printf("Error: option too long: %s\n", optarg);
			goto too_long;
		}

		switch (c)
		{
		case 'a': /* Add */
			cmd = &handle_add;
			memcpy(url, optarg, strlen(optarg)+ 1);
			break;
		case 'd': /* Delete*/
			cmd = &handle_del;
			memcpy(url, optarg, strlen(optarg) + 1);
			break;
		case 'u': /* Update */
			cmd = &handle_update;
			memcpy(url, optarg, strlen(optarg) + 1);
			break;
		case 'r': /* Reset */
			cmd = &handle_reset;
			break;
		case 'q': /* Reset */
			cmd = &handle_quit;
			break;
		case 'h': /* Help */
			ret = 0;
			/* fall-through expected */
		default:
			print_help(ret);
			goto help;
		}
	}


	ret = -ENOMEM;
	env = getenv(ANSPASS_ENV);
	info.env_path= (char*)calloc(1, sizeof(char)*strlen(env)+1);
	if (!info.env_path)
		goto no_env_path;
	strcpy(info.env_path, env);

	info.old_path = getcwd(NULL, 0);
	if (!info.old_path)
		goto no_old_path;

	if (chdir((const char *)info.env_path) < 0)
	{
		printf("Change dir %s failed: %s\n", info.env_path, strerror(errno));
		goto chdir_fail;
	}

	env = getenv(ANSPASS_TOKEN);
	info.token = (char*)calloc(1, sizeof(char)*TOKEN_LEN+1);
	if (!info.token)
		goto no_token_mem;
	strncpy(info.token, env, TOKEN_LEN);

	ret = setup_socket(&info);
	if (ret) {
		printf("Error: Socket failed: %d\n", ret);
		goto socket_fail;
	}

	ret = -ENOTCONN;
	if (connect(info.socket, (struct sockaddr *)info.s_name, sizeof(struct
					sockaddr_un)) == -1)
	{
		ret = errno;
		printf("Error: Connection refused: %d\n", ret);
		goto not_connected;
	}

	ret = cmd(url);

	close(info.socket);
not_connected:
	free(info.s_name);
socket_fail:
	free(info.token);
no_token_mem:
	if(chdir((const char *)info.old_path))
		perror("chdir");
chdir_fail:
	free(info.old_path);
no_old_path:
	free(info.env_path);
no_env_path:
too_long:
help:
	free(url);
no_url_mem:
missing_options:
	return ret;
}



int wait_ack_reply() {
	int ret = -ENOMEM;
	struct anspass_packet *pkt = (struct anspass_packet*)calloc(1,
			sizeof(struct anspass_packet));
	if (!pkt)
		goto no_pkt_mem;

	struct timeval *to = (struct timeval*)calloc(1, sizeof(struct timeval));
	if (!to)
		goto no_to_mem;

	to->tv_sec = 1;
	to->tv_usec = 0;
	pkt->socket = info.socket;
	pkt->to = to;

	ret = check_for_data(pkt);
	if (!ret)
	{
		printf("check timed out.\n");
		goto no_data;
	}

	if (ret < 0) {
		ret = -errno;
		printf("Error checking for data: %d\n", ret);
		goto error_data;
	}

	ret = -EIO;
	pkt->ret = -EIO;
	if(get_data(pkt))
	{
		if (ACK == pkt->type)
			ret = pkt->ret;
	}

error_data:
no_data:
	free(to);
no_to_mem:
	free(pkt);
no_pkt_mem:
	return ret;
}

void print_help(int context) {
	if (context)
		printf("Invalid option.\n");

	printf("anspass version: %s\n", VERSION);
	printf("\n");
	printf("Available options:\n");
	printf("\n");
	printf("   --add <url>\n");
	printf("   --del <url>\n");
	printf("   --update <url>\n");
	printf("   --reset\n");
	printf("   --help\n");
	printf("\n");
	printf("\n");
}

int check_passwd(unsigned char *one, unsigned char *two) {
	int ret = 1;
	int one_len = strlen((char*)one);
	int two_len = strlen((char*)two);
	if (one_len != two_len)
		goto len_differ;
	ret = memcmp(one, two, one_len);

len_differ:
	return ret;
}

static inline void print_user_prompt(char *msg) {
	printf("Please enter a username for %s\n", msg);
	printf("(max of %d characters)\n", MAX_MSG_LENGTH-1);
	printf("Username: ");
}
int send_creds(int type, char *msg) {

	int ret = -ENOMEM;
	int match = 3;
	unsigned char *user = (unsigned char*)calloc(1, sizeof(char) *
			MAX_MSG_LENGTH);
	if (!user)
		goto no_mem_user;

	unsigned char *passwd = (unsigned char*)calloc(1, sizeof(char) *
			MAX_MSG_LENGTH);
	if (!passwd)
		goto no_mem_passwd;
	
	unsigned char *v_passwd = (unsigned char*)calloc(1, sizeof(char) *
			MAX_MSG_LENGTH);
	if (!v_passwd)
		goto no_mem_v_passwd;

	struct anspass_packet *pkt = (struct anspass_packet*)calloc(1,
			sizeof(struct anspass_packet));
	if (!pkt)
		goto no_pkt;

	/* Get the username */
	print_user_prompt(msg);
	get_secret(user, MAX_MSG_LENGTH, 1);
	printf("\n");

	ret = -EINVAL;
	do
	{
		if (match != MAX_PASSWD_ATTEMPT)
			printf("Incorrect password. (%d more attempts)\n",
					match);

		/* Get the password */
		printf("Please enter a password for %s\n", msg);
		printf("(max of %d characters)\n", MAX_MSG_LENGTH-1);
		printf("Password: ");
		get_secret(passwd, MAX_MSG_LENGTH, 0);
		printf("\n");
		printf("\n");

		printf("Please re-enter a password for %s\n", msg);
		printf("Verify password:");
		get_secret(v_passwd, MAX_MSG_LENGTH, 0);
		printf("\n");
		match--;

	} while(match && (ret = check_passwd(passwd, v_passwd)) );

	if (ret != 0)
	{
		printf("Incorrect password.  Maximum attempts reached\n");
		goto passwd_fail;
	}

	pkt->socket = info.socket;
	pkt->type = type;
	memcpy(pkt->token, info.token, TOKEN_LEN);
	memcpy(pkt->msg, msg, strlen(msg));
	memcpy(pkt->user, user, strlen((char*)user));
	memcpy(pkt->passwd, passwd, strlen((char*)passwd));

	printf("Adding %s\n", msg);
	ret = put_data(pkt);
	if (ret < 0)
		goto send_fail;

	ret = wait_ack_reply();
	if (ret) {
		printf("Failed: %d\n", ret);
		goto failed;
	}

	printf("Success\n");
	ret = 0;

failed:
	/* Fall-through expected */
send_fail:
	/* Fall-through expected */
passwd_fail:
	free(pkt);
no_pkt:
	free(v_passwd);
no_mem_v_passwd:
	free(passwd);
no_mem_passwd:
	free(user);
no_mem_user:
	return ret;
}

int handle_add(char *msg) {
	return send_creds(ADD, msg);
}
int handle_update(char *msg) {
	return send_creds(UPDATE, msg);
}

int handle_del(char *msg) {
	int ret = 0;
	unsigned char *user = (unsigned char*)calloc(1, sizeof(char) *
			MAX_MSG_LENGTH);
	if (!user)
		goto no_mem_user;

	struct anspass_packet *pkt = (struct anspass_packet*)calloc(1,
			sizeof(struct anspass_packet));
	if (!pkt)
		goto no_pkt;

	print_user_prompt(msg);
	get_secret(user, MAX_MSG_LENGTH, 1);
	printf("\n");

	printf("Deleting %s:", msg);

	pkt->socket = info.socket;
	pkt->type = DEL;
	memcpy(pkt->token, info.token, TOKEN_LEN);
	memcpy(pkt->msg, msg, strlen(msg));
	memcpy(pkt->user, user, strlen((char*)user));

	ret = put_data(pkt);
	if (ret < 0)
		goto send_fail;

	ret = wait_ack_reply();
	if (ret) {
		printf("Failed: %d\n", ret);
		goto failed;
	}
	printf("Success\n");

failed:
	/* Fall-through expected */
send_fail:
	free(pkt);
no_pkt:
	free(user);
no_mem_user:
	return ret;
}

int handle_reset(char *msg) {
	int ret = 0;
	printf("Resetting database\n");
	send_request(&info, RESET, NULL);
	ret = wait_ack_reply();
	if (!ret) {
		printf("Success\n");
		goto success;
	}
	printf("Failed: %d\n", ret);
success:
	return ret;
}

int handle_quit(char *msg) {
	int ret = 0;
	printf("Telling server to shutdown\n");
	send_request(&info, SHUTDOWN, NULL);
	ret = wait_ack_reply();
	if (!ret) {
		printf("Success\n");
		goto success;
	}
	printf("Failed: %d\n", ret);
success:
	return ret;
}
