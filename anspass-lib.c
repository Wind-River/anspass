#include "anspass-lib.h"

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

int is_env_set() {
	if (getenv(ANSPASS_ENV) != NULL)
		return 1;
	return 0;
}

int is_token_set() {
	if (getenv(ANSPASS_TOKEN) != NULL)
		return 1;
	return 0;
}

int get_data(struct anspass_packet *pkt) {

	int ret = recv(pkt->socket, pkt, sizeof(struct anspass_packet),
				0);
	return ret;
}
int check_for_data(struct anspass_packet *pkt) {
	int ret = 0;
	fd_set input;

	FD_ZERO(&input);
	FD_SET(pkt->socket, &input);

	ret =  select(pkt->socket + 1, &input, NULL, NULL, pkt->to);
	if (ret == -1)
		ret = -errno;

	return ret;
}

int put_data(struct anspass_packet *pkt) {
	int ret = 0;
	if (send(pkt->socket, pkt, sizeof(struct anspass_packet), 0) == -1)
		ret = -errno;
	return ret;
}

int info_check_env_path(struct anspass_info *info, int create) {
	int ret = 0;
	struct stat st = {0};

	if (stat(info->env_path, &st) == -1) {
		if (create)
		{
			if (mkdir(info->env_path, 0700))
				ret = -errno;
		}
		else
		{
			ret = -errno;
		}
	}
	return ret;
}

int setup_socket(struct anspass_info *info) {

	int ret = -ECONNREFUSED;
	int yes = 1;

	info->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	setsockopt(info->socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	ret = -errno;
	if (info->socket < 0)
		goto socket_fail;

	ret = -ENOMEM;
	info->s_name = (struct sockaddr_un*)calloc(1, sizeof(struct
				sockaddr_un));
	if (!info->s_name)
		goto s_name_fail;

	ret = -EACCES;
	if (access(info->s_name->sun_path, F_OK) != -1)
		goto file_exists;

	info->s_name->sun_family = AF_UNIX;
	strcat(info->s_name->sun_path, info->env_path);
	strcat(info->s_name->sun_path, SOCKET_NAME);


	/* Success path */
	return 0;

	/* Failure paths */
file_exists:
	free(info->s_name);
s_name_fail:
	close(info->socket);
socket_fail:
	return ret;
}

void print_env(const char* missing) {
		printf("Error: Please set the environment variable %s\n",
				missing);
}

int send_request(struct anspass_info *info, int type, char *msg) {
	int ret = -EINVAL;

	ret = -ENOMEM;
	struct anspass_packet *pkt = (struct anspass_packet*)calloc(1,
			sizeof(struct anspass_packet));
	if (!pkt)
		goto no_pkt;

	pkt->socket = info->socket;
	pkt->type = type;
	memcpy(pkt->token, info->token, TOKEN_LEN);
	if(msg)
		memcpy(pkt->msg, msg, strlen(msg));

	ret = put_data(pkt);
	if (ret < 0)
		goto send_fail;
	ret = 0;


send_fail:
	free(pkt);
no_pkt:
	return ret;
}

int get_secret(unsigned char *text, uint max, const int echo) {
	char c;
	uint i = 0;
	struct termios old, new;
	tcgetattr( STDIN_FILENO, &old);
	new = old;
	if (!echo)
		new.c_lflag &= ~(ECHO);
	tcsetattr( STDIN_FILENO, TCSANOW, &new);

	/* FIXME: If the user goes over max, then the next input block will
	 * get the remainder and the terminating char.. or something */

	/*reading the password from the console*/
	while ((c = getchar())!= '\n' && c != EOF && i < max) {
		text[i++] = c;
	}
	text[i] = '\0';

	/*resetting our old STDIN_FILENO*/
	tcsetattr( STDIN_FILENO, TCSANOW, &old);
	return i;
}
