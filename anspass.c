#include "anspass.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	int ret = -EINVAL;
	int i = 0;
	int size = 0;
	char *msg;

	if (argc == 1)
		goto no_entry;

	if (!is_env_set())
	{
		print_env(ANSPASS_ENV);
		goto no_env;
	}

	if (!is_token_set())
	{
		print_env(ANSPASS_TOKEN);
		goto no_token;
	}

	for (i = 1; i < argc; i++)
	{
		size = strlen(argv[i]) + 1;
	}

	if (size > MAX_MSG_LENGTH)
		goto too_big;

	ret = -ENOMEM;
	msg = (char*)calloc(1, sizeof(char)*MAX_MSG_LENGTH);
	if (!msg)
		goto no_q_mem;


	size = 0;
	for (i = 1; i < argc; i++)
	{
		strcat(msg+size, argv[i]);
		size += strlen(argv[i]) + 1;
		*(msg+size-1) = ' ';
	}
	*(msg+size-1) = '\0';


	char *env = getenv(ANSPASS_ENV);
	ret = -ENOMEM;
	info.env_path= (char*)calloc(1, sizeof(char)*strlen(env)+1);
	if (!info.env_path)
		goto no_env_path;
	strcpy(info.env_path, env);

	ret = info_check_env_path(&info, 0);
	if (ret)
	{
		printf("Error: Failed to open %s: %d\n", info.env_path, ret);
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

	env = getenv(ANSPASS_TOKEN);

	if (strlen(env) != TOKEN_LEN)
	{
		printf("Error: Token is not the expected length.\n");
		goto token_len_mismatch;
	}

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

	ret = send_request(&info, QUERY, msg);
	if (ret) {
		printf("Error: Sending packet failed: %d\n", ret);
		goto send_fail;
	}

	memset(msg, 0, MAX_MSG_LENGTH);
	ret = wait_for_reply(msg);
	if (ret < 0)
	{
		printf("Error: Cannot get reply: %d\n", ret);
		goto reply_error;
	}

	printf("%s\n", msg);
	ret = 0;


reply_error:
send_fail:
	close(info.socket);
not_connected:
	free(info.s_name);
socket_fail:
	free(info.token);
no_token_mem:
token_len_mismatch:
env_path_dne:
	chdir((const char *)info.old_path);
chdir_fail:
	free(info.old_path);
no_old_path:
	free(info.env_path);
no_env_path:
	free(msg);
no_q_mem:
too_big:
no_token:
no_env:
no_entry:
	return ret;
}




int wait_for_reply(char *msg) {
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

	ret = get_data(pkt);
	if (ret)
		memcpy(msg, pkt->msg, sizeof(pkt->msg));

error_data:
no_data:
	free(to);
no_to_mem:
	free(pkt);
no_pkt_mem:
	return ret;
}
