#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/select.h>
#include "zzsocks.h"

#define HTTP_HEAD_FILE		"HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: application\r\n\r\n"
#define HTTP_HEAD_404		"HTTP/1.0 404 Not Found\r\nConnection: close\r\n\r\n"

enum cmd_para{
	PARA_HTTP_PORT = 1,
	PARA_SOCK_PORT,
	PARA_SERVER_IP,
	PARA_SERVER_PORT,
	PARA_SERVER_PW,
	PARA_MAX
};

unsigned int g_server_ip = 0;
unsigned short g_server_port = 0;
char g_server_pwd[MAX_VALID_PW] = {0};

void url_file(int sock, char *file_name)   /* Maybe binary file */
{
	int len;
	char buf[65536];
	FILE *file = fopen((char *)file_name, "rb");
	if(NULL == file) return;
	do{
		len = fread(buf, 1, sizeof(buf), file);
		if(len > 0) (void)send(sock, buf, len, 0);
	}while(len == sizeof(buf));
	fclose(file);
}

void * thread_web_server(void *arg)
{
	struct timeval timeout={0, 500000};
	int file = 0, size, sock = (int)(long)arg;
	struct stat statbuff = {0,};

	while(1) {
		struct sockaddr_in des = {0, };
		char url[8192] = {0,}, *poz, *end;
		int temp_sock = accept(sock, (void*)&des, (unsigned int *)&size), ret = 1;

		(void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		(void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		while(ret > 0 && strstr(url, "\r\n\r\n") == 0 && strlen(url) < 2048)	/* get head */
			ret = recv(temp_sock, url+strlen(url), 1, 0);

		poz = strchr(url, '/');
		if(!poz) return (void*)(long) close(temp_sock);
		end = strchr(poz, ' ');
		if(!end) return (void*)(long) close(temp_sock);
		*end = 0;

		ret = stat(poz+1, &statbuff);
		if (!ret) {
			(void)send(temp_sock, HTTP_HEAD_FILE, strlen(HTTP_HEAD_FILE), 0);
			url_file(temp_sock, poz+1);
		} else (void)send(temp_sock, HTTP_HEAD_404, strlen(HTTP_HEAD_404), 0);
		close(temp_sock);
	}
	return NULL;
}

void * thread_sock_server(void *arg)
{
	int sock = (int)(long)arg, num = time(NULL) % MAX_VALID_PW;
	unsigned short port = 0;
	char ver[2] = {0x05, 0x00}, *host, buf[CORE_BUF_SIZE] = {0};
	int ret = recv(sock, buf, CORE_BUF_SIZE, 0), temp_sock, max_fd, r;
	unsigned char ok[10] = {0x5, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, *p = 0;
	struct timeval timeout = {5, 0};
	struct socks_msg msg = {0};
	unsigned int ip;
	fd_set rset;

	temp_sock = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in des = {.sin_family = AF_INET,};
	des.sin_addr.s_addr = htonl(g_server_ip);
	des.sin_port = htons(g_server_port);
	p = (unsigned char *)(void *)&g_server_ip;
	(void)setsockopt(temp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	(void)setsockopt(temp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	send(sock, ver, 2, 0);
	recv(sock, buf, 100, 0);
	if (0 == connect(temp_sock, (void *)&des, sizeof(struct sockaddr))) {
		msg.magic = MAGIC_NUMBER;
		msg.num = num;
		if(*(int *)(void *)buf == 0x3000105) {
			char len = *(buf+4);
			host = buf+5;
			port = *(unsigned short *)(void *)(host+len);
			*(host+len) = 0;

			msg.port = port;
			msg.type = TYPE_DNS_RESOVLE;
			msg.length = len;
			send(temp_sock, &msg, sizeof(msg), 0);
			xor_crypt(host, len, g_server_pwd, num);
			send(temp_sock, host, len, 0);
		}else if(*(int *)(void *)buf == 0x1000105) {
			ip = *(unsigned int *)(void *)(buf+4);
			port = *(unsigned short *)(void *)(buf+8);

			msg.port = port;
			msg.type = TYPE_DNS_KNOWN;
			msg.length = ip;
			send(temp_sock, &msg, sizeof(msg), 0);
		}else {
			close(temp_sock);
			return (void*)(long) close(sock);
		}

		send(sock, ok, 10, 0);
		max_fd = (temp_sock > sock) ? temp_sock : sock;

		while (1) {
			FD_ZERO(&rset);
			FD_SET(temp_sock, &rset);
			FD_SET(sock, &rset);
			timeout.tv_sec = 5;
			timeout.tv_usec = 0;
			r = select(max_fd+1, &rset, NULL, NULL, &timeout);
			if (r < 0) break;
			if (!r) continue;
			if (FD_ISSET(sock, &rset)) {
				ret = recv(sock, buf, CORE_BUF_SIZE, 0);
				xor_crypt(buf, ret, g_server_pwd, num);
				if (send(temp_sock, buf, ret, 0) <= 0) break;
			}
			if (FD_ISSET(temp_sock, &rset)) {
				ret = recv(temp_sock, buf, CORE_BUF_SIZE, 0);
				xor_crypt(buf, ret, g_server_pwd, num);
				if (send(sock, buf, ret, 0) <= 0) break;
			}
		}
	} else syslog(LOG_ERR, "connect server %u.%u.%u.%u:%d error\n", p[3], p[2], p[1], p[0], g_server_port);

	close(temp_sock);
	close(sock);
	return NULL;
}

int main(int argc, char *argv[])
{
	struct sigaction sa = {.sa_handler = SIG_IGN, };
	struct sockaddr_in addr_http = {.sin_family = AF_INET,}, addr_sock = {.sin_family = AF_INET,}, des = {0,};
	int size, sock_http, sock_sock, optval = 1;
	pthread_t id;
	struct timeval timeout={5, 0};
	short http_port, sock_port;
	char  cwd[512] = {0,};

	if(argc != PARA_MAX)
		return printf("Userage: ./zzsocksc <http port> <sock port> <server ip> <server port> <password>\n");
	(void)getcwd(cwd, sizeof(cwd) - 1);
	(void)sigaction(SIGPIPE, &sa, 0);
	http_port = (short)atoi(argv[PARA_HTTP_PORT]);
	sock_port = (short)atoi(argv[PARA_SOCK_PORT]);
	g_server_ip = (unsigned int)inet_network(argv[PARA_SERVER_IP]);
	g_server_port = (unsigned short)atoi(argv[PARA_SERVER_PORT]);
	get_key(argv[PARA_SERVER_PW], strlen(argv[PARA_SERVER_PW]), g_server_pwd);

	addr_http.sin_port = htons(http_port);
	addr_http.sin_addr.s_addr = htonl(INADDR_ANY);
	addr_sock.sin_port = htons(sock_port);
	addr_sock.sin_addr.s_addr = htonl(INADDR_ANY);

	sock_http = socket(AF_INET, SOCK_STREAM, 0);
	(void)setsockopt(sock_http, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval));
	if(bind(sock_http, (struct sockaddr *)(void *)&addr_http, sizeof(struct sockaddr_in)) != 0)
		return printf("Error %d to bind the TCP port.\n", errno);
	if(listen(sock_http, 0) != 0)
		return printf("Error %d to listen the TCP port.\n", errno);

	sock_sock = socket(AF_INET, SOCK_STREAM, 0);
	(void)setsockopt(sock_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval));
	if(bind(sock_sock, (struct sockaddr *)(void *)&addr_sock, sizeof(struct sockaddr_in)) != 0)
		return printf("Error %d to bind the TCP port.\n", errno);
	if(listen(sock_sock, 0) != 0)
		return printf("Error %d to listen the TCP port.\n", errno);

	(void)daemon(0, 0);
	strcat(cwd, "/pac");
	(void)chdir(cwd);
	if(0 != pthread_create(&id, NULL, thread_web_server, (void*)(long)sock_http))
		return printf("Error to create thread_web_server.\n");

	while(sock_sock >= 0) {
		int temp_sock = accept(sock_sock, (void*)&des, (unsigned int *)&size);
		(void)setsockopt(temp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		if(temp_sock >= 0){
			if(0 == pthread_create(&id, NULL, thread_sock_server, (void *)(long)temp_sock))
				(void)pthread_detach(id);
			else close(temp_sock);
		}
	}
	return 0;
}
