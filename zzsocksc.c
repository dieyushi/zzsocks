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

#define HTTP_HEAD_FILE		"HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: application\r\n\r\n"
#define HTTP_HEAD_404		"HTTP/1.0 404 Not Found\r\nConnection: close\r\n\r\n"

enum cmd_para{
	PARA_HTTP_PORT = 1,
	PARA_SOCK_PORT,
	PARA_MAX
};

static int DNS(char *host, unsigned int *ip) {
	static int errors = 0;
	int iRes = 0;
	struct addrinfo addrHints = {0};
	struct addrinfo *pAddrResult = NULL, *pAddrRp = NULL;
	struct sockaddr_in *pSrvAddr = NULL;

	if ((NULL == host) || (NULL == ip)) {
		return -1;
	}

	addrHints.ai_family   = AF_INET;        /* do not support IPv6 for performance */
	addrHints.ai_socktype = 0;
	addrHints.ai_flags    = 0;
	addrHints.ai_protocol = 0;

	if (0 == (iRes = getaddrinfo(host, NULL, &addrHints, &pAddrResult))){
		for (pAddrRp = pAddrResult; pAddrRp != NULL; pAddrRp = pAddrRp->ai_next) {
			pSrvAddr = (struct sockaddr_in*)(void*)(pAddrRp->ai_addr);
			*ip = pSrvAddr->sin_addr.s_addr;
			break;
		}
		freeaddrinfo(pAddrResult);
		return 0;
	}

	if((++errors)%5 == 0)
		syslog(LOG_ERR, "getaddrinfo: %s\n", gai_strerror(iRes));
	return -1;
}

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
	int sock = (int)(long)arg;
	unsigned short port = 0;
	char s[100] = {0}, first[2] = {0x05, 0x00}, *host, buf[4096];
	int ret = recv(sock, s, 10, 0), temp_sock;
	char ok[10] = {0x5, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	struct timeval timeout = {5, 0};
	unsigned int ip;

	send(sock, first, 2, 0);
	recv(sock, s, 100, 0);
	if(*(int *)(void *)s == 0x3000105) {
		char len = *(s+4);
		host = s+5;
		port = *(unsigned short *)(void *)(host+len+1);
		DNS(host, &ip);
	}else if(*(int *)(void *)s == 0x1000105) {
		ip = *(unsigned int *)(void *)(s+4);
		port = *(unsigned short *)(void *)(s+8);
	}else return (void*)(long) close(sock);

	temp_sock = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in des = {.sin_family = AF_INET,};
	des.sin_addr.s_addr = ip;
	des.sin_port = htons(port);

	if (host) printf("%s\n", host);

	(void)setsockopt(temp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	(void)setsockopt(temp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (0 == connect(temp_sock, (void *)&des, sizeof(struct sockaddr))){
		send(sock, ok, 10, 0);
		while(ret = recv(sock, buf, 4096, 0)) {
			send(temp_sock, buf, ret, 0);
			while(ret = recv(temp_sock, buf, 4096, 0))
				send(sock, buf, ret, 0);
		}
	}

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
		return printf("Userage: ./zzsocksc <http port> <sock port> \n");
	(void)getcwd(cwd, sizeof(cwd) - 1);
	(void)sigaction(SIGPIPE, &sa, 0);
	http_port = (short)atoi(argv[PARA_HTTP_PORT]);
	sock_port = (short)atoi(argv[PARA_SOCK_PORT]);

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

	/*(void)daemon(0, 0);*/
	strcat(cwd, "/pac");
	(void)chdir(cwd);
	if(0 != pthread_create(&id, NULL, thread_web_server, (void*)(long)sock_http))
		return printf("Error to create thread_web_server.\n");

	while(sock_port >= 0) {
		int temp_sock = accept(sock_sock, (void*)&des, (unsigned int *)&size);
		(void)setsockopt(temp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		if(temp_sock >= 0){
			if(0 == pthread_create(&id, NULL, thread_sock_server, (void *)(long)temp_sock))
				(void)pthread_detach(id);
			else close(temp_sock);
		}
	}
}
