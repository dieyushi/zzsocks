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

enum cmd_para{
	PARA_LISTEN_PORT = 1,
	PARA_SERVER_PW,
	PARA_MAX
};

char g_server_pwd[MAX_VALID_PW] = {0};

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

void * thread_sock_server(void *arg)
{
	int sock = (int)(long)arg, ret, temp_sock, max_fd, r;
	struct sockaddr_in des = {.sin_family = AF_INET,};
	unsigned int ip;
	struct timeval timeout = {5, 0};
	char buf[CORE_BUF_SIZE] = {0}, *p = NULL;
	struct socks_msg msg = {0};
	fd_set rset;

	ret = recv(sock, &msg, sizeof(struct socks_msg), 0);
	if (msg.magic != MAGIC_NUMBER || ret != sizeof(struct socks_msg)) {
		syslog(LOG_ERR, "connect atempt with wrong magic number\n");
		close(sock);
		return NULL;
	}
	if (msg.type == TYPE_DNS_RESOVLE) {
		recv(sock, buf, msg.length, 0);
		xor_crypt(buf, msg.length, g_server_pwd, msg.num);
		buf[msg.length] = 0;
		DNS(buf, &ip);
		syslog(LOG_ERR, "connect %s:%d\n", buf, ntohs(msg.port));
	} else if (msg.type == TYPE_DNS_KNOWN) {
		ip = msg.length;
	} else {
		syslog(LOG_ERR, "connect atempt with wrong message type\n");
		close(sock);
		return NULL;
	}

	temp_sock = socket(AF_INET, SOCK_STREAM, 0);
	(void)setsockopt(temp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	(void)setsockopt(temp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	des.sin_addr.s_addr = ip;
	des.sin_port = msg.port;
	p = (char *)(void *)&ip;

	if (0 == connect(temp_sock, (void *)&des, sizeof(struct sockaddr))) {
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
				xor_crypt(buf, ret, g_server_pwd, msg.num);
				if (send(temp_sock, buf, ret, 0) <= 0) break;
			}
			if (FD_ISSET(temp_sock, &rset)) {
				ret = recv(temp_sock, buf, CORE_BUF_SIZE, 0);
				xor_crypt(buf, ret, g_server_pwd, msg.num);
				if (send(sock, buf, ret, 0) <= 0) break;
			}
		}
	} else syslog(LOG_ERR, "connect %u.%u.%u.%u:%d error\n", p[0], p[1], p[2], p[3], ntohs(msg.port));
	close(temp_sock);
	close(sock);
	return NULL;
}

int main(int argc, char *argv[])
{
	struct sigaction sa = {.sa_handler = SIG_IGN, };
	struct sockaddr_in addr = {.sin_family = AF_INET,}, des = {0,};
	int size, sock, optval = 1;
	pthread_t id;
	struct timeval timeout={5, 0};
	short port;

	if(argc != PARA_MAX)
		return printf("Userage: ./zzsockss <port> <password>\n");
	(void)sigaction(SIGPIPE, &sa, 0);
	port = (short)atoi(argv[PARA_LISTEN_PORT]);
	get_key(argv[PARA_SERVER_PW], strlen(argv[PARA_SERVER_PW]), g_server_pwd);

	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval));
	if(bind(sock, (struct sockaddr *)(void *)&addr, sizeof(struct sockaddr_in)) != 0)
		return printf("Error %d to bind the TCP port.\n", errno);
	if(listen(sock, 0) != 0)
		return printf("Error %d to listen the TCP port.\n", errno);

	(void)daemon(0, 0);

	while(sock >= 0) {
		int temp_sock = accept(sock, (void*)&des, (unsigned int *)&size);
		(void)setsockopt(temp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		if(temp_sock >= 0){
			if(0 == pthread_create(&id, NULL, thread_sock_server, (void *)(long)temp_sock))
				(void)pthread_detach(id);
			else close(temp_sock);
		}
	}
	return 0;
}
