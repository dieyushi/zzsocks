#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <syslog.h>
#include <pthread.h>
#include <fcntl.h>
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
#include "list.h"

enum cmd_para{
	PARA_LISTEN_PORT = 1,
	PARA_SERVER_PW,
	PARA_MAX
};

#define MAX_EVENTS 10240
#define CLIENT_HASH_MAX 1024

struct client {
	struct list_head item;
	int sock;
	int temp_sock;
	int status;
	int msg_num;
};

static char g_server_pwd[MAX_VALID_PW] = {0};
static unsigned int g_pw_hash = 0;
static int g_epoll_fd = 0;
static struct epoll_event g_ev = {0};
static struct list_head g_clients_array[CLIENT_HASH_MAX];
static struct list_head g_temp_array[CLIENT_HASH_MAX];

int set_non_blocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int DNS(char *host, unsigned int *ip) {
	int res = 0;
	struct addrinfo hints = {0};
	struct addrinfo *result = NULL, *rp = NULL;
	struct sockaddr_in *addr = NULL;

	if (!host || !ip) return -1;
	hints.ai_family = AF_INET;

	if (0 == (res = getaddrinfo(host, NULL, &hints, &result))){
		for (rp = result; rp != NULL; rp = rp->ai_next) {
			addr = (struct sockaddr_in*)(void*)(rp->ai_addr);
			*ip = addr->sin_addr.s_addr;
			break;
		}
		freeaddrinfo(result);
		return 0;
	}
	return -1;
}

struct client *find_client(int sock)
{
	int hash = sock & (CLIENT_HASH_MAX - 1);
	struct client *obj = NULL;
	list_for_each_entry(obj, &g_clients_array[hash], item){
		if (obj->sock == sock) return obj;
	}
	list_for_each_entry(obj, &g_temp_array[hash], item){
		if (obj->temp_sock == sock) return obj;
	}
}

int make_connection(struct client *c, char *buf)
{
	int sock = c->sock, ret, temp_sock;
	struct sockaddr_in des = {.sin_family = AF_INET,}, peer_addr = {.sin_family = AF_INET,};
	unsigned int ip, addr_len = sizeof(peer_addr);
	struct timeval timeout = {5, 0};
	unsigned char *p = NULL, *q = NULL;
	struct socks_msg msg = {0};

	(void)getpeername(sock, (void*)&peer_addr, (void *)&addr_len);
	ret = recv(sock, &msg, sizeof(struct socks_msg), 0);
	if (msg.magic != MAGIC_NUMBER || msg.hash != g_pw_hash || ret != sizeof(struct socks_msg)) {
		q = (void *)&peer_addr.sin_addr.s_addr;
		syslog(LOG_ERR, "%u.%u.%u.%u with wrong magic number or wrong hash\n", q[0], q[1], q[2], q[3]);
		return -1;
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
		return -1;
	}

	temp_sock = socket(AF_INET, SOCK_STREAM, 0);
	(void)setsockopt(temp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	(void)setsockopt(temp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	des.sin_addr.s_addr = ip;
	des.sin_port = msg.port;
	p = (void *)&ip;

	if (0 == connect(temp_sock, (void *)&des, sizeof(struct sockaddr))) {
		int hash = temp_sock & (CLIENT_HASH_MAX - 1);
		c->temp_sock = temp_sock;
		c->msg_num = msg.num;
		g_ev.data.fd = temp_sock;
		g_ev.events = EPOLLIN;
		epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, temp_sock, &g_ev);
		struct client *new = calloc(1, sizeof(struct client));
		memcpy(new, c, sizeof(struct client));
		INIT_LIST_HEAD(&new->item);
		list_add_tail(&new->item, &g_temp_array[hash]);
	} else {
		syslog(LOG_ERR, "connect %u.%u.%u.%u:%d error\n", p[0], p[1], p[2], p[3], ntohs(msg.port));
		return -1;
	}
	return 0;
}

void accept_sock(int sock)
{
	int client_sock = 0, optval;
	struct sockaddr_in addr = {0};
	socklen_t addr_len = sizeof(addr);

	while((client_sock = accept(sock, (void *)&addr, &addr_len)) >= 0) {
		/*if (g_client_num >= MAX_CLIENTS || -1 == set_non_blocking(client_sock)){*/
		g_ev.data.fd = client_sock;
		g_ev.events = EPOLLIN;
		epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, client_sock, &g_ev);

		struct client *c = calloc(1, sizeof(struct client));
		c->sock = client_sock;
		c->status = 0;
		int hash = client_sock & (CLIENT_HASH_MAX - 1);
		INIT_LIST_HEAD(&c->item);
		list_add_tail(&c->item, &g_clients_array[hash]);
	}
}

void clean_client(struct client *c)
{
	int hash1 = c->sock & (CLIENT_HASH_MAX - 1), hash2 = c->temp_sock & (CLIENT_HASH_MAX - 1);
	struct list_head *head = &g_clients_array[hash1];
	struct client *obj = NULL, *next = NULL;
	if (c->sock >= 0) close(c->sock);
	if (c->temp_sock >= 0) close(c->temp_sock);
	list_for_each_entry_safe(obj, next, head, item) {
		if (obj->sock == c->sock) {
			list_del(&obj->item);
			free(obj);
		}
	}
	head = &g_temp_array[hash2];
	list_for_each_entry_safe(obj, next, head, item) {
		if (obj->temp_sock == c->temp_sock) {
			list_del(&obj->item);
			free(obj);
		}
	}
}

void epoll_worker(int temp_sock, int sock)
{
	int ret = 0, sock2;
	static char buf[CORE_BUF_SIZE] = {0};
	if (temp_sock == sock) accept_sock(sock);
	else {
		struct client *c = find_client(temp_sock);
		if (!c->status) {
			c->status = 1;
			ret = make_connection(c, buf);
			if (ret) clean_client(c);
		} else if (temp_sock == c->sock) {
			ret = recv(temp_sock, buf, CORE_BUF_SIZE, 0);
			xor_crypt(buf, ret, g_server_pwd, c->msg_num);
			if (send(c->temp_sock, buf, ret, 0) <= 0) clean_client(c);
		} else {
			ret = recv(temp_sock, buf, CORE_BUF_SIZE, 0);
			xor_crypt(buf, ret, g_server_pwd, c->msg_num);
			if (send(c->sock, buf, ret, 0) <= 0) clean_client(c);
		}
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sa = {.sa_handler = SIG_IGN, };
	struct sockaddr_in addr = {.sin_family = AF_INET,}, des = {0,};
	int size, sock, optval = 1, i, nfds;
	struct timeval timeout={5, 0};
	short port;
	struct sched_param my_params = {0,};

	struct epoll_event *events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * MAX_EVENTS);

	for (i = 0; i < CLIENT_HASH_MAX; ++i) {
		INIT_LIST_HEAD(&g_clients_array[i]);
		INIT_LIST_HEAD(&g_temp_array[i]);
	}

	my_params.sched_priority = sched_get_priority_max(SCHED_RR);
	(void)sched_setscheduler(0, SCHED_RR, &my_params);

	if(argc != PARA_MAX)
		return printf("Userage: ./zzsockss <port> <password>\n");
	(void)sigaction(SIGPIPE, &sa, 0);
	port = (short)atoi(argv[PARA_LISTEN_PORT]);
	g_pw_hash = get_key(argv[PARA_SERVER_PW], strlen(argv[PARA_SERVER_PW]), g_server_pwd);

	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval));
	if(bind(sock, (struct sockaddr *)(void *)&addr, sizeof(struct sockaddr_in)) != 0)
		return printf("Error %d to bind the TCP port.\n", errno);
	if(set_non_blocking(sock) == -1)
		return printf("Error %d to set socket nonblocking.\n", errno);
	if(listen(sock, 0) != 0)
		return printf("Error %d to listen the TCP port.\n", errno);

	(void)daemon(0, 0);

	g_epoll_fd = epoll_create1(0);
	if (g_epoll_fd == -1) return printf("Error %d to create epoll fd.\n", errno);

	g_ev.events = EPOLLIN;
	g_ev.data.fd = sock;
	if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sock, &g_ev) == -1)
		return printf("Error %d to epoll_ctl.\n", errno);

	while(1) {
		nfds = epoll_wait(g_epoll_fd, events, MAX_EVENTS, -1);
		for (i = 0; i < nfds; ++i) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
				close(events[i].data.fd);
				continue;
			}
			epoll_worker(events[i].data.fd, sock);
		}
	}

	free(events);
	close(sock);
	return 0;
}
