struct socks_msg {
	unsigned int magic;
	unsigned int key;
	unsigned short type;
	unsigned short port;
	unsigned int length;
};

#define TYPE_DNS_RESOVLE	0
#define TYPE_DNS_KNOWN		1
#define TYPE_DATA_TRANSE	2

#define MAGIC_NUMBER		0x1a2b3c4d
