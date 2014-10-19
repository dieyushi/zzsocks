struct socks_msg {
	unsigned int magic;
	unsigned int num;
	unsigned short type;
	unsigned short port;
	unsigned int length;
};

#define TYPE_DNS_RESOVLE	0
#define TYPE_DNS_KNOWN		1

#define MAGIC_NUMBER		0x1a2b3c4d
#define MAX_VALID_PW		16
#define CORE_BUF_SIZE		4096

static inline void get_key(char *pw, int pw_len, char *key)
{
	char salt[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
	if (pw_len > MAX_VALID_PW)
		memcpy(key, pw, MAX_VALID_PW);
	else {
		memcpy(key, pw, pw_len);
		memcpy(key+pw_len, salt, MAX_VALID_PW-pw_len);
	}
}

static inline void xor_crypt(char *data, int length, char *key, int num)
{
	int i;
	for (i = 0; i < length; ++i)
		data[i] ^= key[num];
}

