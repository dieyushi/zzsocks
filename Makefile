CFLAGS=-g
LDFLAGS=-lpthread

all: zzsockss zzsocksc

zzsocksc:
	$(CC) zzsocksc.c $(CFLAGS) $(LDFLAGS) -o bin/zzsocksc

zzsockss:
	$(CC) zzsockss.c $(CFLAGS) $(LDFLAGS) -o bin/zzsockss

clean:
	rm -rf bin/zzsockss bin/zzsocksc bin/*.dSYM
