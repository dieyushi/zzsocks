CFLAGS=-g
LDFLAGS=-lpthread
LDFLAGS_EXTRA=-lanl

all: zzsockss zzsocksc

zzsocksc:
	$(CC) zzsocksc.c $(CFLAGS) $(LDFLAGS) -o bin/zzsocksc

zzsockss:
	$(CC) zzsockss.c $(CFLAGS) $(LDFLAGS) $(LDFLAGS_EXTRA) -o bin/zzsockss

clean:
	rm -rf bin/zzsockss bin/zzsocksc bin/*.dSYM
