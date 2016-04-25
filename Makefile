CC=gcc
CFLAGS=-lcrypto

all:
	$(CC) $(CFLAGS) dechap.c -o dechap

clean:
	rm dechap
