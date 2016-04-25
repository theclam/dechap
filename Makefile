CC=gcc

CFLAGS=-lssl



all:

	$(CC) $(CFLAGS) dechap.c -o dechap

