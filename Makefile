CC = gcc
LIBCRYPTO_CFLAGS = $(shell pkg-config --cflags libcrypto)
LIBCRYPTO_LIBS = $(shell pkg-config --libs libcrypto)

all:	example

clean:
	rm -f example

check:	all
	./example

example:	example.c
	$(CC) $(LIBCRYPTO_CFLAGS) $(CFLAGS) -o $@ $^ $(LIBCRYPTO_LIBS) $(LDFLAGS)
