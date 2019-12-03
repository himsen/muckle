CC=gcc
CFLAGS=-ggdb -Wall
CPPFLAGS=-I. -I../mbedtls-2.13.0/include -I../PQCrypto-SIDH/src/P503
LDFLAGS=-L../mbedtls-2.13.0/library -L../PQCrypto-SIDH/lib503
LIBS=-lmbedcrypto -lcrypto -lsidh
COMMON_OBJS=test_speed.o

all: test_speed

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

test_speed: $(COMMON_OBJS)
	$(CC) -o $@ $(COMMON_OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm *.o
	rm test_speed