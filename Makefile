CC=gcc
CFLAGS=-ggdb -Wall -DMTR_ENABLED
CPPFLAGS=-I. -Imbedtls-2.13.0/include -IPQCrypto-SIDH/src/P503 -Iminitrace
LDFLAGS=-Lmbedtls-2.13.0/library -LPQCrypto-SIDH/lib503
LIBS=-lmbedcrypto -lsidh
PERFORMANCE_OBJS=minitrace/minitrace.o
COMMON_OBJS=muckle_protocol.o muckle_network.o muckle_msg.o \
			muckle_timingsafe_bcmp.o
INITIATOR_OBJS=muckle_initiator.o $(COMMON_OBJS) $(PERFORMANCE_OBJS)
RESPONDER_OBJS=muckle_responder.o $(COMMON_OBJS) $(PERFORMANCE_OBJS)

all: muckle_initiator muckle_responder

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

muckle_initiator: $(INITIATOR_OBJS)
	$(CC) -o $@ $(INITIATOR_OBJS) $(LDFLAGS) $(LIBS)

muckle_responder: $(RESPONDER_OBJS)
	$(CC) -o $@ $(RESPONDER_OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm *.o
	rm muckle_initiator
	rm muckle_responder
	