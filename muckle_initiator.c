/*
 * @file muckle_initiator.c
 *
 * @author Torben Hansen <torben.hansen.2015@rhul.ac.uk>
 * @author Benjamin Dowling <dowling.bj@gmail.com>
 *
 * Copyright (C) 2018 Benjamin Dowling and Torben Hansen, All Rights Reserved.
 */

#include <ctype.h>

#include "muckle.h"
#include "muckle_msg.h"
#include "muckle_network.h"
#include "muckle_protocol.h"

#define MUCKLE_RESPONDER_IP "127.0.0.1"
#define MUCKLE_PORT 9001

#define MUCKLE_INITIATOR_CHECK(r, f) \
	if ((r = f) == MUCKLE_ERR) { \
		goto out; \
	}

static int muckle_initiator(MUCKLE_STATE *state, char *serverIpAddr,
	int serverPort);
static int main_muckle_performance_profiling();
static void muckle_dump_data(const void *s, size_t len, FILE *f);

static void muckle_dump_data(const void *s, size_t len, FILE *f) {

	size_t i, j;
	const u_char *p = (const u_char *)s;

	for (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		for (j = i; j < i + 16; j++) {
			if (j < len)
				fprintf(f, "%02x ", p[j]);
			else
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		for (j = i; j < i + 16; j++) {
			if (j < len) {
				if  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				else
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

static int muckle_initiator(MUCKLE_STATE *state, char *serverIpAddr,
	int serverPort) {

	int res = 0;
	MUCKLE_NETWORK_CTX network_ctx;
	MUCKLE_PROTOCOL initiator_protocol;
	MUCKLE_MSG msg_one;
	MUCKLE_MSG msg_two;

	if (state == NULL || serverIpAddr == NULL || serverPort < 1) {
		
		res = MUCKLE_ERR;
		goto out;
	}

MTR_BEGIN("Protocol", "muckle_protocol_init()");
	/* Initialise Muckle protocol state */
	muckle_protocol_init(&initiator_protocol);
MTR_END("Protocol", "muckle_protocol_init()");

MTR_BEGIN("Network", "muckle_network_initiator_init()");
	/* Create initiator socket and connect to responder */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_initiator_init(&network_ctx,
		serverIpAddr, serverPort));
MTR_END("Network", "muckle_network_initiator_init()");

MTR_BEGIN("Protocol", "muckle_msg_init(msg1)");
	/* Initialise first Muckle message structure */
	muckle_msg_init(&msg_one, MUCKLE_MSG_ONE_TYPE, MUCKLE_MSG_VERSION);
MTR_END("Protocol", "muckle_msg_init(msg1)");

MTR_BEGIN("Crypto", "muckle_ecdh_gen()");
	/* Generate ECDH public and private keys */
	MUCKLE_INITIATOR_CHECK(res, muckle_ecdh_gen(state, &initiator_protocol,
		&msg_one));
MTR_END("Crypto", "muckle_ecdh_gen()");

MTR_BEGIN("Crypto", "muckle_sidh_gen()");
	/* Generate SIDH public and private keys */
	MUCKLE_INITIATOR_CHECK(res, muckle_sidh_gen(state, &initiator_protocol,
		&msg_one));
MTR_END("Crypto", "muckle_sidh_gen()");

MTR_BEGIN("Crypto", "muckle_mac_msg_out()");
	/* MAC handling for outgoing message */
	MUCKLE_INITIATOR_CHECK(res, muckle_mac_msg_out(state,
		&msg_one));
MTR_END("Crypto", "muckle_mac_msg_out()");

MTR_BEGIN("Network", "muckle_network_send()");
	/* Send first Muckle message */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_send(&network_ctx, &msg_one));
MTR_END("Network", "muckle_network_send()");

MTR_BEGIN("Protocol", "muckle_msg_init(msg2)");
	/* Initialise second Muckle message structure */
	muckle_msg_init(&msg_two, MUCKLE_MSG_TWO_TYPE, MUCKLE_MSG_VERSION);
MTR_END("Protocol", "muckle_msg_init(msg2)");

MTR_BEGIN("Network", "muckle_network_recv()");
	/* Recieve second Muckle message */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_recv(&network_ctx, &msg_two));
MTR_END("Network", "muckle_network_recv()");

MTR_BEGIN("Crypto", "muckle_mac_msg_inn()");
	/* MAC handling for incoming message */
	MUCKLE_INITIATOR_CHECK(res, muckle_mac_msg_in(state, &msg_two));
MTR_END("Crypto", "muckle_mac_msg_inn()");

MTR_BEGIN("Crypto", "muckle_ecdh_compute()");
	/* Compute ECDH key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_ecdh_compute(state, &initiator_protocol,
		&msg_two));
MTR_END("Crypto", "muckle_ecdh_compute()");

MTR_BEGIN("Crypto", "muckle_sidh_compute()");
	/* Compute SIDH key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_sidh_compute(state, &initiator_protocol,
		&msg_two));
MTR_END("Crypto", "muckle_sidh_compute()");

MTR_BEGIN("Crypto", "muckle_read_qkd_keys()");
	/* Read QKD key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_read_qkd_keys(state,
		&initiator_protocol));
MTR_END("Crypto", "muckle_read_qkd_keys()");

MTR_BEGIN("Crypto", "muckle_keys_compute()");
	/* Compute key material and compute new secret state */
	MUCKLE_INITIATOR_CHECK(res, muckle_keys_compute(state, &initiator_protocol,
		&msg_one, &msg_two));
MTR_END("Crypto", "muckle_keys_compute()");

MTR_BEGIN("Protocol", "muckle_state_update()");
	/* Update state */
	MUCKLE_INITIATOR_CHECK(res, muckle_state_update(state,
		&initiator_protocol));
MTR_END("Protocol", "muckle_state_update()");

out:
MTR_BEGIN("Protocol", "muckle_network_close()");
	/* Clean up */
	muckle_network_close(&network_ctx);
MTR_END("Protocol", "muckle_network_close()");

MTR_BEGIN("Protocol", "muckle_protocol_cleanup()");
	muckle_protocol_cleanup(&initiator_protocol);
MTR_END("Protocol", "muckle_protocol_cleanup()");

	return res;
}

static int main_muckle_performance_profiling() {

	int res = 0;
	int main_running = 0;
	int initiator_running = 0;
	MUCKLE_STATE initiator_state;

mtr_init("trace.json");

MTR_META_PROCESS_NAME("Muckle Initiator profiling");
MTR_META_THREAD_NAME("Muckle Initiator");

	/* Initialise Muckle state */
MTR_START("Initiator", "Muckle", &main_running);

MTR_BEGIN("Protocol", "muckle_state_init()");
	MUCKLE_INITIATOR_CHECK(res, muckle_state_init(&initiator_state,
		MUCKLE_MODE_INITIATOR, HARDCODED_PSK));
MTR_END("Protocol", "muckle_state_init()");

MTR_BEGIN("Protocol", "muckle_initiator()");
	/* Run Muckle initiator */
	MUCKLE_INITIATOR_CHECK(res, muckle_initiator(&initiator_state,
		MUCKLE_RESPONDER_IP, MUCKLE_PORT));
MTR_END("Protocol", "muckle_initiator()");

out:
	/* Clean up */
MTR_BEGIN("Protocol", "muckle_state_cleanup()");
	muckle_state_cleanup(&initiator_state);
MTR_END("Protocol", "muckle_state_cleanup()");

MTR_FINISH("Initiator", "Muckle", &main_running);

mtr_flush();
mtr_shutdown();

	return res;
}

int main(int argc, char *argv[]) {

	int res = 0;

	/* Muckle reference initiator implementation profiling */
	res = main_muckle_performance_profiling();

	if (res == MUCKLE_ERR) {

		res = -1;
		fprintf(stderr, "MUCKLE ERROR\n");
	}
	else if (res == MUCKLE_OK) {

		res = 0;
		fprintf(stderr, "MUCKLE OK\n");
	}
	else {

		/* This should not really happen... */
		res = 1;
		fprintf(stderr, "MUCKLE MAGIC...\n");
	}

	return res;
}