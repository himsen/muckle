/*
 * @file muckle_responder.c
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

#define MUCKLE_LISTEN_INTERFACE INADDR_ANY
#define MUCKLE_PORT 9001

#define MUCKLE_RESPONDER_CHECK(r, f) \
	if ((r = f) == MUCKLE_ERR) { \
		goto out; \
	}

static int main_muckle_responder(MUCKLE_STATE *state);
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

static int main_muckle_responder(MUCKLE_STATE *state) {

	int res = 0;
	MUCKLE_NETWORK_CTX network_ctx;
	MUCKLE_PROTOCOL responder_protocol;
	MUCKLE_MSG msg_one;
	MUCKLE_MSG msg_two;

	if (state == NULL) {

		res = MUCKLE_ERR;
		goto out;
	}

	/* Create initiator socket and connect to responder */
	MUCKLE_RESPONDER_CHECK(res, muckle_network_responder_init(&network_ctx,
		MUCKLE_LISTEN_INTERFACE, MUCKLE_PORT));

	while (1) {

		/* Initialise Muckle protocol state */
		muckle_protocol_init(&responder_protocol);

		/* Accept next connextion */
		MUCKLE_RESPONDER_CHECK(res, muckle_network_responder_accept(
			&network_ctx));

		/* Initialise first Muckle message structure */
		muckle_msg_init(&msg_one, MUCKLE_MSG_ONE_TYPE, MUCKLE_MSG_VERSION);	

		/* Recieve first Muckle message */
		MUCKLE_RESPONDER_CHECK(res, muckle_network_recv(&network_ctx,
			&msg_one));

		/* MAC handling for incoming message */
		MUCKLE_RESPONDER_CHECK(res, muckle_mac_msg_in(state, &msg_one));

		/* Initialise second Muckle message structure */
		muckle_msg_init(&msg_two, MUCKLE_MSG_TWO_TYPE, MUCKLE_MSG_VERSION);

		/* Generate ECDH public and private keys */
		MUCKLE_RESPONDER_CHECK(res, muckle_ecdh_gen(state, &responder_protocol,
			&msg_two));

		/* Generate SIDH public and private keys */
		MUCKLE_RESPONDER_CHECK(res, muckle_sidh_gen(state, &responder_protocol,
			&msg_two));

		/* MAC handling for outgoing message */
		MUCKLE_RESPONDER_CHECK(res, muckle_mac_msg_out(state,
			&msg_two));

		/* Send second Muckle message */
		MUCKLE_RESPONDER_CHECK(res, muckle_network_send(&network_ctx,
			&msg_two));

		/* Compute ECDH key material */
		MUCKLE_RESPONDER_CHECK(res, muckle_ecdh_compute(state,
			&responder_protocol, &msg_one));

		/* Compute SIDH key material */
		MUCKLE_RESPONDER_CHECK(res, muckle_sidh_compute(state,
			&responder_protocol, &msg_one));

		/* Read QKD key material */
		MUCKLE_RESPONDER_CHECK(res, muckle_read_qkd_keys(state,
			&responder_protocol));

		/* Compute key material and compute new secret state */
		MUCKLE_RESPONDER_CHECK(res, muckle_keys_compute(state,
			&responder_protocol, &msg_one, &msg_two));

		/* Update state */
		MUCKLE_RESPONDER_CHECK(res, muckle_state_update(state,
			&responder_protocol));

		MUCKLE_RESPONDER_CHECK(res,
			muckle_network_close_accepted(&network_ctx));

		muckle_protocol_cleanup(&responder_protocol);
	} /* While-loop end */

out:
	/* Clean up */
	muckle_network_close(&network_ctx);
	muckle_protocol_cleanup(&responder_protocol);

	return res;
}

int main(int argc, char *argv[]) {

	int res = 0;
	MUCKLE_STATE responder_state;

	/* Initialise Muckle state */
	MUCKLE_RESPONDER_CHECK(res, muckle_state_init(&responder_state,
		MUCKLE_MODE_RESPONDER, HARDCODED_PSK));

	res = main_muckle_responder(&responder_state);

out:
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

	/* Clean up */
	muckle_state_cleanup(&responder_state);

	return res;
}
