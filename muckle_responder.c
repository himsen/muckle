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

/*
 * Harcoded Pre-shared key. This key should be specific to the entities
 * engaging in the Muckle protocol.
 */
static const unsigned char HARDCODED_PSK[MUCKLE_KEY_LEN_PSK] = {
	0x44, 0x4f, 0x4e, 0x27, 0x54, 0x20, 0x55, 0x53, 0x45, 0x20,
	0x54, 0x48, 0x49, 0x53, 0x20, 0x4b, 0x45, 0x59, 0x20, 0x49,
	0x4e, 0x20, 0x50, 0x52, 0x4f, 0x44, 0x55, 0x43, 0x54, 0x49,
	0x4f, 0x4e};

/*
 * Static session identifier hex encoded. This id should be specific to the
 * session between two entities and must be long-term i.e. static over
 * multiple session.
 */
static const unsigned char ID[MUCKLE_ID_LEN] = {
	0x10, 0xc5, 0xd7, 0xb0, 0x7b, 0xd8, 0x33, 0xcd, 0x84, 0xc0,
	0x4b, 0x96, 0x39, 0x74, 0xd1, 0x3b, 0x82, 0x0a, 0xac, 0x1f,
	0xf8, 0x53, 0x16, 0x57, 0xf6, 0x89, 0x3f, 0xf7, 0x76, 0xee,
	0x13, 0xce};

#define MUCKLE_RESPONDER_CHECK(r, f) \
	if ((r = f) == MUCKLE_ERR) { \
		goto out; \
	}

static int main_muckle_responder(MUCKLE_STATE *state, const unsigned char *id);
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

static int main_muckle_responder(MUCKLE_STATE *state, const unsigned char *id) {

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

		/* Recieve first Muckle message */
		MUCKLE_RESPONDER_CHECK(res, muckle_network_recv(&network_ctx,
			&msg_one));

		/* MAC handling for incoming message */
		MUCKLE_RESPONDER_CHECK(res, muckle_mac_msg_in(state, &msg_one));

		/* Initialise second Muckle message structure */
		muckle_msg_init(&msg_two, MUCKLE_MSG_TWO_TYPE, MUCKLE_MSG_VERSION, id);

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

		/* Print session keys */
		fprintf(stderr, "CLIENT SESSION KEY:\n");
		muckle_dump_data(responder_protocol.clientSessionKey,
			MUCKLE_KEY_LEN_SESSION, stderr);
		fprintf(stderr, "SERVER SESSION KEY:\n");
		muckle_dump_data(responder_protocol.serverSessionKey,
			MUCKLE_KEY_LEN_SESSION, stderr);

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

	res = main_muckle_responder(&responder_state, ID);

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
