/*
 * @file muckle_initiator.c
 *
 * @author Torben Hansen <torben.hansen.2015@rhul.ac.uk>
 * @author Benjamin Dowling <dowling.bj@gmail.com>
 *
 * Copyright (C) 2018 Benjamin Dowling and Torben Hansen, All Rights Reserved.
 */

#include <ctype.h>
#include <time.h>

#include "muckle.h"
#include "muckle_msg.h"
#include "muckle_network.h"
#include "muckle_protocol.h"

#define MUCKLE_RESPONDER_IP "127.0.0.1"
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

#define MUCKLE_INITIATOR_CHECK(r, f) \
	if ((r = f) == MUCKLE_ERR) { \
		goto out; \
	}

static int muckle_initiator(MUCKLE_STATE *state, char *serverIpAddr,
	int serverPort, const unsigned char *id);
static int main_muckle_reference();
static void muckle_dump_data(const void *s, size_t len, FILE *f);
static int muckle_key_save(u_char *client_key, u_char *server_key);
static int muckle_keys_to_file(void);

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

#define KEY_LENGTH MUCKLE_KEY_LEN_SESSION
#define NUMBER_OF_KEYS_PER_SESSION 2
#define NUM_SESSIONS_BUFFER 50
#define NUM_OF_SESSIONS 150

u_char key_buffer[KEY_LENGTH * NUMBER_OF_KEYS_PER_SESSION * NUM_SESSIONS_BUFFER];
size_t sessions;

static int muckle_keys_to_file() {

	char file_name[255];
	int i = 0;
	time_t now;

	time(&now);
	strftime(file_name, 255, "%FT%TZ", gmtime(&now));

	int fd = open(file_name, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		return MUCKLE_ERR;
	}

	for (i = 0; i < NUM_SESSIONS_BUFFER; ++i) {

		write(fd, key_buffer + (i * NUMBER_OF_KEYS_PER_SESSION * KEY_LENGTH), KEY_LENGTH);
		write(fd, key_buffer + ((i * NUMBER_OF_KEYS_PER_SESSION * KEY_LENGTH) + KEY_LENGTH), KEY_LENGTH);
	}

	close(fd);

	return MUCKLE_OK;
}

static int muckle_key_save(u_char *client_key, u_char *server_key) {

	memcpy(key_buffer + (sessions * KEY_LENGTH * NUMBER_OF_KEYS_PER_SESSION),
		client_key, KEY_LENGTH);
	memcpy(key_buffer + (sessions * KEY_LENGTH * NUMBER_OF_KEYS_PER_SESSION) + KEY_LENGTH,
		server_key, KEY_LENGTH);

	if (((sessions + 1) % NUM_SESSIONS_BUFFER) == 0) {

		if (MUCKLE_ERR == muckle_keys_to_file()) {
			return MUCKLE_ERR;
		}

		sessions = 0;
	}
	else {
		sessions = sessions + 1;
	}

	return MUCKLE_OK;
}

static int muckle_initiator(MUCKLE_STATE *state, char *serverIpAddr,
	int serverPort, const unsigned char *id) {

	int res = 0;
	MUCKLE_NETWORK_CTX network_ctx;
	MUCKLE_PROTOCOL initiator_protocol;
	MUCKLE_MSG msg_one;
	MUCKLE_MSG msg_two;

	if (state == NULL || serverIpAddr == NULL || serverPort < 1) {
		
		res = MUCKLE_ERR;
		goto out;
	}

	/* Initialise Muckle protocol state */
	muckle_protocol_init(&initiator_protocol);

	/* Create initiator socket and connect to responder */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_initiator_init(&network_ctx,
		serverIpAddr, serverPort));

	/* Initialise first Muckle message structure */
	muckle_msg_init(&msg_one, MUCKLE_MSG_ONE_TYPE, MUCKLE_MSG_VERSION, id);

	/* Generate ECDH public and private keys */
	MUCKLE_INITIATOR_CHECK(res, muckle_ecdh_gen(state, &initiator_protocol,
		&msg_one));

	/* Generate SIDH public and private keys */
	MUCKLE_INITIATOR_CHECK(res, muckle_sidh_gen(state, &initiator_protocol,
		&msg_one));

	/* MAC handling for outgoing message */
	MUCKLE_INITIATOR_CHECK(res, muckle_mac_msg_out(state,
		&msg_one));

	/* Send first Muckle message */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_send(&network_ctx, &msg_one));

	/* Recieve second Muckle message */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_recv(&network_ctx, &msg_two));

	/* MAC handling for incoming message */
	MUCKLE_INITIATOR_CHECK(res, muckle_mac_msg_in(state, &msg_two));

	/* Compute ECDH key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_ecdh_compute(state, &initiator_protocol,
		&msg_two));

	/* Compute SIDH key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_sidh_compute(state, &initiator_protocol,
		&msg_two));

	/* Read QKD key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_read_qkd_keys(state,
		&initiator_protocol));

	/* Compute key material and compute new secret state */
	MUCKLE_INITIATOR_CHECK(res, muckle_keys_compute(state, &initiator_protocol,
		&msg_one, &msg_two));

	/* Update state */
	MUCKLE_INITIATOR_CHECK(res, muckle_state_update(state,
		&initiator_protocol));

	/* Print session keys */
	fprintf(stderr, "CLIENT SESSION KEY:\n");
	muckle_dump_data(initiator_protocol.clientSessionKey,
		MUCKLE_KEY_LEN_SESSION, stderr);
	fprintf(stderr, "SERVER SESSION KEY:\n");
	muckle_dump_data(initiator_protocol.serverSessionKey,
		MUCKLE_KEY_LEN_SESSION, stderr);

	/* Record and save keys */
	MUCKLE_INITIATOR_CHECK(res,
		muckle_key_save(initiator_protocol.clientSessionKey,
						initiator_protocol.serverSessionKey));

out:
	/* Clean up */
	muckle_network_close(&network_ctx);
	muckle_protocol_cleanup(&initiator_protocol);

	return res;
}

static int main_muckle_reference() {

	int res = 0;
	MUCKLE_STATE initiator_state;
	int i = 0;

	/* Initialise Muckle state */
	MUCKLE_INITIATOR_CHECK(res, muckle_state_init(&initiator_state,
		MUCKLE_MODE_INITIATOR, HARDCODED_PSK));

	/* 
	 * Muckle makes sure to update counter (increments of 1), quantum index
	 * (increments of 1) and secret state (output from key
	 * expanding step of the protocol).
	 * So, we can call again if we want as long as we don't
	 * re-set the initiator state.
	 */
	sessions = 0;
	for (i = 0; i < NUM_OF_SESSIONS; ++i) {

		/* Run Muckle initiator */
		MUCKLE_INITIATOR_CHECK(res, muckle_initiator(&initiator_state,
			MUCKLE_RESPONDER_IP, MUCKLE_PORT, ID));

		/*Add small delay here to help synchronisation issues*/
		sleep(0.1);
	}

out:
	/* Clean up */
	muckle_state_cleanup(&initiator_state);

	return res;
}

int main(int argc, char *argv[]) {

	int res = 0;

	/* Muckle reference initiator implementation */
	res = main_muckle_reference();

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
