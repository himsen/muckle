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

static int main_muckle_responder_walltime(MUCKLE_STATE *state);
static void write_log(char *logName);
static double get_current_time(void);

/* Measure wall time */
#include <sys/time.h>
#include <time.h>
#define NUMBER_OF_SAMPLES 4
#define WARM_UP NUMBER_OF_SAMPLES / 4
#define COUNT 8

static double measurements[(WARM_UP * COUNT) + (NUMBER_OF_SAMPLES * COUNT)];
double WALL_start_clk;
double WALL_start_clk_start;

static void write_log(char * logName) {

	int i = 0;
	int j = 0;
	FILE *fd = NULL;
	time_t time_header = time(NULL);
	struct tm tm = *localtime(&time_header);

	fd = fopen(logName, "w+");

	if (fd != NULL) {

		fprintf(fd, "%d-%d-%d\n%s\n%i\n", tm.tm_year + 1900,
			tm.tm_mon + 1, tm.tm_mday, "responder", NUMBER_OF_SAMPLES);

		for (i = WARM_UP * COUNT; i < (WARM_UP * COUNT) + (NUMBER_OF_SAMPLES * COUNT); i = i + COUNT) {
			for (j = 0; j < COUNT; ++j) {
				fprintf(fd, "%.2f\n", 1000 * measurements[i + j]);
			}
		}

		fclose(fd);
	}
}

static double get_current_time(void) {

	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (double) tv.tv_sec + (double) tv.tv_usec / 1000000.0;
}

static int main_muckle_responder_walltime(MUCKLE_STATE *state) {

	int res = 0;
	int i = 0;
	double network_1 = 0;
	double network_2 = 0;
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

	for (i = 0; i < (WARM_UP * COUNT) + (NUMBER_OF_SAMPLES * COUNT); i = i + COUNT) {

WALL_start_clk_start = get_current_time();

		/* Initialise Muckle protocol state */
		muckle_protocol_init(&responder_protocol);

network_1 = get_current_time();

		/* Accept next connextion */
		MUCKLE_RESPONDER_CHECK(res, muckle_network_responder_accept(
			&network_ctx));

network_2 = get_current_time() - network_1;

		/* Initialise first Muckle message structure */
		muckle_msg_init(&msg_one, MUCKLE_MSG_ONE_TYPE, MUCKLE_MSG_VERSION);	

WALL_start_clk = get_current_time();

		/* Recieve first Muckle message */
		MUCKLE_RESPONDER_CHECK(res, muckle_network_recv(&network_ctx,
			&msg_one));

measurements[i] = (get_current_time() - WALL_start_clk) + network_2;

		/* MAC handling for incoming message */
		MUCKLE_RESPONDER_CHECK(res, muckle_mac_msg_in(state, &msg_one));

		/* Initialise second Muckle message structure */
		muckle_msg_init(&msg_two, MUCKLE_MSG_TWO_TYPE, MUCKLE_MSG_VERSION);

WALL_start_clk = get_current_time();

		/* Generate ECDH public and private keys */
		MUCKLE_RESPONDER_CHECK(res, muckle_ecdh_gen(state, &responder_protocol,
			&msg_two));

measurements[i + 1] = get_current_time() - WALL_start_clk;

WALL_start_clk = get_current_time();

		/* Generate SIDH public and private keys */
		MUCKLE_RESPONDER_CHECK(res, muckle_sidh_gen(state, &responder_protocol,
			&msg_two));

measurements[i + 2] = get_current_time() - WALL_start_clk;

		/* MAC handling for outgoing message */
		MUCKLE_RESPONDER_CHECK(res, muckle_mac_msg_out(state,
			&msg_two));

		/* Send second Muckle message */
		MUCKLE_RESPONDER_CHECK(res, muckle_network_send(&network_ctx,
			&msg_two));

WALL_start_clk = get_current_time();

		/* Compute ECDH key material */
		MUCKLE_RESPONDER_CHECK(res, muckle_ecdh_compute(state,
			&responder_protocol, &msg_one));

measurements[i + 3] = get_current_time() - WALL_start_clk;

WALL_start_clk = get_current_time();

		/* Compute SIDH key material */
		MUCKLE_RESPONDER_CHECK(res, muckle_sidh_compute(state,
			&responder_protocol, &msg_one));

measurements[i + 4] = get_current_time() - WALL_start_clk;

WALL_start_clk = get_current_time();

		/* Read QKD key material */
		MUCKLE_RESPONDER_CHECK(res, muckle_read_qkd_keys(state,
			&responder_protocol));

measurements[i + 5] = get_current_time() - WALL_start_clk;

WALL_start_clk = get_current_time();

		/* Compute key material and compute new secret state */
		MUCKLE_RESPONDER_CHECK(res, muckle_keys_compute(state,
			&responder_protocol, &msg_one, &msg_two));

measurements[i + 6] = get_current_time() - WALL_start_clk;

		/* Update state */
		MUCKLE_RESPONDER_CHECK(res, muckle_state_update(state,
			&responder_protocol));

		MUCKLE_RESPONDER_CHECK(res,
			muckle_network_close_accepted(&network_ctx));

		muckle_protocol_cleanup(&responder_protocol);

measurements[i + 7] = get_current_time() - WALL_start_clk_start; 
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

	res = main_muckle_responder_walltime(&responder_state);
	write_log("muckle_responder_walltime_functions.log");

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
