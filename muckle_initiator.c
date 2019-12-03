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

static int muckle_initiator_walltime(MUCKLE_STATE *state, char *serverIpAddr,
	int serverPort, int i);
static void write_log(char *logName);
static double get_current_time(void);
static int main_muckle_performance(void);

/* Measure wall time */
#include <sys/time.h>
#include <time.h>
#define NUMBER_OF_SAMPLES 4
#define WARM_UP NUMBER_OF_SAMPLES / 4
#define COUNT 8

static double measurements[(WARM_UP * COUNT) + (NUMBER_OF_SAMPLES * COUNT)];
double WALL_start_clk;
double WALL_start_clk_start;

static double get_current_time(void) {

	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (double) tv.tv_sec + (double) tv.tv_usec / 1000000.0;
}

static int muckle_initiator_walltime(MUCKLE_STATE *state, char *serverIpAddr,
	int serverPort, int i) {

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
	muckle_msg_init(&msg_one, MUCKLE_MSG_ONE_TYPE, MUCKLE_MSG_VERSION);

WALL_start_clk = get_current_time();

	/* Generate ECDH public and private keys */
	MUCKLE_INITIATOR_CHECK(res, muckle_ecdh_gen(state, &initiator_protocol,
		&msg_one));

measurements[i] = get_current_time() - WALL_start_clk;

WALL_start_clk = get_current_time();

	/* Generate SIDH public and private keys */
	MUCKLE_INITIATOR_CHECK(res, muckle_sidh_gen(state, &initiator_protocol,
		&msg_one));

measurements[i + 1] = get_current_time() - WALL_start_clk;

	/* MAC handling for outgoing message */
	MUCKLE_INITIATOR_CHECK(res, muckle_mac_msg_out(state,
		&msg_one));

WALL_start_clk = get_current_time();

	/* Send first Muckle message */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_send(&network_ctx, &msg_one));

	/* Initialise second Muckle message structure */
	muckle_msg_init(&msg_two, MUCKLE_MSG_TWO_TYPE, MUCKLE_MSG_VERSION);

	/* Recieve second Muckle message */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_recv(&network_ctx, &msg_two));

measurements[i + 2] = get_current_time() - WALL_start_clk;

	/* MAC handling for incoming message */
	MUCKLE_INITIATOR_CHECK(res, muckle_mac_msg_in(state, &msg_two));

WALL_start_clk = get_current_time();

	/* Compute ECDH key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_ecdh_compute(state, &initiator_protocol,
		&msg_two));

measurements[i + 3] = get_current_time() - WALL_start_clk;

WALL_start_clk = get_current_time();

	/* Compute SIDH key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_sidh_compute(state, &initiator_protocol,
		&msg_two));

measurements[i + 4] = get_current_time() - WALL_start_clk;

WALL_start_clk = get_current_time();

	/* Read QKD key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_read_qkd_keys(state,
		&initiator_protocol));

measurements[i + 5] = get_current_time() - WALL_start_clk;

WALL_start_clk = get_current_time();

	/* Compute key material and compute new secret state */
	MUCKLE_INITIATOR_CHECK(res, muckle_keys_compute(state, &initiator_protocol,
		&msg_one, &msg_two));

measurements[i + 6] = get_current_time() - WALL_start_clk;

	/* Update state */
	MUCKLE_INITIATOR_CHECK(res, muckle_state_update(state,
		&initiator_protocol));

out:
	/* Clean up */
	muckle_network_close(&network_ctx);
	muckle_protocol_cleanup(&initiator_protocol);

	return res;
}

static void write_log(char *logName) {

	int i = 0;
	int j = 0;
	FILE *fd = NULL;
	time_t time_header = time(NULL);
	struct tm tm = *localtime(&time_header);

	fd = fopen(logName, "w+");

	if (fd != NULL) {

		fprintf(fd, "%d-%d-%d\n%s\n%i\n", tm.tm_year + 1900,
			tm.tm_mon + 1, tm.tm_mday, "initiator", NUMBER_OF_SAMPLES);

		for (i = WARM_UP * COUNT; i < (WARM_UP * COUNT) + (NUMBER_OF_SAMPLES * COUNT); i = i + COUNT) {
			for (j = 0; j < COUNT; ++j) {
				fprintf(fd, "%.5f\n", 1000 * measurements[i + j]);
			}
		}

		fclose(fd);
	}
}

static int main_muckle_performance(void) {

	int i = 0;
	int res = 0;
	MUCKLE_STATE initiator_state;

	/* Initialise Muckle state */
	MUCKLE_INITIATOR_CHECK(res, muckle_state_init(&initiator_state,
		MUCKLE_MODE_INITIATOR, HARDCODED_PSK));

	for (i = 0; i < WARM_UP * COUNT; i = i + COUNT) {
		MUCKLE_INITIATOR_CHECK(res, muckle_initiator_walltime(&initiator_state,
			MUCKLE_RESPONDER_IP, MUCKLE_PORT, i));
	}

	for (i = WARM_UP * COUNT; i < (WARM_UP * COUNT) + (NUMBER_OF_SAMPLES * COUNT); i = i + COUNT) {

WALL_start_clk_start = get_current_time();

		MUCKLE_INITIATOR_CHECK(res, muckle_initiator_walltime(&initiator_state,
			MUCKLE_RESPONDER_IP, MUCKLE_PORT, i));

measurements[i + 7] = get_current_time() - WALL_start_clk_start;
	}

out:
	/* Clean up */
	muckle_state_cleanup(&initiator_state);

	return res;
}

int main(int argc, char *argv[]) {

	int res = 0;

	/* Muckle reference initiator implementation performance */
	res = main_muckle_performance();
	write_log("muckle_initiator_walltime_functions.log");

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
