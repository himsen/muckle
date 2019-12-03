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
static int muckle_initiator_cycle_functions(MUCKLE_STATE *state, char *serverIpAddr,
	int serverPort, int i);
static void write_log(char *logName);
static int main_muckle_cycle_complete(void);
static int main_muckle_cycle_functions(void);

/* Measure cycles using RDTSC */
#include <time.h>
#define NUMBER_OF_SAMPLES 4
#define WARM_UP NUMBER_OF_SAMPLES / 4

static double measurements_complete[NUMBER_OF_SAMPLES];
static double measurements_functions[(WARM_UP * 7) + (NUMBER_OF_SAMPLES * 7)];
unsigned long long RDTSC_start_clk;
unsigned long long RDTSC_start_clk_start;

inline static uint64_t get_Clks(void) {
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtscp\n\t" : "=a"(lo), "=d"(hi)::"rcx");
    return ( (uint64_t)lo)^( ((uint64_t)hi)<<32 );
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

	/* Initialise Muckle protocol state */
	muckle_protocol_init(&initiator_protocol);

	/* Create initiator socket and connect to responder */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_initiator_init(&network_ctx,
		serverIpAddr, serverPort));

	/* Initialise first Muckle message structure */
	muckle_msg_init(&msg_one, MUCKLE_MSG_ONE_TYPE, MUCKLE_MSG_VERSION);

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

	/* Initialise second Muckle message structure */
	muckle_msg_init(&msg_two, MUCKLE_MSG_TWO_TYPE, MUCKLE_MSG_VERSION);

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

out:
	/* Clean up */
	muckle_network_close(&network_ctx);
	muckle_protocol_cleanup(&initiator_protocol);

	return res;
}

static void write_log(char *logName) {

	int i = 0;
	FILE *fd = NULL;
	time_t time_header = time(NULL);
	struct tm tm = *localtime(&time_header);

	fd = fopen(logName, "w+");

	if (fd != NULL) {

		fprintf(fd, "%d-%d-%d\n%s\n%i\n", tm.tm_year + 1900,
			tm.tm_mon + 1, tm.tm_mday, logName, NUMBER_OF_SAMPLES);

		for (i = 0; i < NUMBER_OF_SAMPLES; ++i) {
			fprintf(fd, "%.2f\n", measurements_complete[i]);
		}

		fclose(fd);
	}
}

static int main_muckle_cycle_complete(void) {

	int i = 0;
	int res = 0;
	MUCKLE_STATE initiator_state;

	/* Initialise Muckle state */
	MUCKLE_INITIATOR_CHECK(res, muckle_state_init(&initiator_state,
		MUCKLE_MODE_INITIATOR, HARDCODED_PSK));

	for (i = 0; i < WARM_UP; ++i) {
		MUCKLE_INITIATOR_CHECK(res, muckle_initiator(&initiator_state,
			MUCKLE_RESPONDER_IP, MUCKLE_PORT));
	}

	for (i = 0; i < NUMBER_OF_SAMPLES; ++i) {

RDTSC_start_clk = get_Clks();

		MUCKLE_INITIATOR_CHECK(res, muckle_initiator(&initiator_state,
			MUCKLE_RESPONDER_IP, MUCKLE_PORT));

measurements_complete[i] = get_Clks() - RDTSC_start_clk;
	}

out:
	/* Clean up */
	muckle_state_cleanup(&initiator_state);

	return res;
}

static int muckle_initiator_cycle_functions(MUCKLE_STATE *state, char *serverIpAddr,
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

RDTSC_start_clk = get_Clks();

	/* Generate ECDH public and private keys */
	MUCKLE_INITIATOR_CHECK(res, muckle_ecdh_gen(state, &initiator_protocol,
		&msg_one));

measurements_functions[i] = get_Clks() - RDTSC_start_clk;

RDTSC_start_clk = get_Clks();

	/* Generate SIDH public and private keys */
	MUCKLE_INITIATOR_CHECK(res, muckle_sidh_gen(state, &initiator_protocol,
		&msg_one));

measurements_functions[i + 1] = get_Clks() - RDTSC_start_clk;

	/* MAC handling for outgoing message */
	MUCKLE_INITIATOR_CHECK(res, muckle_mac_msg_out(state,
		&msg_one));

	/* Send first Muckle message */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_send(&network_ctx, &msg_one));

	/* Initialise second Muckle message structure */
	muckle_msg_init(&msg_two, MUCKLE_MSG_TWO_TYPE, MUCKLE_MSG_VERSION);

	/* Recieve second Muckle message */
	MUCKLE_INITIATOR_CHECK(res, muckle_network_recv(&network_ctx, &msg_two));

	/* MAC handling for incoming message */
	MUCKLE_INITIATOR_CHECK(res, muckle_mac_msg_in(state, &msg_two));

RDTSC_start_clk = get_Clks();

	/* Compute ECDH key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_ecdh_compute(state, &initiator_protocol,
		&msg_two));

measurements_functions[i + 2] = get_Clks() - RDTSC_start_clk;

RDTSC_start_clk = get_Clks();

	/* Compute SIDH key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_sidh_compute(state, &initiator_protocol,
		&msg_two));

measurements_functions[i + 3] = get_Clks() - RDTSC_start_clk;

RDTSC_start_clk = get_Clks();

	/* Read QKD key material */
	MUCKLE_INITIATOR_CHECK(res, muckle_read_qkd_keys(state,
		&initiator_protocol));

measurements_functions[i + 4] = get_Clks() - RDTSC_start_clk;

RDTSC_start_clk = get_Clks();

	/* Compute key material and compute new secret state */
	MUCKLE_INITIATOR_CHECK(res, muckle_keys_compute(state, &initiator_protocol,
		&msg_one, &msg_two));

measurements_functions[i + 5] = get_Clks() - RDTSC_start_clk;

	/* Update state */
	MUCKLE_INITIATOR_CHECK(res, muckle_state_update(state,
		&initiator_protocol));

out:
	/* Clean up */
	muckle_network_close(&network_ctx);
	muckle_protocol_cleanup(&initiator_protocol);

	return res;
}

static void write_log_functions(char *logName) {

	int i = 0;
	int j = 0;
	FILE *fd = NULL;
	time_t time_header = time(NULL);
	struct tm tm = *localtime(&time_header);

	fd = fopen(logName, "w+");

	if (fd != NULL) {

		fprintf(fd, "%d-%d-%d\n%s\n%i\n", tm.tm_year + 1900,
			tm.tm_mon + 1, tm.tm_mday, "initiator", NUMBER_OF_SAMPLES);

		for (i = WARM_UP * 7; i < (WARM_UP * 7) + (NUMBER_OF_SAMPLES * 7); i = i + 7) {
			for (j = 0; j < 7; ++j) {
				fprintf(fd, "%.2f\n", measurements_functions[i + j]);
			}
		}

		fclose(fd);
	}
}

static int main_muckle_cycle_functions(void) {

	int i = 0;
	int res = 0;
	MUCKLE_STATE initiator_state;

	/* Initialise Muckle state */
	MUCKLE_INITIATOR_CHECK(res, muckle_state_init(&initiator_state,
		MUCKLE_MODE_INITIATOR, HARDCODED_PSK));

	for (i = 0; i < WARM_UP * 7; i = i + 7) {
		MUCKLE_INITIATOR_CHECK(res, muckle_initiator_cycle_functions(&initiator_state,
			MUCKLE_RESPONDER_IP, MUCKLE_PORT, i));
	}

	for (i = WARM_UP * 7; i < (WARM_UP * 7) + (NUMBER_OF_SAMPLES * 7); i = i + 7) {

RDTSC_start_clk_start = get_Clks();

		MUCKLE_INITIATOR_CHECK(res, muckle_initiator_cycle_functions(&initiator_state,
			MUCKLE_RESPONDER_IP, MUCKLE_PORT, i));

measurements_functions[i + 6] = get_Clks() - RDTSC_start_clk_start;
	}

out:
	/* Clean up */
	muckle_state_cleanup(&initiator_state);

	return res;
}

int main(int argc, char *argv[]) {

	int res = 0;

	//res = main_muckle_cycle_complete();
	//write_log("muckle_initiator_cycle.log");

	res = main_muckle_cycle_functions();
	write_log_functions("muckle_initiator_cycle_functions.log");

	return res;
}
