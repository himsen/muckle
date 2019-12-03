/*
 * @file muckle_protocol.h
 *
 * @author Torben Hansen <torben.hansen.2015@rhul.ac.uk>
 * @author Benjamin Dowling <dowling.bj@gmail.com>
 *
 * Copyright (C) 2018 Benjamin Dowling and Torben Hansen, All Rights Reserved.
 */

#ifndef MUCKLE_PROTOCOL_H
#define MUCKLE_PROTOCOL_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"

#include "P503_api.h"

#include "muckle_msg.h"

#define MUCKLE_COUNTER_LEN sizeof(u_int8_t)

#define MUCKLE_U8ENCODE(p, v) \
	do { \
		const u_int8_t __v = (v); \
		((unsigned char *)(p))[0] = __v & 0xff; \
	} while (0)

typedef struct muckle_protocol {

	unsigned char 	serverSessionKey[MUCKLE_KEY_LEN_SESSION];
	unsigned char 	clientSessionKey[MUCKLE_KEY_LEN_SESSION];
	unsigned char 	classicalKeyMaterial[MUCKLE_KEY_LEN_ECDH];
	unsigned char 	qraKeyMaterial[MUCKLE_KEY_LEN_SIDH];
	unsigned char	qkdKeyMaterial[MUCKLE_KEY_LEN_QKD];
	unsigned char	qraPrivate[MUCKLE_KEY_LEN_SIDH_PRI];
	mbedtls_ecdh_context *ecdhCtx;

} MUCKLE_PROTOCOL;

typedef struct muckle_state {

	MUCKLE_MODE mode;
	u_int8_t counter;
	int quantumKeyIndex;
	unsigned char 	presharedKey[MUCKLE_KEY_LEN_PSK];
	unsigned char 	secretState[MUCKLE_LEN_SECRET_STATE];
	mbedtls_entropy_context entropy_ctx;
	mbedtls_ctr_drbg_context rng_ctx;

} MUCKLE_STATE;

/*
 * Public Muckle state API
 */

/*
 * Initialise Muckle state.
 * counter: 0
 * quantum key index: 0
 * pre-shared key: psk
 * secret state: MUCKLE_KEY_LEN_PSK of 0x00 bytes
 */
int muckle_state_init(MUCKLE_STATE *state, MUCKLE_MODE mode,
	const unsigned char *psk);

/*
 * Document
 */
void muckle_state_cleanup(MUCKLE_STATE *state);

/*
 * Document
 */
int muckle_state_update(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol);

/*
 * Document
 */
void muckle_protocol_init(MUCKLE_PROTOCOL *protocol); 

/*
 * Document
 */
void muckle_protocol_cleanup(MUCKLE_PROTOCOL *protocol);

/*
 * Public Muckle cryptographic API
 */

/*
 * Document
 */
int muckle_ecdh_gen(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg);

/*
 * Document
 */
int muckle_ecdh_compute(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg);

/*
 * Document
 */
int muckle_sidh_gen(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg);

/*
 * Document
 */
int muckle_sidh_compute(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg);

/*
 * Document
 */
int muckle_read_qkd_keys(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol);

/*
 * Document
 */
int muckle_keys_compute(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg_one, MUCKLE_MSG *msg_two);

/*
 * Document
 */
int muckle_mac_msg_out(MUCKLE_STATE *state, MUCKLE_MSG *msg);

/*
 * Document
 */
int muckle_mac_msg_in(MUCKLE_STATE *state, MUCKLE_MSG *msg);

#endif /* MUCKLE_PROTOCOL_H */
