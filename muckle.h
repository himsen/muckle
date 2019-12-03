/*
 * @file muckle.h
 *
 * @author Torben Hansen <torben.hansen.2015@rhul.ac.uk>
 * @author Benjamin Dowling <dowling.bj@gmail.com>
 *
 * Copyright (C) 2018 Benjamin Dowling and Torben Hansen, All Rights Reserved.
 */

#ifndef MUCKLE_H
#define MUCKLE_H

#include <stdio.h>
#include <errno.h>
#include <string.h>

/* Muckle status codes */
#define MUCKLE_OK 0
#define MUCKLE_ERR -1

/* Muckle modes */
#define MUCKLE_MODE_INITIATOR MUCKLE_INITIATOR
#define MUCKLE_MODE_RESPONDER MUCKLE_RESPONDER

typedef enum muckle_mode {
	MUCKLE_INITIATOR,
	MUCKLE_RESPONDER
} MUCKLE_MODE;

/* Muckle protocol */
#define MUCKLE_LABEL_PRNG "MUCKLE PRNG"
#define MUCKLE_LABEL_MAC_INITIATOR "INITIATOR MAC KEY"
#define MUCKLE_LABEL_MAC_RESPONDER "RESPONDER MAC KEY"
#define MUCKLE_LABEL_PROTOCOL_VERISON "MUCKLE PROTOCOL VERSION 0"
#define MUCKLE_LABEL_KEY_CLASSICAL "CLASSICAL KEY EXTRACTION"
#define MUCKLE_LABEL_KEY_QRA "QRA KEY EXTRACTION"

#define MUCKLE_KEY_LEN_PSK 32 /* Counted in bytes */
#define MUCKLE_KEY_LEN_MAC 32 /* Counted in bytes */
#define MUCKLE_LEN_SECRET_STATE 32 /* Counted in bytes */
#define MUCKLE_KEY_LEN_SESSION 32 /* Counted in bytes */

#define MUCKLE_KEY_LEN_ECDH 32 /* Counted in bytes */
#define MUCKLE_KEY_LEN_ECDH_PUB 32 /* Counted in bytes */
#define MUCKLE_KEY_LEN_SIDH 126 /* Counted in bytes */
#define MUCKLE_KEY_LEN_SIDH_PUB 378 /* Counted in bytes */
#define MUCKLE_KEY_LEN_SIDH_PRI 32 /* Counted in bytes */
#define MUCKLE_KEY_LEN_QKD 32 /* Counted in bytes */

#define MUCKLE_KEY_LEN_CHAIN_QRA 32 /* Counted in bytes */
#define MUCKLE_KEY_LEN_CHAIN_QKD 32 /* Counted in bytes */
#define MUCKLE_KEY_LEN_CHAIN_CLASS 32 /* Counted in bytes */
#define MUCKLE_KEY_LEN_EXTRACTED 32 /* Counted in bytes */
#define MUCKLE_KEY_LEN_EXPANDED (MUCKLE_LEN_SECRET_STATE + (2 * MUCKLE_KEY_LEN_SESSION))  /* Counted in bytes */

#define MUCKLE_TAG_LEN 32 /* Counted in bytes */

/* Muckle message */
#define MUCKLE_MSG_VERSION 0
#define MUCKLE_MSG_ONE_TYPE 0
#define MUCKLE_MSG_TWO_TYPE 1
#define MUCKLE_MSG_LEN 444 /* Counted in bytes */

#endif /* MUCKLE_H */
