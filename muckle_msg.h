/*
 * @file muckle_msg.h
 *
 * @author Torben Hansen <torben.hansen.2015@rhul.ac.uk>
 * @author Benjamin Dowling <dowling.bj@gmail.com>
 *
 * Copyright (C) 2018 Benjamin Dowling and Torben Hansen, All Rights Reserved.
 */

#ifndef MUCKLE_MSG_H
#define MUCKLE_MSG_H

#include <stdlib.h>

/* Private Muckle msg data */
typedef struct muckle_msg {

	u_int8_t type;
	u_int8_t version;
	unsigned char classEcdhPub[MUCKLE_KEY_LEN_ECDH_PUB];
	unsigned char qraSidhPub[MUCKLE_KEY_LEN_SIDH_PUB];
	unsigned char tag[MUCKLE_TAG_LEN];

} MUCKLE_MSG;

/*
 * Public Muckle message API
 */

/*
 * Document
 */
void muckle_msg_init(MUCKLE_MSG *msg, u_int8_t msgType, u_int8_t msgVersion);

/*
 * Document
 */
void muckle_msg_zeroise(MUCKLE_MSG *msg);

/*
 * Document
 */
void muckle_msg_serialise(MUCKLE_MSG *msg, unsigned char *msgSerialised);

/*
 * Document
 */
void muckle_msg_deserialise(MUCKLE_MSG *msg, unsigned char *msgSerialised);

/*
 * Document
 */
void muckle_msg_transcript(MUCKLE_MSG *msg_one, MUCKLE_MSG *msg_two,
	unsigned char *transcript);

#endif /* MUCKLE_MSG_H */
