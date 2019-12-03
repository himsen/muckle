/*
 * @file muckle_msg.c
 *
 * @author Torben Hansen <torben.hansen.2015@rhul.ac.uk>
 * @author Benjamin Dowling <dowling.bj@gmail.com>
 *
 * Copyright (C) 2018 Benjamin Dowling and Torben Hansen, All Rights Reserved.
 */

#include <string.h>

#include "muckle.h"
#include "muckle_msg.h"

/*
 * Public Muckle message function definitions
 */

void muckle_msg_init(MUCKLE_MSG *msg, u_int8_t msgType, u_int8_t msgVersion,
	const unsigned char *id) {

	msg->type = msgType;
	msg->version = msgVersion;
	memcpy(msg->id, id, MUCKLE_ID_LEN);
}

void muckle_msg_serialise(MUCKLE_MSG *msg, unsigned char *msgSerialised) {

	int index = 0;

	memcpy(msgSerialised, &msg->type, sizeof(u_int8_t));
	index = index + sizeof(u_int8_t);

	memcpy(msgSerialised + index, &msg->version, sizeof(u_int8_t));
	index = index + sizeof(u_int8_t);

	memcpy(msgSerialised + index, msg->id, MUCKLE_ID_LEN);
	index = index + MUCKLE_ID_LEN;

	memcpy(msgSerialised + index, msg->classEcdhPub, MUCKLE_KEY_LEN_ECDH_PUB);
	index = index + MUCKLE_KEY_LEN_ECDH_PUB;

	memcpy(msgSerialised + index, msg->qraSidhPub,
		MUCKLE_KEY_LEN_SIDH_PUB);
	index = index + MUCKLE_KEY_LEN_SIDH_PUB;

	memcpy(msgSerialised + index, &msg->tag, MUCKLE_TAG_LEN);
}

void muckle_msg_deserialise(MUCKLE_MSG *msg, unsigned char *msgSerialised) {

	int index = 0;

	memcpy(&msg->type, msgSerialised,  sizeof(u_int8_t));
	index = index + sizeof(u_int8_t);

	memcpy(&msg->version, msgSerialised + index, sizeof(u_int8_t));
	index = index + sizeof(u_int8_t);

	memcpy(msg->id, msgSerialised + index, MUCKLE_ID_LEN);
	index = index + MUCKLE_ID_LEN;

	memcpy(msg->classEcdhPub, msgSerialised + index, MUCKLE_KEY_LEN_ECDH_PUB);
	index = index + MUCKLE_KEY_LEN_ECDH_PUB;

	memcpy(msg->qraSidhPub, msgSerialised + index,
		MUCKLE_KEY_LEN_SIDH_PUB);
	index = index + MUCKLE_KEY_LEN_SIDH_PUB;

	memcpy(msg->tag, msgSerialised + index, MUCKLE_TAG_LEN);
}

void muckle_msg_transcript(MUCKLE_MSG *msg_one, MUCKLE_MSG *msg_two,
	unsigned char *transcript) {

	muckle_msg_serialise(msg_one, transcript);
	muckle_msg_serialise(msg_two, transcript + MUCKLE_MSG_LEN);
}
