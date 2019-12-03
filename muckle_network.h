/*
 * @file muckle_network.h
 *
 * @author Torben Hansen <torben.hansen.2015@rhul.ac.uk>
 * @author Benjamin Dowling <dowling.bj@gmail.com>
 *
 * Copyright (C) 2018 Benjamin Dowling and Torben Hansen, All Rights Reserved.
 */

#ifndef MUCKLE_NETWORK_H
#define MUCKLE_NETWORK_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "muckle_msg.h"

typedef struct muckle_network_ctx {

	int socket;
	int socket_status;
	int socket_accepted;
	int socket_accepted_status;
	struct sockaddr_in addr;
	MUCKLE_MODE mode;

} MUCKLE_NETWORK_CTX;

/*
 * Public Muckle networking API
 */

/*
 * Document
 */
int muckle_network_initiator_init(MUCKLE_NETWORK_CTX *network_ctx, 
	char *serverIpAddr, int serverPort);

/*
 * Document
 */
int muckle_network_responder_init(MUCKLE_NETWORK_CTX *network_ctx,
	uint32_t interface, int port);

/*
 * Document
 */
int muckle_network_responder_accept(MUCKLE_NETWORK_CTX *network_ctx);

/*
 * Document
 */
int muckle_network_send(MUCKLE_NETWORK_CTX *network_ctx, MUCKLE_MSG *msg);

/*
 * Document
 */
int muckle_network_recv(MUCKLE_NETWORK_CTX *network_ctx,
	MUCKLE_MSG *msg);

/*
 * Document
 */
int muckle_network_close_accepted(MUCKLE_NETWORK_CTX *network_ctx);

/*
 * Document
 */
void muckle_network_close(MUCKLE_NETWORK_CTX *network_ctx);

#endif /* MUCKLE_NETWORK_H */
