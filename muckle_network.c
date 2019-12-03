/*
 * @file muckle_network.c
 *
 * @author Torben Hansen <torben.hansen.2015@rhul.ac.uk>
 * @author Benjamin Dowling <dowling.bj@gmail.com>
 *
 * Copyright (C) 2018 Benjamin Dowling and Torben Hansen, All Rights Reserved.
 */

#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "muckle.h"
#include "muckle_network.h"

#define MUCKLE_NETWORK_SOCKET_FAMILY AF_INET
#define MUCKLE_NETWORK_SOCKET_TYPE SOCK_STREAM
#define MUCKLE_NETWORK_BACKLOG 50
#define MUCKLE_NETWORK_OPEN 0x00
#define MUCKLE_NETWORK_CLOSED 0x01

/*
 * Private Muckle network API
 */

/*
 * Document
 */
static int muckle_socket_open(MUCKLE_NETWORK_CTX *network_ctx);

/*
 * Document
 */
static int muckle_socket_close(int socket);

/*
 * Document
 */
static int muckle_socket_connect(MUCKLE_NETWORK_CTX *network_ctx, 
	char *serverIpAddr, int serverPort);

/*
 * Document
 */
static int muckle_socket_bind(MUCKLE_NETWORK_CTX *network_ctx,
	uint32_t interface, int port);

/*
 * Document
 */
static int muckle_socket_listen(int socket);

/*
 * Blocks until a connection is present.
 */
static int muckle_socket_accept(MUCKLE_NETWORK_CTX *network_ctx);

/*
 * Document
 */
static int muckle_socket_send(int socket, unsigned char *msg, size_t msgLen);

/*
 * This function blocks until the requested amount of bytes are fulfilled.
 * Currently MSG_WAITALL is used; this might not be appropriate.
 */
static int muckle_socket_recv(int socket, unsigned char *msg, size_t msgLen);

/*
 * Document
 */
static inline int muckle_socket_choose(MUCKLE_NETWORK_CTX *network_ctx,
	int *sock);

/*
 * Private Muckle network function definitions
 */

static int muckle_socket_open(MUCKLE_NETWORK_CTX *network_ctx) {

	int sock = -1;

	sock = socket(MUCKLE_NETWORK_SOCKET_FAMILY,
		MUCKLE_NETWORK_SOCKET_TYPE, 0);

	if (sock < 0) {
		return MUCKLE_ERR;
	}

	network_ctx->socket = sock;
	network_ctx->socket_status = MUCKLE_NETWORK_OPEN;

	return MUCKLE_OK;
}

static int muckle_socket_close(int socket) {

	int res = 0;

	res = close(socket);
	if (res < 0) {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

static int muckle_socket_connect(MUCKLE_NETWORK_CTX *network_ctx, 
	char *serverIpAddr, int serverPort) {

	int res = 0;

	memset(&network_ctx->addr, '0', sizeof(network_ctx->addr));

	res = inet_aton(serverIpAddr, &network_ctx->addr.sin_addr);
	if (res == 0) {
		return MUCKLE_ERR;
	}

	network_ctx->addr.sin_family = MUCKLE_NETWORK_SOCKET_FAMILY;
	network_ctx->addr.sin_port = htons(serverPort);

	res = connect(network_ctx->socket,
		(const struct sockaddr *) &network_ctx->addr,
		sizeof(network_ctx->addr));
	if (res < 0) {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

static int muckle_socket_bind(MUCKLE_NETWORK_CTX *network_ctx,
	uint32_t interface, int port) {

	int res = 0;

	memset(&network_ctx->addr, '0', sizeof(network_ctx->addr));

	network_ctx->addr.sin_family = MUCKLE_NETWORK_SOCKET_FAMILY;
	network_ctx->addr.sin_port = htons(port);
	network_ctx->addr.sin_addr.s_addr = htonl(interface);
	/* Uncomment line below if running locally */
	//network_ctx->addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	res = bind(network_ctx->socket, (struct sockaddr*) &network_ctx->addr,
		sizeof(network_ctx->addr));
	if (res < 0) {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

static int muckle_socket_listen(int socket) {

	int res = 0;

	res = listen(socket, MUCKLE_NETWORK_BACKLOG);
	if (res < 0) {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

static int muckle_socket_accept(MUCKLE_NETWORK_CTX *network_ctx) {

	int accepted_sock = 0;

	accepted_sock = accept(network_ctx->socket, NULL, NULL);
	if (accepted_sock < 0) {
		return MUCKLE_ERR;
	}

	network_ctx->socket_accepted = accepted_sock;
	network_ctx->socket_accepted_status = MUCKLE_NETWORK_OPEN;

	return MUCKLE_OK;
}

static int muckle_socket_send(int socket, unsigned char *msg, size_t msgLen) {

	int res = 0;

	res = send(socket, msg, msgLen, 0);
	if (res < 0) {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

static int muckle_socket_recv(int socket, unsigned char *msg, size_t msgLen) {

	size_t returned = 0;

	returned = recv(socket, msg, msgLen, MSG_WAITALL);
	if (returned < msgLen) {
		/* Some error occured */
		return MUCKLE_ERR;
	}
	else if (returned > msgLen) {
		/* This is not good... */
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

static inline int muckle_socket_choose(MUCKLE_NETWORK_CTX *network_ctx,
	int *sock) {

	if (MUCKLE_MODE_INITIATOR == network_ctx->mode) {
		*sock = network_ctx->socket;
	}
	else if (MUCKLE_MODE_RESPONDER == network_ctx->mode) {
		*sock = network_ctx->socket_accepted;
	}
	else {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

/*
 * Public Muckle network function definitions
 */

int muckle_network_initiator_init(MUCKLE_NETWORK_CTX *network_ctx, 
	char *serverIpAddr, int serverPort) {

	if ((muckle_socket_open(network_ctx) == MUCKLE_ERR) ||
		(muckle_socket_connect(network_ctx, serverIpAddr,
			serverPort) == MUCKLE_ERR)) {

		return MUCKLE_ERR;
	}

	network_ctx->socket_accepted_status = MUCKLE_NETWORK_CLOSED;
	network_ctx->mode = MUCKLE_MODE_INITIATOR;
	return MUCKLE_OK;
}

int muckle_network_responder_init(MUCKLE_NETWORK_CTX *network_ctx,
	uint32_t interface, int port) {

	if ((muckle_socket_open(network_ctx) == MUCKLE_ERR) ||
		(muckle_socket_bind(network_ctx, interface, port) == MUCKLE_ERR) ||
		(muckle_socket_listen(network_ctx->socket) == MUCKLE_ERR)) {

		return MUCKLE_ERR;
	}

	network_ctx->socket_accepted_status = MUCKLE_NETWORK_CLOSED;
	network_ctx->mode = MUCKLE_MODE_RESPONDER;

	return MUCKLE_OK;
}

int muckle_network_responder_accept(MUCKLE_NETWORK_CTX *network_ctx) {

	return muckle_socket_accept(network_ctx);
}

int muckle_network_send(MUCKLE_NETWORK_CTX *network_ctx, MUCKLE_MSG *msg) {

	int sock = 0;
	unsigned char msgSerialised[MUCKLE_MSG_LEN];

	muckle_msg_serialise(msg, msgSerialised);

	if ((muckle_socket_choose(network_ctx, &sock) == MUCKLE_ERR) ||
		(muckle_socket_send(sock, msgSerialised,
			MUCKLE_MSG_LEN) == MUCKLE_ERR)) {

		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

int muckle_network_recv(MUCKLE_NETWORK_CTX *network_ctx,
	MUCKLE_MSG *msg) {

	int sock = 0;
	unsigned char msgSerialised[MUCKLE_MSG_LEN];

	if ((muckle_socket_choose(network_ctx, &sock) == MUCKLE_ERR) ||
		(muckle_socket_recv(sock, msgSerialised,
			MUCKLE_MSG_LEN) == MUCKLE_ERR)) {

		return MUCKLE_ERR;
	}

	muckle_msg_deserialise(msg, msgSerialised);

	return MUCKLE_OK;
}

int muckle_network_close_accepted(MUCKLE_NETWORK_CTX *network_ctx) {

	if (MUCKLE_NETWORK_OPEN == network_ctx->socket_accepted_status) {
		if (muckle_socket_close(network_ctx->socket_accepted) == MUCKLE_ERR) {
			return MUCKLE_ERR;
		}

		network_ctx->socket_accepted_status = MUCKLE_NETWORK_CLOSED;
	}

	return MUCKLE_OK;
}

void muckle_network_close(MUCKLE_NETWORK_CTX *network_ctx) {

	if (MUCKLE_NETWORK_OPEN == network_ctx->socket_status) {
		if (muckle_socket_close(network_ctx->socket) == MUCKLE_ERR) {
			/*
			 * OK, so how do we handle this exactly?
			 * For now, just exit silently like nothing happened...
			 */
		}

		network_ctx->socket_status = MUCKLE_NETWORK_CLOSED;
	}

	if (muckle_network_close_accepted(network_ctx) == MUCKLE_ERR) {
		/*
		 * OK, so how do we handle this exactly?
		 * For now, just exit silently like nothing happened...
		 */
	}
}
