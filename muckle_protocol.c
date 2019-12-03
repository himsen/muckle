/*
 * @file muckle_protocol.c
 *
 * @author Torben Hansen <torben.hansen.2015@rhul.ac.uk>
 * @author Benjamin Dowling <dowling.bj@gmail.com>
 *
 * Copyright (C) 2018 Benjamin Dowling and Torben Hansen, All Rights Reserved.
 */

#include "muckle.h"
#include "muckle_protocol.h"
#include "muckle_msg.h"
#include "muckle_timingsafe_bcmp.h"
#include "muckle_qkd_keys.h"

#define MUCKLE_ECDH_GROUP MBEDTLS_ECP_DP_CURVE25519

/* These should be re-evaluated */
#define MUCKLE_COUNTER_MAX INT_MAX
#define MUCKLE_QKD_INDEX_MAX INT_MAX

/*
 * Private Muckle cryptographic API
 */

/*
 * Document
 */
static int muckle_mac_gen_key(MUCKLE_STATE *state,
	const mbedtls_md_info_t *md_sha256_ctx, const unsigned char *label,
	size_t labelLen, unsigned char *macKey, size_t macKeyLen);

/*
 * Document
 */
static int muckle_mac_compute(MUCKLE_MSG *msg,
	const mbedtls_md_info_t *md_sha256_ctx, unsigned char *macKey,
	unsigned char *macTag);

/*
 * Document
 */
static int muckle_mac_handle(MUCKLE_STATE *state, MUCKLE_MSG *msg,
	const unsigned char *label, unsigned char *macTag);

/*
 * Document
 */
static int muckle_read_qkd_keys_file(char *fileName, int index,
	unsigned char *keys);

/*
 * Document
 */
static int muckle_read_qkd_keys_static(const unsigned char *qkd_keys, int index,
	unsigned char *keys);

/*
 * Document
 */
static inline void muckle_transcript_ctr(u_int8_t counter,
	unsigned char *transcript, unsigned char *transcriptCtr);

/*
 * Document
 */
static int muckle_hkdf_key_gen(const mbedtls_md_info_t *mdCtx,
	unsigned char *inKey, size_t inKeyLen, unsigned char *salt, size_t saltLen,
	unsigned char *outKey, size_t outKeyLen);

/*
 * Document
 */
static int muckle_hkdf_key_extract(const mbedtls_md_info_t *mdCtx,
	unsigned char *inKey, size_t inKeyLen, unsigned char *salt, size_t saltLen,
	unsigned char *outKey);

/*
 * Document
 */
static int muckle_hkdf_key_expand(const mbedtls_md_info_t *mdCtx,
	unsigned char *inKey, size_t inKeyLen, unsigned char *outKey,
	size_t outKeyLen);

/*
 * Private Muckle cryptographic function definitions
 */

static int muckle_mac_gen_key(MUCKLE_STATE *state,
	const mbedtls_md_info_t *mdSha256Ctx, const unsigned char *label,
	size_t labelLen, unsigned char *macKey, size_t macKeyLen) {

	int res = 0;
	
	res = mbedtls_hkdf(mdSha256Ctx, state->secretState,
		MUCKLE_LEN_SECRET_STATE, state->presharedKey,
		MUCKLE_KEY_LEN_PSK, label, sizeof(label), macKey, macKeyLen);
	if (res < 0) {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

static int muckle_mac_compute(MUCKLE_MSG *msg,
	const mbedtls_md_info_t *mdSha256Ctx, unsigned char *macKey,
	unsigned char *macTag) {

	size_t index = 0;
	size_t bufLen = 0;
	unsigned char buf[MUCKLE_MSG_LEN - MUCKLE_TAG_LEN];
	mbedtls_md_context_t hmac_ctx;

	/* Compute MAC over message */
	bufLen = MUCKLE_MSG_LEN - MUCKLE_TAG_LEN;

	memcpy(buf, &msg->type, sizeof(u_int8_t));
	index = index + sizeof(u_int8_t);

	memcpy(buf + index, &msg->version, sizeof(u_int8_t));
	index = index + sizeof(u_int8_t);

	memcpy(buf + index, msg->id, MUCKLE_ID_LEN);
	index = index + MUCKLE_ID_LEN;

	memcpy(buf + index, msg->classEcdhPub, MUCKLE_KEY_LEN_ECDH);
	index = index + MUCKLE_KEY_LEN_ECDH;

	memcpy(buf + index, msg->qraSidhPub,
		MUCKLE_KEY_LEN_SIDH_PUB);

	mbedtls_md_init(&hmac_ctx);

	if (NULL == mdSha256Ctx ||
		mbedtls_md_setup(&hmac_ctx, mdSha256Ctx, 1) < 0 ||
		mbedtls_md_hmac_starts(&hmac_ctx, macKey, MUCKLE_KEY_LEN_MAC) < 0 ||
		mbedtls_md_hmac_update(&hmac_ctx, buf, bufLen) < 0 ||
		mbedtls_md_hmac_finish(&hmac_ctx, macTag) < 0) {

		return MUCKLE_ERR;
	}

	mbedtls_md_free(&hmac_ctx);

	return MUCKLE_OK;
}

static int muckle_mac_handle(MUCKLE_STATE *state, MUCKLE_MSG *msg,
	const unsigned char *label, unsigned char *macTag) {

	unsigned char macKey[MUCKLE_KEY_LEN_MAC];
	const mbedtls_md_info_t *mdSha256Ctx = NULL;

	/* Generate MAC key */
	mdSha256Ctx = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (NULL == mdSha256Ctx) {
		return MUCKLE_ERR;
	}

	if ((muckle_mac_gen_key(state, mdSha256Ctx, label, sizeof(label),
		macKey, MUCKLE_KEY_LEN_MAC) == MUCKLE_ERR) ||
		(muckle_mac_compute(msg, mdSha256Ctx, macKey,
			macTag) == MUCKLE_ERR)) {

		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

static int muckle_read_qkd_keys_file(char *fileName, int index,
	unsigned char *keys) {

    FILE *fp= NULL;
    size_t i = 0;
    size_t end_pos = 0;
    size_t index_pos = 0;
    int c = 0;

    fp = fopen(fileName, "r");
    if (fp == NULL) {
    	return MUCKLE_ERR;
    }

    /* Compute index into file */
    index_pos = 32 * index;

    /* Do we have enough QKD key material? */
    if (fseek(fp, 0, SEEK_END) != 0) {
    	return MUCKLE_ERR;
    }
    end_pos = ftell(fp);

    if (end_pos < (index_pos + 32)) {
    	return MUCKLE_ERR;
    }

    /* OK, we have enough QKD key material */
    fseek(fp, index_pos, SEEK_SET);

    /* Read QKD key material */
    for (i = 0; i < 32; ++i) {

    	c = fgetc(fp);
        keys[i] = (char) c;
    }

    fclose(fp);

    return MUCKLE_OK;
}

static int muckle_read_qkd_keys_static(const unsigned char *qkd_keys, int index,
	unsigned char *keys) {

	size_t i = 0;
	size_t index_pos = 0;

	index_pos = 32 * index;
	if (qkd_keys_static_array_len < (index_pos + 32)) {
		return MUCKLE_ERR;
	}

	for (i = 0; i < 32; ++i) {
		keys[i] = qkd_keys_static_array[index_pos + i];
	}

	return MUCKLE_OK;
}

static inline void muckle_transcript_ctr(u_int8_t counter,
	unsigned char *transcript, unsigned char *transcriptCtr) {

	unsigned char counterBuf[1];

	memcpy(transcriptCtr, transcript, 2 * MUCKLE_MSG_LEN);

	MUCKLE_U8ENCODE(counterBuf, counter);
	memcpy(transcriptCtr + (2 * MUCKLE_MSG_LEN), counterBuf,
		MUCKLE_COUNTER_LEN);
}

static int muckle_hkdf_key_gen(const mbedtls_md_info_t *mdCtx,
	unsigned char *inKey, size_t inKeyLen, unsigned char *salt, size_t saltLen,
	unsigned char *outKey, size_t outKeyLen) {

	int res = 0;

	res =  mbedtls_hkdf(mdCtx, salt, saltLen, inKey, inKeyLen,
		(const unsigned char *) MUCKLE_LABEL_PROTOCOL_VERISON,
		strlen(MUCKLE_LABEL_PROTOCOL_VERISON), outKey, outKeyLen);

	return res;
}

static int muckle_hkdf_key_extract(const mbedtls_md_info_t *mdCtx,
	unsigned char *inKey, size_t inKeyLen, unsigned char *salt, size_t saltLen,
	unsigned char *outKey) {

	int res = 0;

	res = mbedtls_hkdf_extract(mdCtx, salt, saltLen, inKey, inKeyLen,
		outKey);

	return res;
}

static int muckle_hkdf_key_expand(const mbedtls_md_info_t *mdCtx,
	unsigned char *inKey, size_t inKeyLen, unsigned char *outKey,
	size_t outKeyLen) {

	int res = 0;

	res =  mbedtls_hkdf_expand(mdCtx, inKey, inKeyLen,
		(const unsigned char *) MUCKLE_LABEL_PROTOCOL_VERISON,
		strlen(MUCKLE_LABEL_PROTOCOL_VERISON), outKey, outKeyLen);

	return res;
}

/*
 * Public Muckle state function definitions
 */

int muckle_state_init(MUCKLE_STATE *state, MUCKLE_MODE mode,
	const unsigned char *psk) {

	int res = 0;

	state->mode = mode;
	state->counter = 0;
	state->quantumKeyIndex = 0;
	memcpy(state->presharedKey, psk, MUCKLE_KEY_LEN_PSK);
	memset(state->secretState, 0, MUCKLE_LEN_SECRET_STATE);

	mbedtls_entropy_init(&state->entropy_ctx);
	mbedtls_ctr_drbg_init(&state->rng_ctx);

	/* When should this be re-seeded? */
	res = mbedtls_ctr_drbg_seed(&state->rng_ctx, mbedtls_entropy_func,
		&state->entropy_ctx, (const unsigned char *) MUCKLE_LABEL_PRNG,
		sizeof(MUCKLE_LABEL_PRNG));
	if (res < 0) {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

int muckle_state_update(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol) {

	if ((u_int8_t) ((state->counter) + 1) > (u_int8_t) MUCKLE_COUNTER_MAX) {
		return MUCKLE_ERR;
	}
	else {
		state->counter = (state->counter) + 1;
	}

	if (((state->quantumKeyIndex) + 1) > MUCKLE_QKD_INDEX_MAX) {
		return MUCKLE_ERR;
	}
	else {
		state->quantumKeyIndex = (state->quantumKeyIndex) + 1;
	}

	return MUCKLE_OK;
}

void muckle_state_cleanup(MUCKLE_STATE *state) {

	state->counter = 0;
	state->quantumKeyIndex = 0;
	memset(state->presharedKey, 0, MUCKLE_KEY_LEN_PSK);
	memset(state->secretState, 0, MUCKLE_LEN_SECRET_STATE);
	mbedtls_ctr_drbg_free(&state->rng_ctx);
	mbedtls_entropy_free(&state->entropy_ctx);
}

void muckle_protocol_init(MUCKLE_PROTOCOL *protocol) {

	memset(protocol->serverSessionKey, 0, MUCKLE_KEY_LEN_SESSION);
	memset(protocol->clientSessionKey, 0, MUCKLE_KEY_LEN_SESSION);
	memset(protocol->classicalKeyMaterial, 0, MUCKLE_KEY_LEN_ECDH);
	memset(protocol->qraKeyMaterial, 0, MUCKLE_KEY_LEN_SIDH);
	memset(protocol->qkdKeyMaterial, 0, MUCKLE_KEY_LEN_QKD);
	memset(protocol->qraPrivate, 0, MUCKLE_KEY_LEN_SIDH_PRI);
	protocol->ecdhCtx = calloc(1, sizeof(mbedtls_ecdh_context));
}

void muckle_protocol_cleanup(MUCKLE_PROTOCOL *protocol) {

	memset(protocol->serverSessionKey, 0, MUCKLE_KEY_LEN_SESSION);
	memset(protocol->clientSessionKey, 0, MUCKLE_KEY_LEN_SESSION);
	memset(protocol->classicalKeyMaterial, 0, MUCKLE_KEY_LEN_ECDH);
	memset(protocol->qraKeyMaterial, 0, MUCKLE_KEY_LEN_SIDH);
	memset(protocol->qkdKeyMaterial, 0, MUCKLE_KEY_LEN_QKD);
	memset(protocol->qraPrivate, 0, MUCKLE_KEY_LEN_SIDH_PRI);
	if (protocol->ecdhCtx != NULL) {
		mbedtls_ecdh_free(protocol->ecdhCtx);
		free(protocol->ecdhCtx);
		protocol->ecdhCtx = NULL;
	}
}

/*
 * Public Muckle cryptographic function definitions
 */

int muckle_ecdh_gen(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg) {

	mbedtls_ecp_group_id mbedTLSgroupId;
	mbedtls_ecdh_context *ecdh_ctx = NULL;

	ecdh_ctx = protocol->ecdhCtx;

	mbedtls_ecdh_init(ecdh_ctx);
	mbedtls_ecp_group_init(&ecdh_ctx->grp);

	mbedTLSgroupId = MUCKLE_ECDH_GROUP;
	if ((mbedtls_ecp_group_load(&ecdh_ctx->grp, mbedTLSgroupId) < 0) ||
		(mbedtls_ecdh_gen_public(&ecdh_ctx->grp, &ecdh_ctx->d, &ecdh_ctx->Q,
			mbedtls_ctr_drbg_random, &state->rng_ctx) < 0) ||
		(mbedtls_mpi_write_binary(&ecdh_ctx->Q.X, msg->classEcdhPub,
			MUCKLE_KEY_LEN_ECDH_PUB) < 0)) {

		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

int muckle_ecdh_compute(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg) {

	size_t outLen = 0;
	unsigned char ecdhComputedSecret[MUCKLE_KEY_LEN_ECDH];
	const mbedtls_md_info_t *mdSha256Ctx = NULL;

	mdSha256Ctx = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (NULL == mdSha256Ctx) {
		return MUCKLE_ERR;
	}

	if ((mbedtls_mpi_read_binary(&protocol->ecdhCtx->Qp.X, msg->classEcdhPub,
			MUCKLE_KEY_LEN_ECDH_PUB) < 0) ||
		(mbedtls_mpi_lset(&protocol->ecdhCtx->Qp.Z, 1) < 0) ||
		(mbedtls_ecdh_calc_secret(protocol->ecdhCtx, &outLen,
			ecdhComputedSecret, MUCKLE_KEY_LEN_ECDH,
			mbedtls_ctr_drbg_random, &state->rng_ctx) < 0) ||
		(muckle_hkdf_key_gen(mdSha256Ctx, ecdhComputedSecret,
			MUCKLE_KEY_LEN_ECDH, (unsigned char *) MUCKLE_LABEL_KEY_CLASSICAL,
			sizeof(MUCKLE_LABEL_KEY_CLASSICAL),	protocol->classicalKeyMaterial,
			MUCKLE_KEY_LEN_ECDH) < 0)) {

		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

int muckle_sidh_gen(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg) {

	int res = 0;
	unsigned char sidhPublic[MUCKLE_KEY_LEN_SIDH_PUB];

	if (MUCKLE_MODE_INITIATOR == state->mode) {

		/* What source of randomness does this function use? */
		random_mod_order_A_SIDHp503(protocol->qraPrivate);
		res = EphemeralKeyGeneration_A_SIDHp503(protocol->qraPrivate, sidhPublic);
	}
	else if (MUCKLE_MODE_RESPONDER == state->mode) {

		/* What source of randomness does this function use? */
		random_mod_order_B_SIDHp503(protocol->qraPrivate);
		res = EphemeralKeyGeneration_B_SIDHp503(protocol->qraPrivate, sidhPublic);
	}
	else {
		return MUCKLE_ERR;
	}

	if (res < 0) {
		return MUCKLE_ERR;
	}

	memcpy(msg->qraSidhPub, sidhPublic, MUCKLE_KEY_LEN_SIDH_PUB);

	return MUCKLE_OK;
}

int muckle_sidh_compute(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg) {

	int res = 0;
	unsigned char qraComputedSecret[MUCKLE_KEY_LEN_SIDH];
	const mbedtls_md_info_t *mdSha256Ctx = NULL;

	mdSha256Ctx = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (NULL == mdSha256Ctx) {
		return MUCKLE_ERR;
	}

	if (MUCKLE_MODE_INITIATOR == state->mode) {
		res = EphemeralSecretAgreement_A_SIDHp503(protocol->qraPrivate,
			msg->qraSidhPub, qraComputedSecret);
	}
	else if(MUCKLE_MODE_RESPONDER == state->mode) {
		res = EphemeralSecretAgreement_B_SIDHp503(protocol->qraPrivate,
			msg->qraSidhPub, qraComputedSecret);
	}
	else {
		return MUCKLE_ERR;
	}

	if (res < 0) {
		return MUCKLE_ERR;
	}

	if (muckle_hkdf_key_gen(mdSha256Ctx, qraComputedSecret,
			MUCKLE_KEY_LEN_SIDH, (unsigned char *) MUCKLE_LABEL_KEY_QRA,
			sizeof(MUCKLE_LABEL_KEY_QRA), protocol->qraKeyMaterial,
			MUCKLE_KEY_LEN_SIDH) == MUCKLE_ERR) {

		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

int muckle_read_qkd_keys(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol) {

	switch (MUCKLE_QKD_KEYS_METHOD) {

		case MUCKLE_QKD_KEYS_FILE:
			return muckle_read_qkd_keys_file(MUCKLE_QKD_KEYS_FILE_NAME,
				state->quantumKeyIndex, protocol->qkdKeyMaterial);
		case MUCKLE_QKD_KEYS_STATIC:
			return muckle_read_qkd_keys_static(qkd_keys_static_array,
				state->quantumKeyIndex, protocol->qkdKeyMaterial);
	}

	return MUCKLE_ERR;
}

int muckle_keys_compute(MUCKLE_STATE *state, MUCKLE_PROTOCOL *protocol,
	MUCKLE_MSG *msg_one, MUCKLE_MSG *msg_two) {

	size_t index = 0;
	unsigned char transcript[2 * MUCKLE_MSG_LEN];
	unsigned char transcriptCtr[(2 * MUCKLE_MSG_LEN) + MUCKLE_COUNTER_LEN];
	unsigned char chainingKeyQra[MUCKLE_KEY_LEN_CHAIN_QRA];
	unsigned char chainingKeyQKD[MUCKLE_KEY_LEN_CHAIN_QKD];
	unsigned char chainingKeyClassic[MUCKLE_KEY_LEN_CHAIN_CLASS];
	unsigned char extractedKey[MUCKLE_KEY_LEN_EXTRACTED];
	unsigned char expandedKeys[MUCKLE_KEY_LEN_EXPANDED];
	const mbedtls_md_info_t *mdSha256Ctx = NULL;

	mdSha256Ctx = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (NULL == mdSha256Ctx) {
		return MUCKLE_ERR;
	}
 
 	/* Produce transcript from Muckle messages */
	muckle_msg_transcript(msg_one, msg_two, transcript);

	/*
	 * Generated chaining keys
	 * Chaining key <- HKDF(salt, key)
	 * 1. QRA-chain <- HKDF(transcript, QRA-SS)
	 * 2. Classical-chain <- HKDF(QRA-chain, Classical-SS)
	 * 3. QKD-chain <- HKDF(Classical-chain, QKD-SS)
	 */
	if ((muckle_hkdf_key_gen(mdSha256Ctx, protocol->qraKeyMaterial,
		MUCKLE_KEY_LEN_SIDH, transcript, 2 * MUCKLE_MSG_LEN,
		chainingKeyQra, MUCKLE_KEY_LEN_CHAIN_QRA) < 0) ||
		(muckle_hkdf_key_gen(mdSha256Ctx, protocol->classicalKeyMaterial,
		MUCKLE_KEY_LEN_ECDH, chainingKeyQra, MUCKLE_KEY_LEN_CHAIN_QRA,
		chainingKeyClassic, MUCKLE_KEY_LEN_CHAIN_CLASS) < 0) ||
		(muckle_hkdf_key_gen(mdSha256Ctx, protocol->qkdKeyMaterial,
		MUCKLE_KEY_LEN_QKD, chainingKeyClassic, MUCKLE_KEY_LEN_CHAIN_CLASS,
		chainingKeyQKD, MUCKLE_KEY_LEN_CHAIN_QKD) < 0)) {

		return MUCKLE_ERR;
	}

	/* Produce transcript concatenated with counter */
	muckle_transcript_ctr(state->counter, transcript, transcriptCtr);

	/*
	 * Extract key
	 */
	if (muckle_hkdf_key_extract(mdSha256Ctx, chainingKeyQKD,
		MUCKLE_KEY_LEN_CHAIN_QKD, transcriptCtr,
		(2 * MUCKLE_MSG_LEN) + MUCKLE_COUNTER_LEN, extractedKey) < 0) {

		return MUCKLE_ERR;
	}

	/*
	 * Expand key
	 */
	if (muckle_hkdf_key_expand(mdSha256Ctx, extractedKey,
		MUCKLE_KEY_LEN_EXTRACTED, expandedKeys, MUCKLE_KEY_LEN_EXPANDED) < 0) {

		return MUCKLE_ERR;
	}

	/*
	 * expandedKeys[0;MUCKLE_LEN_SECRET_STATE]: new secret state
	 * index = MUCKLE_LEN_SECRET_STATE
	 * expandedKeys[index: index + MUCKLE_KEY_LEN_SESSION]: client session key
	 * index = index + MUCKLE_KEY_LEN_SESSION
	 * expandedKeys[index: index + MUCKLE_KEY_LEN_SESSION]: server session key
	 */
	memcpy(state->secretState, expandedKeys, MUCKLE_LEN_SECRET_STATE);
	index = MUCKLE_LEN_SECRET_STATE;
	memcpy(protocol->clientSessionKey, expandedKeys + index,
		MUCKLE_KEY_LEN_SESSION);
	index = index + MUCKLE_KEY_LEN_SESSION;
	memcpy(protocol->serverSessionKey, expandedKeys + index,
		MUCKLE_KEY_LEN_SESSION);

	/* Zeroise temporary buffers before exiting? */

	return MUCKLE_OK;
}

int muckle_mac_msg_out(MUCKLE_STATE *state, MUCKLE_MSG *msg) {

	const unsigned char *label = NULL;

	if (MUCKLE_MODE_INITIATOR == state->mode) {

		label = (const unsigned char *) MUCKLE_LABEL_MAC_INITIATOR;
	}
	else if (MUCKLE_MODE_RESPONDER == state->mode){

		label = (const unsigned char *) MUCKLE_LABEL_MAC_RESPONDER;
	}
	else {
		return MUCKLE_ERR;
	}

	if (muckle_mac_handle(state, msg, label, msg->tag) == MUCKLE_ERR) {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}

int muckle_mac_msg_in(MUCKLE_STATE *state, MUCKLE_MSG *msg) {

	const unsigned char *label = NULL;
	unsigned char macTagComputed[MUCKLE_TAG_LEN];

	if (MUCKLE_MODE_INITIATOR == state->mode) {

		label = (const unsigned char *) MUCKLE_LABEL_MAC_RESPONDER;
	}
	else if (MUCKLE_MODE_RESPONDER == state->mode){

		label = (const unsigned char *) MUCKLE_LABEL_MAC_INITIATOR;
	}
	else {
		return MUCKLE_ERR;
	}

	if (muckle_mac_handle(state, msg, label, macTagComputed) == MUCKLE_ERR) {
		return MUCKLE_ERR;
	}

	/*
	 * Verify MAC tag
	 * This constant-time compare implementation is not the most safe
	 * implementation and should probably be swapped with something better.
	 * For example, the OpenSSL constant-time compare function
	 * 'CRYPTO_memcmp()'.
	 */
	if (muckle_timingsafe_bcmp(msg->tag, macTagComputed, MUCKLE_TAG_LEN) != 0) {
		return MUCKLE_ERR;
	}

	return MUCKLE_OK;
}
