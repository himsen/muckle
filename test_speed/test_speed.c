

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"

#include "P503_api.h"

#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/ecdh.h"

#define NUMBER_OF_MEASUREMENTS 6
#define WARM_UP NUMBER_OF_MEASUREMENTS / 4


static double measurements_mbedtls_ecdh[(WARM_UP + NUMBER_OF_MEASUREMENTS) * 2];
static double measurements_pqcrypto_ecdh[(WARM_UP + NUMBER_OF_MEASUREMENTS) * 4];
static double measurements_openssl_ecdh[(WARM_UP + NUMBER_OF_MEASUREMENTS) * 2];
unsigned long long start_clk;

inline static uint64_t get_Clks(void) {
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtscp\n\t" : "=a"(lo), "=d"(hi)::"rcx");
    return ( (uint64_t)lo)^( ((uint64_t)hi)<<32 );
}

void write_log(char *logName) {

	int i = 0;
	int index = 0;
	FILE *fd = NULL;
	time_t time_header = time(NULL);
	struct tm tm = *localtime(&time_header);

	fd = fopen(logName, "w+");

	if (fd != NULL) {

		fprintf(fd, "%d-%d-%d\n%s\n%i\n", tm.tm_year + 1900,
			tm.tm_mon + 1, tm.tm_mday, "Testing ECDH: mbedtls (curve25519), pqcrypto (sidh), openssl (secp224r1)", NUMBER_OF_MEASUREMENTS);

		/* Write mbedtls ECDH curve25519 */
		index = WARM_UP * 2;
		for (i = 0; i < NUMBER_OF_MEASUREMENTS; ++i) {
			fprintf(fd, "%.2f\n", measurements_mbedtls_ecdh[index + i * 2]);
		}
		for (i = 0; i < NUMBER_OF_MEASUREMENTS; ++i) {
			fprintf(fd, "%.2f\n", measurements_mbedtls_ecdh[index + (i * 2) + 1]);
		}

		/* Write pqcrypto ECDH SIDH */
		index = WARM_UP * 4;
		for (i = 0; i < NUMBER_OF_MEASUREMENTS; ++i) {
			fprintf(fd, "%.2f\n", measurements_pqcrypto_ecdh[index + i * 4]);
		}
		for (i = 0; i < NUMBER_OF_MEASUREMENTS; ++i) {
			fprintf(fd, "%.2f\n", measurements_pqcrypto_ecdh[index + (i * 4) + 1]);
		}
		for (i = 0; i < NUMBER_OF_MEASUREMENTS; ++i) {
			fprintf(fd, "%.2f\n", measurements_pqcrypto_ecdh[index + (i * 4) + 2]);
		}
		for (i = 0; i < NUMBER_OF_MEASUREMENTS; ++i) {
			fprintf(fd, "%.2f\n", measurements_pqcrypto_ecdh[index + (i * 4) + 3]);
		}

		/* Write OpenSSL ECDH NID_secp224r1 */
		index = WARM_UP * 2;
		for (i = 0; i < NUMBER_OF_MEASUREMENTS; ++i) {
			fprintf(fd, "%.2f\n", measurements_openssl_ecdh[index + i * 2]);
		}
		for (i = 0; i < NUMBER_OF_MEASUREMENTS; ++i) {
			fprintf(fd, "%.2f\n", measurements_openssl_ecdh[index + (i * 2) + 1]);
		}

		fclose(fd);
	}

}

void mbedtls_ecdh(int i) {

	/* ECDH CURVE25519 gen mbedtls */

	int r = 0;
	mbedtls_ecp_group_id mbedTLSgroupId_25519;
	mbedtls_ecdh_context *ecdhCtx_25519 = NULL;
	mbedtls_entropy_context entropy_ctx_25519;
	mbedtls_ctr_drbg_context rng_ctx_25519;
	unsigned char ecdhPub_25519[32];
	unsigned char ecdhComputedSecret_25519[32];
	size_t outLen_25519 = 0;

	memset(ecdhPub_25519, 0x00, 32);
	memset(ecdhComputedSecret_25519, 0x00, 32);

	mbedtls_entropy_init(&entropy_ctx_25519);
	mbedtls_ctr_drbg_init(&rng_ctx_25519);

	r = mbedtls_ctr_drbg_seed(&rng_ctx_25519, mbedtls_entropy_func, 
		&entropy_ctx_25519, (const unsigned char *) "label", sizeof("label"));
	if (r < 0) {
		r = 1;
		goto out;
	}
	ecdhCtx_25519 = calloc(1, sizeof(mbedtls_ecdh_context));

	mbedtls_ecdh_init(ecdhCtx_25519);
	mbedtls_ecp_group_init(&ecdhCtx_25519->grp);

	mbedTLSgroupId_25519 = MBEDTLS_ECP_DP_CURVE25519;

	if (mbedtls_ecp_group_load(&ecdhCtx_25519->grp, mbedTLSgroupId_25519) < 0) {

		r = 2;
		goto out;
	}

start_clk = get_Clks();

	if (mbedtls_ecdh_gen_public(&ecdhCtx_25519->grp, &ecdhCtx_25519->d, &ecdhCtx_25519->Q,
			mbedtls_ctr_drbg_random, &rng_ctx_25519) < 0) {

		r = 3;
		goto out;
	}

measurements_mbedtls_ecdh[i] = get_Clks() - start_clk;

	if (mbedtls_mpi_write_binary(&ecdhCtx_25519->Q.X, ecdhPub_25519, 32) < 0) {

		r = 4;
		goto out;
	}


	/* ECDH CURVE25519 compute mbedtls */

	if (mbedtls_mpi_read_binary(&ecdhCtx_25519->Qp.X, ecdhPub_25519, 32) < 0) {

		r = 6;
		goto out;
	}
	if (mbedtls_mpi_lset(&ecdhCtx_25519->Qp.Z, 1) < 0) {

		r = 7;
		goto out;
	}

start_clk = get_Clks();

	if (mbedtls_ecdh_calc_secret(ecdhCtx_25519, &outLen_25519, ecdhComputedSecret_25519, 32,
			mbedtls_ctr_drbg_random, &rng_ctx_25519) < 0) {

		r = 8;
		goto out;
	}

measurements_mbedtls_ecdh[i + 1] = get_Clks() - start_clk;

out:
	if (r > 0) {
		fprintf(stderr, "Error: %i\n", r);
	}

	mbedtls_ctr_drbg_free(&rng_ctx_25519);
	mbedtls_entropy_free(&entropy_ctx_25519);

	if (ecdhCtx_25519 != NULL) {
		mbedtls_ecdh_free(ecdhCtx_25519);
		free(ecdhCtx_25519);	
	}
}

void pqcrypto_ecdh(int i) {

	unsigned char privA[32];
	unsigned char pubA[378];
	unsigned char secA[126];
	unsigned char privB[32];
	unsigned char pubB[378];
	unsigned char secB[126];

start_clk = get_Clks();

	random_mod_order_A_SIDHp503(privA);
	EphemeralKeyGeneration_A_SIDHp503(privA, pubA);

measurements_pqcrypto_ecdh[i] = get_Clks() - start_clk;

start_clk = get_Clks();

	random_mod_order_B_SIDHp503(privB);
	EphemeralKeyGeneration_B_SIDHp503(privB, pubB);

measurements_pqcrypto_ecdh[i+1] = get_Clks() - start_clk;

start_clk = get_Clks();

	EphemeralSecretAgreement_A_SIDHp503(privA, pubB, secA);

measurements_pqcrypto_ecdh[i+2] = get_Clks() - start_clk;

start_clk = get_Clks();

	EphemeralSecretAgreement_B_SIDHp503(privB, pubB, secB);

measurements_pqcrypto_ecdh[i+3] = get_Clks() - start_clk;
}

void openssl_ecdh(int i) {

	int r = 0;
	EC_KEY *key = NULL;
	const EC_GROUP *group = NULL;
	const EC_POINT *public_key = NULL;
	unsigned char *kbuf = NULL;
	size_t klen = 0;

	if ((key = EC_KEY_new_by_curve_name(NID_secp256k1)) == NULL) {

		r = 9;
		goto out;
	}

start_clk = get_Clks();

	if (EC_KEY_generate_key(key) != 1) {

		r = 10;
		goto out;
	}

measurements_openssl_ecdh[i] = get_Clks() - start_clk;

	group = EC_KEY_get0_group(key);
	public_key = EC_KEY_get0_public_key(key);

	/* ECDH compute libcrypto */

	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	if ((kbuf = malloc(klen)) == NULL) {

		r = 11;
		goto out;
	}

start_clk = get_Clks();

	if (ECDH_compute_key(kbuf, klen, public_key, key, NULL) != (int) klen) {

		r = 12;
		goto out;
	}

measurements_openssl_ecdh[i+1] = get_Clks() - start_clk;

out:
	if (r > 0) {
		fprintf(stderr, "Error: %i\n", r);
	}

	if (key != NULL) {
		EC_KEY_free(key);
	}

	if (kbuf != NULL) {
		free(kbuf);
	}

}

int main(int argc, char *argv[]) {

	int i = 0;

	/* mbedtls ECDH */
	for (i = 0; i < (WARM_UP + NUMBER_OF_MEASUREMENTS) * 2; i = i + 2) {
		mbedtls_ecdh(i);	
	}

	for (i = 0; i < (WARM_UP + NUMBER_OF_MEASUREMENTS) * 4; i = i + 4) {
		pqcrypto_ecdh(i);
	}

	for (i = 0; i < (WARM_UP + NUMBER_OF_MEASUREMENTS) * 2; i = i + 2) {
		openssl_ecdh(i);
	}

	write_log("muckle_cycles_core_crypto.log");

	return 1;
}
