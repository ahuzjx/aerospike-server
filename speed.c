#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

static uint64_t now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
		fprintf(stderr, "clock_gettime() failed\n");
		exit(1);
	}

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void xts_encrypt(const uint8_t *key, uint64_t tweak, const uint8_t *in,
		size_t sz_in, uint8_t *out)
{
	uint8_t iv[16] = { 0 };
	memcpy(iv, &tweak, sizeof(tweak));

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (ctx == NULL) {
		fprintf(stderr, "EVP_CIPHER_CTX_new() failed\n");
		exit(1);
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv) < 1) {
		fprintf(stderr, "EVP_EncryptInit_ex() failed\n");
		exit(1);
	}

	int32_t sz_out_1 = 0;

	if (EVP_EncryptUpdate(ctx, out, &sz_out_1, in, (int32_t)sz_in) < 1) {
		fprintf(stderr, "EVP_EncryptUpdate() failed\n");
		exit(1);
	}

	int32_t sz_out_2 = 0;

	if (EVP_EncryptFinal_ex(ctx, out + sz_out_1, &sz_out_2) < 1) {
		fprintf(stderr, "EVP_EncryptFinal_ex() failed\n");
		exit(1);
	}

	if (sz_out_1 + sz_out_2 != (int32_t)sz_in) {
		fprintf(stderr, "unexpected encrypted size: %d + %d vs. %zu\n",
				sz_out_1, sz_out_2, sz_in);
		exit(1);
	}

	EVP_CIPHER_CTX_free(ctx);
}

static void xts_decrypt(const uint8_t *key, uint64_t tweak, const uint8_t *in,
		size_t sz_in, uint8_t *out)
{
	uint8_t iv[16] = { 0 };
	memcpy(iv, &tweak, sizeof(tweak));

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (ctx == NULL) {
		fprintf(stderr, "EVP_CIPHER_CTX_new() failed\n");
		exit(1);
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv) < 1) {
		fprintf(stderr, "EVP_DecryptInit_ex() failed\n");
		exit(1);
	}

	int32_t sz_out_1 = 0;

	if (EVP_DecryptUpdate(ctx, out, &sz_out_1, in, (int32_t)sz_in) < 1) {
		fprintf(stderr, "EVP_DecryptUpdate() failed\n");
		exit(1);
	}

	int32_t sz_out_2 = 0;

	if (EVP_DecryptFinal_ex(ctx, out + sz_out_1, &sz_out_2) < 1) {
		fprintf(stderr, "EVP_DecryptFinal_ex() failed\n");
		exit(1);
	}

	if (sz_out_1 + sz_out_2 != (int32_t)sz_in) {
		fprintf(stderr, "unexpected decrypted size: %d + %d vs. %zu\n",
				sz_out_1, sz_out_2, sz_in);
		exit(1);
	}

	EVP_CIPHER_CTX_free(ctx);
}

typedef union {
	uint8_t val8[16];
	uint64_t val64[2];
} conv_t;

static void xts_decrypt2(const uint8_t *key, uint64_t tweak, const uint8_t *in,
		size_t sz_in, uint8_t *out)
{
	if (sz_in % 16 != 0) {
		fprintf(stderr, "unexpected encrypted size: %zu\n", sz_in);
		exit(1);
	}

	conv_t iv;
	iv.val64[0] = tweak;
	iv.val64[1] = 0;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	if (EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL) < 1) {
		fprintf(stderr, "EVP_EncryptInit_ex() failed\n");
		exit(1);
	}

	if (EVP_CIPHER_CTX_set_padding(&ctx, 0) < 1) {
		fprintf(stderr, "EVP_CIPHER_CTX_set_padding() failed\n");
		exit(1);
	}

	int32_t sz_out = 0;

	if (EVP_EncryptUpdate(&ctx, iv.val8, &sz_out, iv.val8, 16) < 1) {
		fprintf(stderr, "EVP_EncryptUpdate() failed\n");
		exit(1);
	}

	if (sz_out != 16) {
		fprintf(stderr, "unexpected encrypted size: %d vs. 16\n", sz_out);
		exit(1);
	}

	EVP_CIPHER_CTX_cleanup(&ctx);
	EVP_CIPHER_CTX_init(&ctx);

	if (EVP_DecryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key + 16, NULL) < 1) {
		fprintf(stderr, "EVP_DecryptInit_ex() failed\n");
		exit(1);
	}

	if (EVP_CIPHER_CTX_set_padding(&ctx, 0) < 1) {
		fprintf(stderr, "EVP_CIPHER_CTX_set_padding() failed\n");
		exit(1);
	}

	while (sz_in > 0) {
		conv_t tmp;
		memcpy(tmp.val8, in, 16);

		tmp.val64[0] ^= iv.val64[0];
		tmp.val64[1] ^= iv.val64[1];

		sz_out = 0;

		if (EVP_DecryptUpdate(&ctx, tmp.val8, &sz_out, tmp.val8, 16) < 1) {
			fprintf(stderr, "EVP_DecryptUpdate() failed\n");
			exit(1);
		}

		if (sz_out != 16) {
			fprintf(stderr, "unexpected decrypted size: %d vs. 16\n", sz_out);
			exit(1);
		}

		tmp.val64[0] ^= iv.val64[0];
		tmp.val64[1] ^= iv.val64[1];

		memcpy(out, tmp.val8, 16);

		// multiply polynomial with x (shift left)

		uint64_t carry0 = iv.val64[0] >> 63;
		uint64_t carry1 = iv.val64[1] >> 63;

		iv.val64[0] = iv.val64[0] << 1;
		iv.val64[1] = (iv.val64[1] << 1) | carry0;

		// if we shifted out x ** 128, then subtract x ** 7 + x ** 2 + x + 1,
		// i.e., 10000111b or 0x87.

		iv.val64[0] ^= -carry1 & (uint64_t)0x87;

		sz_in -= 16;
		in += 16;
		out += 16;
	}

	EVP_CIPHER_CTX_cleanup(&ctx);
}

int32_t main(int32_t argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "usage: speed record-size iterations\n");
		exit(1);
	}

	char *end;
	uint64_t size = strtoul(argv[1], &end, 10);

	if (size > 1024 * 1024 || *end != 0) {
		fprintf(stderr, "invalid record size: %s\n", argv[1]);
		exit(1);
	}

	uint64_t iter = strtoul(argv[2], &end, 10);

	if (*end != 0) {
		fprintf(stderr, "invalid iterations: %s\n", argv[2]);
		exit(1);
	}

	uint8_t *buf = malloc(size);
	uint8_t *buf_enc = malloc(size);

	if (buf == NULL || buf_enc == NULL) {
		fprintf(stderr, "OOM\n");
		exit(1);
	}

	uint8_t key[32];
	memset(key, 0, sizeof(key));

	printf("encrypting\n");
	memset(buf, 0x11, size);
	memset(buf_enc, 0x22, size);

	uint64_t start = now();

	for (uint64_t i = 0; i < iter; ++i) {
		xts_encrypt(key, i, buf, size, buf_enc);
	}

	uint64_t stop = now();

	if (stop == start) {
		fprintf(stderr, "ran for less than 1 ms\n");
		stop = start + 1;
	}

	uint64_t tps_enc = iter * 1000 / (stop - start);

	printf("decrypting\n");
	memset(buf, 0x33, size);

	start = now();

	for (uint64_t i = 0; i < iter; ++i) {
		xts_decrypt(key, i, buf_enc, 16, buf);
		xts_decrypt(key, i, buf_enc, size, buf);
	}

	stop = now();

	if (stop == start) {
		fprintf(stderr, "ran for less than 1 ms\n");
		stop = start + 1;
	}

	uint64_t tps_dec = iter * 1000 / (stop - start);

#if 0
	for (uint64_t i = 0; i < size; ++i) {
		printf("%02x ", buf[i]);
	}

	printf("\n");
#endif

	printf("decrypting 2\n");
	memset(buf, 0x44, size);

	start = now();

	for (uint64_t i = 0; i < iter; ++i) {
		xts_decrypt2(key, i, buf_enc, size, buf);
	}

	stop = now();

	if (stop == start) {
		fprintf(stderr, "ran for less than 1 ms\n");
		stop = start + 1;
	}

	uint64_t tps_dec2 = iter * 1000 / (stop - start);

#if 0
	for (uint64_t i = 0; i < size; ++i) {
		printf("%02x ", buf[i]);
	}

	printf("\n");
#endif

	printf("%" PRIu64 ":%" PRIu64 ":%" PRIu64
			" (TPS encrypt:TPS decrypt:TPS decrypt 2)\n",
			tps_enc, tps_dec, tps_dec2);

	exit(0);
}
