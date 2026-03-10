/*
 * encrypt.h - Define the enryptor's interface
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#ifndef __MINGW32__
#include <sys/socket.h>
#else

#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

typedef const EVP_CIPHER cipher_kt_t;
typedef EVP_CIPHER_CTX *cipher_evp_t;
typedef const EVP_MD digest_type_t;
#define MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define MAX_IV_LENGTH EVP_MAX_IV_LENGTH
#define MAX_MD_SIZE EVP_MAX_MD_SIZE

#elif defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/cipher.h>
#include <mbedtls/gcm.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/md5.h>
#include <mbedtls/md.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

typedef mbedtls_cipher_info_t cipher_kt_t;
typedef mbedtls_cipher_context_t cipher_evp_t;
typedef mbedtls_md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_IV_LENGTH MBEDTLS_MAX_IV_LENGTH
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE

#endif

typedef struct {
#if defined(USE_CRYPTO_OPENSSL)
    EVP_CIPHER_CTX *evp;
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_cipher_context_t evp;
#endif
    uint8_t iv[MAX_IV_LENGTH];
} cipher_ctx_t;

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

//#define SODIUM_BLOCK_SIZE   64

#define NONE                -1
#define TABLE               0
#define RC4                 1
#define RC4_MD5             2
#define AES_128_CFB         3
#define AES_192_CFB         4
#define AES_256_CFB         5
#define BF_CFB              6
#define CAMELLIA_128_CFB    7
#define CAMELLIA_192_CFB    8
#define CAMELLIA_256_CFB    9
#define CAST5_CFB           10
#define DES_CFB             11
#define IDEA_CFB            12
#define RC2_CFB             13
#define SEED_CFB            14
#define AES_128_GCM         15
#define AES_192_GCM         16
#define AES_256_GCM         17
#define CHACHA20_IETF_POLY1305 18

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

typedef struct enc_info_t {
    int method;
    uint8_t key[MAX_KEY_LENGTH];
    int     key_len;
    int     iv_len;
    uint8_t *enc_table;
    uint8_t *dec_table;
} enc_info;

struct enc_ctx {
    uint8_t init;
    uint64_t counter;       /* nonce counter for AEAD, incremented per AE op */
    cipher_ctx_t evp;
    enc_info * info;
    uint8_t subkey[MAX_KEY_LENGTH]; /* AEAD per-session subkey derived from salt */
};

int enc_init(enc_info * info, const char *pass, const char *method);
void enc_free(enc_info * info);
int enc_ctx_init(enc_info * info, struct enc_ctx *ctx, int enc);
void enc_ctx_free(struct enc_ctx *ctx);
int ss_encrypt(struct enc_ctx *ctx, char *plaintext, size_t plen,
                  char * ciphertext, size_t * clen);
int ss_decrypt(struct enc_ctx *ctx, char *ciphertext, size_t clen,
                 char *plaintext, size_t *olen);
size_t ss_calc_buffer_size(struct enc_ctx *ctx, size_t ilen);
/* UDP-specific AEAD: [salt][enc(payload)+TAG], no length chunking */
int ss_udp_encrypt(enc_info *info, char *plaintext, size_t plen, char *ciphertext, size_t *clen);
int ss_udp_decrypt(enc_info *info, char *ciphertext, size_t clen, char *plaintext, size_t *olen);
#define is_aead_cipher(m) ((m) == AES_128_GCM || (m) == AES_192_GCM || (m) == AES_256_GCM || (m) == CHACHA20_IETF_POLY1305)

#endif // _ENCRYPT_H
