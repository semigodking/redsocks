/*
 * encrypt.c - Manage the global encryptor
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

#include <stdint.h>

#if defined(USE_CRYPTO_OPENSSL)

/* OpenSSL 3.0+ compatibility */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#define EVP_CIPHER_CTX_new_compat() EVP_CIPHER_CTX_new()
#define EVP_CIPHER_CTX_free_compat(ctx) EVP_CIPHER_CTX_free(ctx)
#define EVP_CIPHER_CTX_init_compat(ctx)
#define EVP_CIPHER_CTX_cleanup_compat(ctx)
#else
/* OpenSSL 1.1.x and earlier */
#define EVP_CIPHER_CTX_new_compat() EVP_CIPHER_CTX_new()
#define EVP_CIPHER_CTX_free_compat(ctx) EVP_CIPHER_CTX_free(ctx)
#define EVP_CIPHER_CTX_init_compat(ctx) EVP_CIPHER_CTX_init(ctx)
#define EVP_CIPHER_CTX_cleanup_compat(ctx) EVP_CIPHER_CTX_cleanup(ctx)
#endif

#elif defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/md5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#define CIPHER_UNSUPPORTED "unsupported"

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

#endif

#include "encrypt.h"

#define AEAD_TAG_LEN    16
#define AEAD_NONCE_LEN  12
#define AEAD_CHUNK_MAX  0x3FFF  /* SIP004: payload length capped at 16383 */

/* HKDF-SHA1: RFC 5869. info = "ss-subkey" per SIP004 */
static int hkdf_sha1(const uint8_t *key, int key_len,
                     const uint8_t *salt, int salt_len,
                     uint8_t *out, int out_len)
{
    const char *info = "ss-subkey";
    int info_len = 9;
#if defined(USE_CRYPTO_OPENSSL)
    uint8_t prk[20];
    unsigned int prk_len = sizeof(prk);
    if (!HMAC(EVP_sha1(), salt, salt_len, key, key_len, prk, &prk_len))
        return -1;
    /* HKDF-Expand: T(i) = HMAC-SHA1(PRK, T(i-1) || info || i) */
    uint8_t t[20], buf[20 + 9 + 1];
    unsigned int t_len = 0;
    int done = 0;
    for (uint8_t i = 1; done < out_len; i++) {
        int blen = t_len + info_len + 1;
        memcpy(buf, t, t_len);
        memcpy(buf + t_len, info, info_len);
        buf[t_len + info_len] = i;
        t_len = sizeof(t);
        if (!HMAC(EVP_sha1(), prk, prk_len, buf, blen, t, &t_len))
            return -1;
        int copy = min((int)t_len, out_len - done);
        memcpy(out + done, t, copy);
        done += copy;
    }
    return 0;
#elif defined(USE_CRYPTO_MBEDTLS)
    uint8_t prk[20];
    const mbedtls_md_info_t *sha1 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (mbedtls_md_hmac(sha1, salt, salt_len, key, key_len, prk) != 0)
        return -1;
    uint8_t t[20], buf[20 + 9 + 1];
    size_t t_len = 0;
    int done = 0;
    for (uint8_t i = 1; done < out_len; i++) {
        int blen = (int)t_len + info_len + 1;
        memcpy(buf, t, t_len);
        memcpy(buf + t_len, info, info_len);
        buf[t_len + info_len] = i;
        if (mbedtls_md_hmac(sha1, prk, sizeof(prk), buf, blen, t) != 0)
            return -1;
        t_len = 20;
        int copy = min((int)t_len, out_len - done);
        memcpy(out + done, t, copy);
        done += copy;
    }
    return 0;
#endif
}

/* Build 12-byte little-endian nonce from counter */
static void make_nonce(uint8_t nonce[AEAD_NONCE_LEN], uint64_t counter)
{
    memset(nonce, 0, AEAD_NONCE_LEN);
    /* little-endian */
    for (int i = 0; i < 8; i++)
        nonce[i] = (counter >> (8 * i)) & 0xff;
}

/* Single AEAD encrypt: plaintext -> ciphertext + tag. Returns 1 on success. */
static int aead_encrypt(const uint8_t *subkey, int key_len, int is_chacha,
                        const uint8_t nonce[AEAD_NONCE_LEN],
                        const uint8_t *plain, int plen,
                        uint8_t *out)  /* out must hold plen + AEAD_TAG_LEN */
{
#if defined(USE_CRYPTO_OPENSSL)
    const EVP_CIPHER *cipher = is_chacha ? EVP_chacha20_poly1305() :
                               (key_len == 16) ? EVP_aes_128_gcm() :
                               (key_len == 24) ? EVP_aes_192_gcm() :
                                                 EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = 0, clen = 0, flen = 0;
    if (!ctx) return 0;
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, subkey, nonce)) goto done;
    if (!EVP_EncryptUpdate(ctx, out, &clen, plain, plen)) goto done;
    if (!EVP_EncryptFinal_ex(ctx, out + clen, &flen)) goto done;
    int ctrl = is_chacha ? EVP_CTRL_AEAD_GET_TAG : EVP_CTRL_GCM_GET_TAG;
    if (!EVP_CIPHER_CTX_ctrl(ctx, ctrl, AEAD_TAG_LEN, out + clen + flen)) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
#elif defined(USE_CRYPTO_MBEDTLS)
    if (is_chacha) {
        mbedtls_chachapoly_context ctx;
        mbedtls_chachapoly_init(&ctx);
        int ok = 0;
        if (mbedtls_chachapoly_setkey(&ctx, subkey) != 0) goto done_cp_enc;
        if (mbedtls_chachapoly_encrypt_and_tag(&ctx, plen, nonce,
                                               NULL, 0, plain, out, out + plen) != 0) goto done_cp_enc;
        ok = 1;
done_cp_enc:
        mbedtls_chachapoly_free(&ctx);
        return ok;
    }
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ok = 0;
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, subkey, key_len * 8) != 0) goto done_enc;
    if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plen,
                                   nonce, AEAD_NONCE_LEN, NULL, 0,
                                   plain, out, AEAD_TAG_LEN, out + plen) != 0) goto done_enc;
    ok = 1;
done_enc:
    mbedtls_gcm_free(&gcm);
    return ok;
#endif
}

/* Single AEAD decrypt: ciphertext + tag -> plaintext. Returns 1 on success. */
static int aead_decrypt(const uint8_t *subkey, int key_len, int is_chacha,
                        const uint8_t nonce[AEAD_NONCE_LEN],
                        const uint8_t *in, int clen, /* clen excludes tag */
                        const uint8_t *tag,
                        uint8_t *out)
{
#if defined(USE_CRYPTO_OPENSSL)
    const EVP_CIPHER *cipher = is_chacha ? EVP_chacha20_poly1305() :
                               (key_len == 16) ? EVP_aes_128_gcm() :
                               (key_len == 24) ? EVP_aes_192_gcm() :
                                                 EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = 0, plen = 0, flen = 0;
    if (!ctx) return 0;
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, subkey, nonce)) goto done;
    int ctrl = is_chacha ? EVP_CTRL_AEAD_SET_TAG : EVP_CTRL_GCM_SET_TAG;
    if (!EVP_CIPHER_CTX_ctrl(ctx, ctrl, AEAD_TAG_LEN, (void *)tag)) goto done;
    if (!EVP_DecryptUpdate(ctx, out, &plen, in, clen)) goto done;
    if (!EVP_DecryptFinal_ex(ctx, out + plen, &flen)) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
#elif defined(USE_CRYPTO_MBEDTLS)
    if (is_chacha) {
        mbedtls_chachapoly_context ctx;
        mbedtls_chachapoly_init(&ctx);
        int ok = 0;
        if (mbedtls_chachapoly_setkey(&ctx, subkey) != 0) goto done_cp_dec;
        if (mbedtls_chachapoly_auth_decrypt(&ctx, clen, nonce,
                                            NULL, 0, tag, in, out) != 0) goto done_cp_dec;
        ok = 1;
done_cp_dec:
        mbedtls_chachapoly_free(&ctx);
        return ok;
    }
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ok = 0;
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, subkey, key_len * 8) != 0) goto done_dec;
    if (mbedtls_gcm_auth_decrypt(&gcm, clen, nonce, AEAD_NONCE_LEN,
                                  NULL, 0, tag, AEAD_TAG_LEN, in, out) != 0) goto done_dec;
    ok = 1;
done_dec:
    mbedtls_gcm_free(&gcm);
    return ok;
#endif
}

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

#ifdef DEBUG
static void dump(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++) {
        printf("0x%02x ", (uint8_t)text[i]);
    }
    printf("\n");
}
#endif

static const char * supported_ciphers[] =
{
    "table",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
};

#ifdef USE_CRYPTO_MBEDTLS
static const char * supported_ciphers_mbedtls[] =
{
    "table",
    "ARC4-128",
    "ARC4-128",
    "AES-128-CFB128",
    "AES-192-CFB128",
    "AES-256-CFB128",
    "BLOWFISH-CFB64",
    "CAMELLIA-128-CFB128",
    "CAMELLIA-192-CFB128",
    "CAMELLIA-256-CFB128",
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
};
#endif

#define CIPHER_NUM (sizeof(supported_ciphers)/sizeof(supported_ciphers[0]))

/* Check if the method uses GCM mode (AEAD cipher) */
static int is_aead_mode(int method)
{
    return (method == AES_128_GCM || method == AES_192_GCM || method == AES_256_GCM
            || method == CHACHA20_IETF_POLY1305);
}

static int random_compare(const void *_x, const void *_y, uint32_t i,
                          uint64_t a)
{
    uint8_t x = *((uint8_t *)_x);
    uint8_t y = *((uint8_t *)_y);
    return a % (x + i) - a % (y + i);
}

static void merge(uint8_t *left, int llength, uint8_t *right,
                  int rlength, uint32_t salt, uint64_t key)
{
    uint8_t *ltmp = (uint8_t *)malloc(llength * sizeof(uint8_t));
    uint8_t *rtmp = (uint8_t *)malloc(rlength * sizeof(uint8_t));

    if (!ltmp || !rtmp) {
        free(ltmp);
        free(rtmp);
        return;
    }

    uint8_t *ll = ltmp;
    uint8_t *rr = rtmp;

    uint8_t *result = left;

    memcpy(ltmp, left, llength * sizeof(uint8_t));
    memcpy(rtmp, right, rlength * sizeof(uint8_t));

    while (llength > 0 && rlength > 0) {
        if (random_compare(ll, rr, salt, key) <= 0) {
            *result = *ll;
            ++ll;
            --llength;
        } else {
            *result = *rr;
            ++rr;
            --rlength;
        }
        ++result;
    }

    if (llength > 0) {
        while (llength > 0) {
            *result = *ll;
            ++result;
            ++ll;
            --llength;
        }
    } else {
        while (rlength > 0) {
            *result = *rr;
            ++result;
            ++rr;
            --rlength;
        }
    }

    free(ltmp);
    free(rtmp);
}

static void merge_sort(uint8_t array[], int length,
                       uint32_t salt, uint64_t key)
{
    uint8_t middle;
    uint8_t *left, *right;
    int llength;

    if (length <= 1) {
        return;
    }

    middle = length / 2;

    llength = length - middle;

    left = array;
    right = array + llength;

    merge_sort(left, llength, salt, key);
    merge_sort(right, middle, salt, key);
    merge(left, llength, right, middle, salt, key);
}

static unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md)
{
#if defined(USE_CRYPTO_OPENSSL)
    static unsigned char m[16];
    if (md == NULL) {
        md = m;
    }
    MD5(d, n, md);
    return md;
#elif defined(USE_CRYPTO_MBEDTLS)
    static unsigned char m[16];
    if (md == NULL) {
        md = m;
    }
    mbedtls_md5(d, n, md);
    return md;
#endif
}

static void enc_table_init(enc_info * info, const char *pass)
{
    uint32_t i;
    uint64_t key = 0;
    uint8_t *digest;

    info->enc_table = malloc(256);
    info->dec_table = malloc(256);

    digest = enc_md5((const uint8_t *)pass, strlen(pass), NULL);

    for (i = 0; i < 8; i++) {
        key += OFFSET_ROL(digest, i);
    }

    for (i = 0; i < 256; ++i) {
        info->enc_table[i] = i;
    }
    for (i = 1; i < 1024; ++i) {
        merge_sort(info->enc_table, 256, i, key);
    }
    for (i = 0; i < 256; ++i) {
        // gen decrypt table from encrypt table
        info->dec_table[info->enc_table[i]] = i;
    }
}

int cipher_iv_size(const cipher_kt_t *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CIPHER_iv_length(cipher);
#elif defined(USE_CRYPTO_MBEDTLS)
    if (cipher == NULL)
        return 0;
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);
    if (mbedtls_cipher_setup(&ctx, cipher) != 0) {
        mbedtls_cipher_free(&ctx);
        return 0;
    }
    int iv_size = mbedtls_cipher_get_iv_size(&ctx);
    mbedtls_cipher_free(&ctx);
    return iv_size;
#endif
}

int cipher_key_size(const cipher_kt_t *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CIPHER_key_length(cipher);
#elif defined(USE_CRYPTO_MBEDTLS)
    if (cipher == NULL)
        return 0;
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);
    if (mbedtls_cipher_setup(&ctx, cipher) != 0) {
        mbedtls_cipher_free(&ctx);
        return 0;
    }
    int key_bits = mbedtls_cipher_get_key_bitlen(&ctx);
    mbedtls_cipher_free(&ctx);
    return key_bits / 8;
#endif
}

int bytes_to_key(const cipher_kt_t *cipher, const digest_type_t *md,
                 const uint8_t *pass, uint8_t *key, uint8_t *iv)
{
    size_t datal;
    datal = strlen((const char *)pass);
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_BytesToKey(cipher, md, NULL, pass, datal, 1, key, iv);
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_md_context_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    int niv;
    int nkey;
    int addmd;
    unsigned int mds;
    unsigned int i;
    int rv;

    nkey = cipher_key_size(cipher);
    niv = cipher_iv_size(cipher);
    rv = nkey;
    if (pass == NULL) {
        return nkey;
    }

    mbedtls_md_init(&c);
    if (mbedtls_md_setup(&c, md, 0) != 0) {
        mbedtls_md_free(&c);
        return 0;
    }
    addmd = 0;
    mds = mbedtls_md_get_size(md);
    for (;; ) {
        int error;
        do {
            error = 1;
            if (mbedtls_md_starts(&c) != 0) {
                break;
            }
            if (addmd) {
                if (mbedtls_md_update(&c, &(md_buf[0]), mds) != 0) {
                    break;
                }
            } else {
                addmd = 1;
            }
            if (mbedtls_md_update(&c, pass, datal) != 0) {
                break;
            }
            if (mbedtls_md_finish(&c, &(md_buf[0])) != 0) {
                break;
            }
            error = 0;
        } while (0);
        if (error) {
            mbedtls_md_free(&c);
            memset(md_buf, 0, MAX_MD_SIZE);
            return 0;
        }

        i = 0;
        if (nkey) {
            for (;; ) {
                if (nkey == 0) {
                    break;
                }
                if (i == mds) {
                    break;
                }
                if (key != NULL) {
                    *(key++) = md_buf[i];
                }
                nkey--;
                i++;
            }
        }
        if (niv && (i != mds)) {
            for (;; ) {
                if (niv == 0) {
                    break;
                }
                if (i == mds) {
                    break;
                }
                if (iv != NULL) {
                    *(iv++) = md_buf[i];
                }
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0)) {
            break;
        }
    }
    mbedtls_md_free(&c);
    memset(md_buf, 0, MAX_MD_SIZE);
    return rv;
#endif
}

int rand_bytes(uint8_t *output, int len)
{
#if defined(USE_CRYPTO_OPENSSL)
    return RAND_bytes(output, len);
#elif defined(USE_CRYPTO_MBEDTLS)
    static mbedtls_entropy_context ec = {};
    static mbedtls_ctr_drbg_context cd_ctx = {};
    static unsigned char rand_initialised = 0;
    const size_t blen = min(len, MBEDTLS_CTR_DRBG_MAX_REQUEST);

    if (!rand_initialised) {
#ifdef _WIN32
        HCRYPTPROV hProvider;
        union {
            unsigned __int64 seed;
            BYTE buffer[8];
        } rand_buffer;

        hProvider = 0;
        if (CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, \
                                CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            CryptGenRandom(hProvider, 8, rand_buffer.buffer);
            CryptReleaseContext(hProvider, 0);
        } else {
            rand_buffer.seed = (unsigned __int64)clock();
        }
#else
        FILE *urand;
        union {
            uint64_t seed;
            uint8_t buffer[8];
        } rand_buffer;

        urand = fopen("/dev/urandom", "r");
        if (urand) {
            int read = fread(&rand_buffer.seed, sizeof(rand_buffer.seed), 1,
                             urand);
            fclose(urand);
            if (read <= 0) {
                rand_buffer.seed = (uint64_t)clock();
            }
        } else {
            rand_buffer.seed = (uint64_t)clock();
        }
#endif
        mbedtls_entropy_init(&ec);
        if (mbedtls_ctr_drbg_seed(&cd_ctx, mbedtls_entropy_func, &ec,
                          (const unsigned char *)rand_buffer.buffer, 8) != 0) {
            mbedtls_ctr_drbg_free(&cd_ctx);
            mbedtls_entropy_free(&ec);
            return 0;
        }
        rand_initialised = 1;
    }
    while (len > 0) {
        if (mbedtls_ctr_drbg_random(&cd_ctx, output, blen) != 0) {
            return 0;
        }
        output += blen;
        len -= blen;
    }
    return 1;
#endif
}

const cipher_kt_t *get_cipher_type(int method)
{
    if (method <= TABLE || method >= CIPHER_NUM) {
        //LOGE("get_cipher_type(): Illegal method");
        return NULL;
    }

    if (method == RC4_MD5) {
        method = RC4;
    }
#if defined(USE_CRYPTO_OPENSSL)
    if (method == CHACHA20_IETF_POLY1305)
        return EVP_get_cipherbyname("chacha20-poly1305");
    const char *ciphername = supported_ciphers[method];
    return EVP_get_cipherbyname(ciphername);
#elif defined(USE_CRYPTO_MBEDTLS)
    const char *mbedtls_name = supported_ciphers_mbedtls[method];
    if (strcmp(mbedtls_name, CIPHER_UNSUPPORTED) == 0) {
        //LOGE("Cipher %s currently is not supported by mbedTLS library",
        //     ciphername);
        return NULL;
    }
    return mbedtls_cipher_info_from_string(mbedtls_name);
#endif
}

const digest_type_t *get_digest_type(const char *digest)
{
    if (digest == NULL) {
        //LOGE("get_digest_type(): Digest name is null");
        return NULL;
    }

#if defined(USE_CRYPTO_OPENSSL)
    return EVP_get_digestbyname(digest);
#elif defined(USE_CRYPTO_MBEDTLS)
    return mbedtls_md_info_from_string(digest);
#endif
}

static int cipher_context_init(const enc_info * info, cipher_ctx_t *ctx, int enc)
{
    int method = info->method;
    if (method <= TABLE || method >= CIPHER_NUM) {
        // Illegal method
        return -1;
    }
#if defined(USE_CRYPTO_OPENSSL)
    cipher_evp_t evp = EVP_CIPHER_CTX_new_compat();
    if (evp == NULL) {
        // Cannot allocate cipher context
        return -1;
    }
    ctx->evp = evp;

    const cipher_kt_t *cipher = get_cipher_type(method);
    if (cipher == NULL) {
        // Cipher is not found in OpenSSL library
        EVP_CIPHER_CTX_free_compat(evp);
        ctx->evp = NULL;
        return -1;
    }
    EVP_CIPHER_CTX_init_compat(evp);
    if (!EVP_CipherInit_ex(evp, cipher, NULL, NULL, NULL, enc)) {
        // Cannot initialize cipher
        EVP_CIPHER_CTX_free_compat(evp);
        ctx->evp = NULL;
        return -1;
    }
    if (!EVP_CIPHER_CTX_set_key_length(evp, info->key_len)) {
        EVP_CIPHER_CTX_cleanup_compat(evp);
        EVP_CIPHER_CTX_free_compat(evp);
        ctx->evp = NULL;
        // Invalid key length
        return -1;
    }
    if (is_aead_mode(method)) {
        /* GCM mode - disable padding and set tag length */
        EVP_CIPHER_CTX_set_padding(evp, 0);
        /* Tag length will be set after initialization */
    } else if (method > RC4_MD5) {
        EVP_CIPHER_CTX_set_padding(evp, 1);
    }
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_cipher_context_t *evp = &ctx->evp;
    const cipher_kt_t *cipher = get_cipher_type(method);
    if (cipher == NULL) {
        // Cipher is not found in mbedTLS library
        return -1;
    }
    mbedtls_cipher_init(evp);
    if (mbedtls_cipher_setup(evp, cipher) != 0) {
        mbedtls_cipher_free(evp);
        return -1;
    }
#endif
    return 0;
}

static void cipher_context_set_iv(const enc_info * info, cipher_ctx_t *ctx, uint8_t *iv, size_t iv_len,
                           int enc)
{
    const unsigned char *true_key;

    if (iv == NULL) {
        //LOGE("cipher_context_set_iv(): IV is null");
        return;
    }

    if (enc) {
        rand_bytes(iv, iv_len);
    }
    if (info->method == RC4_MD5) {
        unsigned char key_iv[32];
        memcpy(key_iv, info->key, 16);
        memcpy(key_iv + 16, iv, 16);
        true_key = enc_md5(key_iv, 32, NULL);
        iv_len = 0;
    } else {
        true_key = info->key;
    }

#if defined(USE_CRYPTO_OPENSSL)
    cipher_evp_t evp = ctx->evp;
    if (evp == NULL) {
        //LOGE("cipher_context_set_iv(): Cipher context is null");
        return;
    }
    if (!EVP_CipherInit_ex(evp, NULL, NULL, true_key, iv, enc)) {
        EVP_CIPHER_CTX_cleanup_compat(evp);
        //FATAL("Cannot set key and IV");
    }
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_cipher_context_t *evp = &ctx->evp;
    if (mbedtls_cipher_setkey(evp, true_key, info->key_len * 8,
                             enc ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) != 0) {
        mbedtls_cipher_free(evp);
        //FATAL("Cannot set mbedTLS cipher key");
    }
    if (mbedtls_cipher_set_iv(evp, iv, iv_len) != 0) {
        mbedtls_cipher_free(evp);
        //FATAL("Cannot set mbedTLS cipher IV");
    }
    if (mbedtls_cipher_reset(evp) != 0) {
        mbedtls_cipher_free(evp);
        //FATAL("Cannot reset mbedTLS cipher context");
    }
#endif

#ifdef DEBUG
    dump("IV", (char *)iv, iv_len);
#endif
}

static void cipher_context_release(enc_info * info, cipher_ctx_t *ctx)
{
#if defined(USE_CRYPTO_OPENSSL)
    cipher_evp_t evp = ctx->evp;
    if (evp != NULL) {
        EVP_CIPHER_CTX_cleanup_compat(evp);
        EVP_CIPHER_CTX_free_compat(evp);
        ctx->evp = NULL;
    }
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_cipher_context_t *evp = &ctx->evp;
    mbedtls_cipher_free(evp);
#endif
}

static int cipher_context_update(cipher_ctx_t *ctx, uint8_t *output, int *olen,
                                 const uint8_t *input, int ilen)
{
#if defined(USE_CRYPTO_OPENSSL)
    EVP_CIPHER_CTX *evp = ctx->evp;
    return EVP_CipherUpdate(evp, (uint8_t *)output, olen,
                            (const uint8_t *)input, (size_t)ilen);
#elif defined(USE_CRYPTO_MBEDTLS)
    size_t outlen = *olen;
    int ret = mbedtls_cipher_update(&ctx->evp, (const uint8_t *)input, (size_t)ilen,
                          (uint8_t *)output, &outlen);
    *olen = (int)outlen;
    return (ret == 0) ? 1 : 0;
#endif
}

/* Calculate buffer size required for encrypt/decrypt data */
size_t ss_calc_buffer_size(struct enc_ctx * ctx, size_t ilen)
{
    int method = ctx->info->method;
    if (is_aead_mode(method)) {
        /*
         * SIP004 TCP format:
         *   first call: [salt] + N * ([2+TAG] + [payload+TAG])
         *   subsequent: N * ([2+TAG] + [payload+TAG])
         * Worst case: each byte could be its own chunk.
         * In practice ilen <= AEAD_CHUNK_MAX, so one chunk:
         *   (2 + AEAD_TAG_LEN) + (ilen + AEAD_TAG_LEN)
         */
        size_t salt_len = ctx->init ? 0 : ctx->info->key_len;
        size_t chunks = (ilen + AEAD_CHUNK_MAX - 1) / AEAD_CHUNK_MAX;
        if (chunks == 0) chunks = 1;
        return salt_len + chunks * (2 + AEAD_TAG_LEN + AEAD_CHUNK_MAX + AEAD_TAG_LEN);
    }
#if defined(USE_CRYPTO_OPENSSL)
    const cipher_kt_t *cipher = get_cipher_type(method);
    if (cipher == NULL)
        return ilen;
    if (ctx->init)
        return ilen + EVP_CIPHER_block_size(cipher);
    else
        return EVP_CIPHER_iv_length(cipher) + ilen + EVP_CIPHER_block_size(cipher);
#elif defined(USE_CRYPTO_MBEDTLS)
    const cipher_kt_t *cipher = get_cipher_type(method);
    if (cipher == NULL)
        return ilen;
    if (ctx->init)
        return ilen + mbedtls_cipher_get_block_size(&ctx->evp.evp);
    else
        return mbedtls_cipher_get_iv_size(&ctx->evp.evp) + ilen + mbedtls_cipher_get_block_size(&ctx->evp.evp);
#endif
}

int ss_encrypt(struct enc_ctx *ctx, char *plaintext, size_t plen,
                  char * ciphertext, size_t * clen)
{
    if (ctx != NULL && ctx->info->method != TABLE) {
        if (is_aead_mode(ctx->info->method)) {
            /*
             * SIP004 TCP AEAD encrypt:
             *   First call: prepend salt, derive subkey via HKDF-SHA1
             *   Each chunk: [enc(2-byte-len) + TAG] [enc(payload) + TAG]
             *   Nonce: 12-byte little-endian counter, incremented per AE op
             */
            uint8_t *out = (uint8_t *)ciphertext;
            size_t out_len = 0;
            int key_len = ctx->info->key_len;
            int is_chacha = (ctx->info->method == CHACHA20_IETF_POLY1305);

            if (!ctx->init) {
                /* Generate salt and derive subkey */
                rand_bytes(out, key_len);
                if (hkdf_sha1(ctx->info->key, key_len, out, key_len,
                              ctx->subkey, key_len) != 0)
                    return 0;
                out += key_len;
                out_len += key_len;
                ctx->counter = 0;
                ctx->init = 1;
            }

            const uint8_t *src = (const uint8_t *)plaintext;
            size_t remaining = plen;
            uint8_t nonce[AEAD_NONCE_LEN];

            while (remaining > 0) {
                uint16_t chunk = (uint16_t)min(remaining, (size_t)AEAD_CHUNK_MAX);

                /* Encrypt 2-byte length */
                uint8_t len_buf[2] = { (chunk >> 8) & 0xff, chunk & 0xff };
                make_nonce(nonce, ctx->counter++);
                if (!aead_encrypt(ctx->subkey, key_len, is_chacha, nonce,
                                    len_buf, 2, out))
                    return 0;
                out += 2 + AEAD_TAG_LEN;
                out_len += 2 + AEAD_TAG_LEN;

                /* Encrypt payload */
                make_nonce(nonce, ctx->counter++);
                if (!aead_encrypt(ctx->subkey, key_len, is_chacha, nonce,
                                    src, chunk, out))
                    return 0;
                out += chunk + AEAD_TAG_LEN;
                out_len += chunk + AEAD_TAG_LEN;

                src += chunk;
                remaining -= chunk;
            }
            *clen = out_len;
            return 1;
        }

        int err = 1;
        int iv_len = 0;
        int p_len = plen, c_len = plen;
        if (!ctx->init) {
            iv_len = ctx->info->iv_len;
        }

        if (!ctx->init) {
            uint8_t iv[MAX_IV_LENGTH];
            cipher_context_set_iv(ctx->info, &ctx->evp, iv, iv_len, 1);
            memcpy(ciphertext, iv, iv_len);
            ctx->counter = 0;
            ctx->init = 1;
        }

        err = cipher_context_update(&ctx->evp,
                                    (uint8_t *)(ciphertext + iv_len),
                                    &c_len, (const uint8_t *)plaintext,
                                    p_len);
        if (!err)
            return 0;

#ifdef DEBUG
        dump("PLAIN", plaintext, p_len);
        dump("CIPHER", ciphertext + iv_len, c_len);
#endif
        *clen = iv_len + c_len;
        return 1;
    } else {
        char *begin = plaintext;
        while (plaintext < begin + plen) {
            *ciphertext = (char)ctx->info->enc_table[(uint8_t)*plaintext];
            plaintext++;
            ciphertext++;
        }
        *clen = plen;
        return 1;
    }
}

/* You need to ensure you have enough output buffer allocated */
int ss_decrypt(struct enc_ctx *ctx, char *ciphertext, size_t clen,
                 char *plaintext, size_t *olen)
{
    if (ctx != NULL && ctx->info->method != TABLE) {
        if (is_aead_mode(ctx->info->method)) {
            /*
             * SIP004 TCP AEAD decrypt:
             *   First call: read salt, derive subkey via HKDF-SHA1
             *   Each chunk: decrypt [enc(2-byte-len)+TAG] then [enc(payload)+TAG]
             */
            const uint8_t *in = (const uint8_t *)ciphertext;
            size_t in_remaining = clen;
            uint8_t *out = (uint8_t *)plaintext;
            size_t out_len = 0;
            int key_len = ctx->info->key_len;
            int is_chacha = (ctx->info->method == CHACHA20_IETF_POLY1305);
            uint8_t nonce[AEAD_NONCE_LEN];

            if (!ctx->init) {
                if (in_remaining < (size_t)key_len)
                    return 0;
                if (hkdf_sha1(ctx->info->key, key_len, in, key_len,
                              ctx->subkey, key_len) != 0)
                    return 0;
                in += key_len;
                in_remaining -= key_len;
                ctx->counter = 0;
                ctx->init = 1;
            }

            while (in_remaining > 0) {
                /* Need at least encrypted length field */
                if (in_remaining < 2 + AEAD_TAG_LEN)
                    break;

                /* Decrypt length */
                uint8_t len_plain[2];
                make_nonce(nonce, ctx->counter);
                if (!aead_decrypt(ctx->subkey, key_len, is_chacha, nonce,
                                    in, 2, in + 2, len_plain))
                    return 0;
                ctx->counter++;

                uint16_t chunk = ((uint16_t)len_plain[0] << 8) | len_plain[1];
                if (chunk > AEAD_CHUNK_MAX)
                    return 0;

                in += 2 + AEAD_TAG_LEN;
                in_remaining -= 2 + AEAD_TAG_LEN;

                /* Need full encrypted payload */
                if (in_remaining < (size_t)(chunk + AEAD_TAG_LEN))
                    break;

                /* Decrypt payload */
                make_nonce(nonce, ctx->counter);
                if (!aead_decrypt(ctx->subkey, key_len, is_chacha, nonce,
                                    in, chunk, in + chunk, out))
                    return 0;
                ctx->counter++;

                out += chunk;
                out_len += chunk;
                in += chunk + AEAD_TAG_LEN;
                in_remaining -= chunk + AEAD_TAG_LEN;
            }
            *olen = out_len;
            return 1;
        }

        int p_len = clen;
        int iv_len = 0;
        int err = 1;

        if (!ctx->init) {
            iv_len = ctx->info->iv_len;
            p_len -= iv_len;
            cipher_context_set_iv(ctx->info, &ctx->evp, (uint8_t *)ciphertext, iv_len, 0);
            ctx->counter = 0;
            ctx->init = 1;
        }

        err = cipher_context_update(&ctx->evp, (uint8_t *)plaintext, &p_len,
                                    (const uint8_t *)(ciphertext + iv_len),
                                    clen - iv_len);
        if (!err)
            return 0;

        *olen = p_len;
        return 1;
    } else {
        char *begin = ciphertext;
        while (ciphertext < begin + clen) {
            *plaintext = (char)ctx->info->dec_table[(uint8_t)*ciphertext];
            ciphertext++;
            plaintext++;
        }
        *olen = clen;
        return 1;
    }
}

int enc_ctx_init(enc_info * info, struct enc_ctx *ctx, int enc)
{
    memset(ctx, 0, sizeof(struct enc_ctx));
    ctx->info = info;
    if (is_aead_mode(info->method))
        return 0;  /* GCM uses per-operation contexts, no persistent ctx needed */
    return cipher_context_init(info, &ctx->evp, enc);
}

void enc_ctx_free(struct enc_ctx *ctx)
{
    if (!is_aead_mode(ctx->info->method))
        cipher_context_release(ctx->info, &ctx->evp);
}

static int enc_key_init(enc_info * info, int method, const char *pass)
{
    if (method <= TABLE || method >= CIPHER_NUM)
        return -1;

#if defined(USE_CRYPTO_OPENSSL)
    /* OpenSSL 3.0+ - algorithms are loaded automatically */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    OpenSSL_add_all_algorithms();
#endif
#endif

    uint8_t iv[MAX_IV_LENGTH];

    const cipher_kt_t *cipher = NULL;

    cipher = (cipher_kt_t *)get_cipher_type(method);

    if (cipher == NULL)
        return -1;

    const digest_type_t *md = get_digest_type("MD5");
    if (md == NULL)
        return -1;

    info->key_len = bytes_to_key(cipher, md, (const uint8_t *)pass, info->key, iv);
    if (info->key_len == 0) {
        //FATAL("Cannot generate key and IV");
        return -1;
    }
    if (method == RC4_MD5) {
        info->iv_len = 16;
    } else {
        info->iv_len = cipher_iv_size(cipher);
    }
    info->method = method;
    return method;
}

int enc_init(enc_info * info, const char *pass, const char *method)
{
    memset((void *)info, 0, sizeof(enc_info));
    int m = TABLE;
    if (method != NULL) {
        for (m = TABLE; m < CIPHER_NUM; m++) {
            if (strcmp(method, supported_ciphers[m]) == 0) {
                break;
            }
        }
        if (m >= CIPHER_NUM)
            // Invalid encryption method
            return -1;
    }
    if (m == TABLE) {
        enc_table_init(info, pass);
    } else {
        m = enc_key_init(info, m, pass);
    }
    return m;
}

void enc_free(enc_info * info)
{
    if (info->enc_table)
    {
        free(info->enc_table);
        info->enc_table = NULL;
    }
    if (info->dec_table)
    {
        free(info->dec_table);
        info->dec_table = NULL;
    }

}
