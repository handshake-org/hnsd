/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "secp256k1.h"

#include "util.h"
#include "num_impl.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"
#include "ecmult_gen_impl.h"
#include "ecdsa_impl.h"
#include "eckey_impl.h"
#include "hash_impl.h"
#include "scratch_impl.h"

#define ARG_CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        hsk_secp256k1_callback_call(&ctx->illegal_callback, #cond); \
        return 0; \
    } \
} while(0)

static void default_illegal_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] illegal argument: %s\n", str);
    abort();
}

static const hsk_secp256k1_callback default_illegal_callback = {
    default_illegal_callback_fn,
    NULL
};

static void default_error_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] internal consistency check failed: %s\n", str);
    abort();
}

static const hsk_secp256k1_callback default_error_callback = {
    default_error_callback_fn,
    NULL
};


struct hsk_secp256k1_context_struct {
    hsk_secp256k1_ecmult_context ecmult_ctx;
    hsk_secp256k1_ecmult_gen_context ecmult_gen_ctx;
    hsk_secp256k1_callback illegal_callback;
    hsk_secp256k1_callback error_callback;
};

hsk_secp256k1_context* hsk_secp256k1_context_create(unsigned int flags) {
    hsk_secp256k1_context* ret = (hsk_secp256k1_context*)checked_malloc(&default_error_callback, sizeof(hsk_secp256k1_context));
    ret->illegal_callback = default_illegal_callback;
    ret->error_callback = default_error_callback;

    if (EXPECT((flags & HSK_SECP256K1_FLAGS_TYPE_MASK) != HSK_SECP256K1_FLAGS_TYPE_CONTEXT, 0)) {
            hsk_secp256k1_callback_call(&ret->illegal_callback,
                                    "Invalid flags");
            free(ret);
            return NULL;
    }

    hsk_secp256k1_ecmult_context_init(&ret->ecmult_ctx);
    hsk_secp256k1_ecmult_gen_context_init(&ret->ecmult_gen_ctx);

    if (flags & HSK_SECP256K1_FLAGS_BIT_CONTEXT_SIGN) {
        hsk_secp256k1_ecmult_gen_context_build(&ret->ecmult_gen_ctx, &ret->error_callback);
    }
    if (flags & HSK_SECP256K1_FLAGS_BIT_CONTEXT_VERIFY) {
        hsk_secp256k1_ecmult_context_build(&ret->ecmult_ctx, &ret->error_callback);
    }

    return ret;
}

hsk_secp256k1_context* hsk_secp256k1_context_clone(const hsk_secp256k1_context* ctx) {
    hsk_secp256k1_context* ret = (hsk_secp256k1_context*)checked_malloc(&ctx->error_callback, sizeof(hsk_secp256k1_context));
    ret->illegal_callback = ctx->illegal_callback;
    ret->error_callback = ctx->error_callback;
    hsk_secp256k1_ecmult_context_clone(&ret->ecmult_ctx, &ctx->ecmult_ctx, &ctx->error_callback);
    hsk_secp256k1_ecmult_gen_context_clone(&ret->ecmult_gen_ctx, &ctx->ecmult_gen_ctx, &ctx->error_callback);
    return ret;
}

void hsk_secp256k1_context_destroy(hsk_secp256k1_context* ctx) {
    if (ctx != NULL) {
        hsk_secp256k1_ecmult_context_clear(&ctx->ecmult_ctx);
        hsk_secp256k1_ecmult_gen_context_clear(&ctx->ecmult_gen_ctx);

        free(ctx);
    }
}

void hsk_secp256k1_context_set_illegal_callback(hsk_secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    if (fun == NULL) {
        fun = default_illegal_callback_fn;
    }
    ctx->illegal_callback.fn = fun;
    ctx->illegal_callback.data = data;
}

void hsk_secp256k1_context_set_error_callback(hsk_secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    if (fun == NULL) {
        fun = default_error_callback_fn;
    }
    ctx->error_callback.fn = fun;
    ctx->error_callback.data = data;
}

hsk_secp256k1_scratch_space* hsk_secp256k1_scratch_space_create(const hsk_secp256k1_context* ctx, size_t init_size, size_t max_size) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(max_size >= init_size);

    return hsk_secp256k1_scratch_create(&ctx->error_callback, init_size, max_size);
}

void hsk_secp256k1_scratch_space_destroy(hsk_secp256k1_scratch_space* scratch) {
    hsk_secp256k1_scratch_destroy(scratch);
}

static int hsk_secp256k1_pubkey_load(const hsk_secp256k1_context* ctx, hsk_secp256k1_ge* ge, const hsk_secp256k1_pubkey* pubkey) {
    if (sizeof(hsk_secp256k1_ge_storage) == 64) {
        /* When the hsk_secp256k1_ge_storage type is exactly 64 byte, use its
         * representation inside hsk_secp256k1_pubkey, as conversion is very fast.
         * Note that hsk_secp256k1_pubkey_save must use the same representation. */
        hsk_secp256k1_ge_storage s;
        memcpy(&s, &pubkey->data[0], sizeof(s));
        hsk_secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        hsk_secp256k1_fe x, y;
        hsk_secp256k1_fe_set_b32(&x, pubkey->data);
        hsk_secp256k1_fe_set_b32(&y, pubkey->data + 32);
        hsk_secp256k1_ge_set_xy(ge, &x, &y);
    }
    ARG_CHECK(!hsk_secp256k1_fe_is_zero(&ge->x));
    return 1;
}

static void hsk_secp256k1_pubkey_save(hsk_secp256k1_pubkey* pubkey, hsk_secp256k1_ge* ge) {
    if (sizeof(hsk_secp256k1_ge_storage) == 64) {
        hsk_secp256k1_ge_storage s;
        hsk_secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, sizeof(s));
    } else {
        VERIFY_CHECK(!hsk_secp256k1_ge_is_infinity(ge));
        hsk_secp256k1_fe_normalize_var(&ge->x);
        hsk_secp256k1_fe_normalize_var(&ge->y);
        hsk_secp256k1_fe_get_b32(pubkey->data, &ge->x);
        hsk_secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

int hsk_secp256k1_ec_pubkey_parse(const hsk_secp256k1_context* ctx, hsk_secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen) {
    hsk_secp256k1_ge Q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input != NULL);
    if (!hsk_secp256k1_eckey_pubkey_parse(&Q, input, inputlen)) {
        return 0;
    }
    hsk_secp256k1_pubkey_save(pubkey, &Q);
    hsk_secp256k1_ge_clear(&Q);
    return 1;
}

int hsk_secp256k1_ec_pubkey_serialize(const hsk_secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const hsk_secp256k1_pubkey* pubkey, unsigned int flags) {
    hsk_secp256k1_ge Q;
    size_t len;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(*outputlen >= ((flags & HSK_SECP256K1_FLAGS_BIT_COMPRESSION) ? 33 : 65));
    len = *outputlen;
    *outputlen = 0;
    ARG_CHECK(output != NULL);
    memset(output, 0, len);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK((flags & HSK_SECP256K1_FLAGS_TYPE_MASK) == HSK_SECP256K1_FLAGS_TYPE_COMPRESSION);
    if (hsk_secp256k1_pubkey_load(ctx, &Q, pubkey)) {
        ret = hsk_secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & HSK_SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}

static void hsk_secp256k1_ecdsa_signature_load(const hsk_secp256k1_context* ctx, hsk_secp256k1_scalar* r, hsk_secp256k1_scalar* s, const hsk_secp256k1_ecdsa_signature* sig) {
    (void)ctx;
    if (sizeof(hsk_secp256k1_scalar) == 32) {
        /* When the hsk_secp256k1_scalar type is exactly 32 byte, use its
         * representation inside hsk_secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that hsk_secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        hsk_secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        hsk_secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
}

static void hsk_secp256k1_ecdsa_signature_save(hsk_secp256k1_ecdsa_signature* sig, const hsk_secp256k1_scalar* r, const hsk_secp256k1_scalar* s) {
    if (sizeof(hsk_secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        hsk_secp256k1_scalar_get_b32(&sig->data[0], r);
        hsk_secp256k1_scalar_get_b32(&sig->data[32], s);
    }
}

int hsk_secp256k1_ecdsa_signature_parse_der(const hsk_secp256k1_context* ctx, hsk_secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    hsk_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input != NULL);

    if (hsk_secp256k1_ecdsa_sig_parse(&r, &s, input, inputlen)) {
        hsk_secp256k1_ecdsa_signature_save(sig, &r, &s);
        return 1;
    } else {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }
}

int hsk_secp256k1_ecdsa_signature_parse_compact(const hsk_secp256k1_context* ctx, hsk_secp256k1_ecdsa_signature* sig, const unsigned char *input64) {
    hsk_secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);

    hsk_secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    hsk_secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        hsk_secp256k1_ecdsa_signature_save(sig, &r, &s);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int hsk_secp256k1_ecdsa_signature_serialize_der(const hsk_secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const hsk_secp256k1_ecdsa_signature* sig) {
    hsk_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(sig != NULL);

    hsk_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return hsk_secp256k1_ecdsa_sig_serialize(output, outputlen, &r, &s);
}

int hsk_secp256k1_ecdsa_signature_serialize_compact(const hsk_secp256k1_context* ctx, unsigned char *output64, const hsk_secp256k1_ecdsa_signature* sig) {
    hsk_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);

    hsk_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    hsk_secp256k1_scalar_get_b32(&output64[0], &r);
    hsk_secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int hsk_secp256k1_ecdsa_signature_normalize(const hsk_secp256k1_context* ctx, hsk_secp256k1_ecdsa_signature *sigout, const hsk_secp256k1_ecdsa_signature *sigin) {
    hsk_secp256k1_scalar r, s;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sigin != NULL);

    hsk_secp256k1_ecdsa_signature_load(ctx, &r, &s, sigin);
    ret = hsk_secp256k1_scalar_is_high(&s);
    if (sigout != NULL) {
        if (ret) {
            hsk_secp256k1_scalar_negate(&s, &s);
        }
        hsk_secp256k1_ecdsa_signature_save(sigout, &r, &s);
    }

    return ret;
}

int hsk_secp256k1_ecdsa_verify(const hsk_secp256k1_context* ctx, const hsk_secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const hsk_secp256k1_pubkey *pubkey) {
    hsk_secp256k1_ge q;
    hsk_secp256k1_scalar r, s;
    hsk_secp256k1_scalar m;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hsk_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkey != NULL);

    hsk_secp256k1_scalar_set_b32(&m, msg32, NULL);
    hsk_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return (!hsk_secp256k1_scalar_is_high(&s) &&
            hsk_secp256k1_pubkey_load(ctx, &q, pubkey) &&
            hsk_secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &r, &s, &q, &m));
}

static HSK_SECP256K1_INLINE void buffer_append(unsigned char *buf, unsigned int *offset, const void *data, unsigned int len) {
    memcpy(buf + *offset, data, len);
    *offset += len;
}

static int nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   unsigned char keydata[112];
   unsigned int offset = 0;
   hsk_secp256k1_rfc6979_hmac_sha256 rng;
   unsigned int i;
   /* We feed a byte array to the PRNG as input, consisting of:
    * - the private key (32 bytes) and message (32 bytes), see RFC 6979 3.2d.
    * - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
    * - optionally 16 extra bytes with the algorithm name.
    * Because the arguments have distinct fixed lengths it is not possible for
    *  different argument mixtures to emulate each other and result in the same
    *  nonces.
    */
   buffer_append(keydata, &offset, key32, 32);
   buffer_append(keydata, &offset, msg32, 32);
   if (data != NULL) {
       buffer_append(keydata, &offset, data, 32);
   }
   if (algo16 != NULL) {
       buffer_append(keydata, &offset, algo16, 16);
   }
   hsk_secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, offset);
   memset(keydata, 0, sizeof(keydata));
   for (i = 0; i <= counter; i++) {
       hsk_secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
   }
   hsk_secp256k1_rfc6979_hmac_sha256_finalize(&rng);
   return 1;
}

const hsk_secp256k1_nonce_function hsk_secp256k1_nonce_function_rfc6979 = nonce_function_rfc6979;
const hsk_secp256k1_nonce_function hsk_secp256k1_nonce_function_default = nonce_function_rfc6979;

int hsk_secp256k1_ecdsa_sign(const hsk_secp256k1_context* ctx, hsk_secp256k1_ecdsa_signature *signature, const unsigned char *msg32, const unsigned char *seckey, hsk_secp256k1_nonce_function noncefp, const void* noncedata) {
    hsk_secp256k1_scalar r, s;
    hsk_secp256k1_scalar sec, non, msg;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hsk_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    if (noncefp == NULL) {
        noncefp = hsk_secp256k1_nonce_function_default;
    }

    hsk_secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !hsk_secp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        hsk_secp256k1_scalar_set_b32(&msg, msg32, NULL);
        while (1) {
            ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
            if (!ret) {
                break;
            }
            hsk_secp256k1_scalar_set_b32(&non, nonce32, &overflow);
            if (!overflow && !hsk_secp256k1_scalar_is_zero(&non)) {
                if (hsk_secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, NULL)) {
                    break;
                }
            }
            count++;
        }
        memset(nonce32, 0, 32);
        hsk_secp256k1_scalar_clear(&msg);
        hsk_secp256k1_scalar_clear(&non);
        hsk_secp256k1_scalar_clear(&sec);
    }
    if (ret) {
        hsk_secp256k1_ecdsa_signature_save(signature, &r, &s);
    } else {
        memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int hsk_secp256k1_ec_seckey_verify(const hsk_secp256k1_context* ctx, const unsigned char *seckey) {
    hsk_secp256k1_scalar sec;
    int ret;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    hsk_secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = !overflow && !hsk_secp256k1_scalar_is_zero(&sec);
    hsk_secp256k1_scalar_clear(&sec);
    return ret;
}

int hsk_secp256k1_ec_pubkey_create(const hsk_secp256k1_context* ctx, hsk_secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    hsk_secp256k1_gej pj;
    hsk_secp256k1_ge p;
    hsk_secp256k1_scalar sec;
    int overflow;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(hsk_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey != NULL);

    hsk_secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = (!overflow) & (!hsk_secp256k1_scalar_is_zero(&sec));
    if (ret) {
        hsk_secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pj, &sec);
        hsk_secp256k1_ge_set_gej(&p, &pj);
        hsk_secp256k1_pubkey_save(pubkey, &p);
    }
    hsk_secp256k1_scalar_clear(&sec);
    return ret;
}

int hsk_secp256k1_ec_privkey_negate(const hsk_secp256k1_context* ctx, unsigned char *seckey) {
    hsk_secp256k1_scalar sec;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    hsk_secp256k1_scalar_set_b32(&sec, seckey, NULL);
    hsk_secp256k1_scalar_negate(&sec, &sec);
    hsk_secp256k1_scalar_get_b32(seckey, &sec);

    return 1;
}

int hsk_secp256k1_ec_pubkey_negate(const hsk_secp256k1_context* ctx, hsk_secp256k1_pubkey *pubkey) {
    int ret = 0;
    hsk_secp256k1_ge p;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);

    ret = hsk_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        hsk_secp256k1_ge_neg(&p, &p);
        hsk_secp256k1_pubkey_save(pubkey, &p);
    }
    return ret;
}

int hsk_secp256k1_ec_privkey_tweak_add(const hsk_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    hsk_secp256k1_scalar term;
    hsk_secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak != NULL);

    hsk_secp256k1_scalar_set_b32(&term, tweak, &overflow);
    hsk_secp256k1_scalar_set_b32(&sec, seckey, NULL);

    ret = !overflow && hsk_secp256k1_eckey_privkey_tweak_add(&sec, &term);
    memset(seckey, 0, 32);
    if (ret) {
        hsk_secp256k1_scalar_get_b32(seckey, &sec);
    }

    hsk_secp256k1_scalar_clear(&sec);
    hsk_secp256k1_scalar_clear(&term);
    return ret;
}

int hsk_secp256k1_ec_pubkey_tweak_add(const hsk_secp256k1_context* ctx, hsk_secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    hsk_secp256k1_ge p;
    hsk_secp256k1_scalar term;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hsk_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak != NULL);

    hsk_secp256k1_scalar_set_b32(&term, tweak, &overflow);
    ret = !overflow && hsk_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (hsk_secp256k1_eckey_pubkey_tweak_add(&ctx->ecmult_ctx, &p, &term)) {
            hsk_secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int hsk_secp256k1_ec_privkey_tweak_mul(const hsk_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    hsk_secp256k1_scalar factor;
    hsk_secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak != NULL);

    hsk_secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    hsk_secp256k1_scalar_set_b32(&sec, seckey, NULL);
    ret = !overflow && hsk_secp256k1_eckey_privkey_tweak_mul(&sec, &factor);
    memset(seckey, 0, 32);
    if (ret) {
        hsk_secp256k1_scalar_get_b32(seckey, &sec);
    }

    hsk_secp256k1_scalar_clear(&sec);
    hsk_secp256k1_scalar_clear(&factor);
    return ret;
}

int hsk_secp256k1_ec_pubkey_tweak_mul(const hsk_secp256k1_context* ctx, hsk_secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    hsk_secp256k1_ge p;
    hsk_secp256k1_scalar factor;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hsk_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak != NULL);

    hsk_secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    ret = !overflow && hsk_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (hsk_secp256k1_eckey_pubkey_tweak_mul(&ctx->ecmult_ctx, &p, &factor)) {
            hsk_secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int hsk_secp256k1_context_randomize(hsk_secp256k1_context* ctx, const unsigned char *seed32) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hsk_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    hsk_secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, seed32);
    return 1;
}

int hsk_secp256k1_ec_pubkey_combine(const hsk_secp256k1_context* ctx, hsk_secp256k1_pubkey *pubnonce, const hsk_secp256k1_pubkey * const *pubnonces, size_t n) {
    size_t i;
    hsk_secp256k1_gej Qj;
    hsk_secp256k1_ge Q;

    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(n >= 1);
    ARG_CHECK(pubnonces != NULL);

    hsk_secp256k1_gej_set_infinity(&Qj);

    for (i = 0; i < n; i++) {
        hsk_secp256k1_pubkey_load(ctx, &Q, pubnonces[i]);
        hsk_secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (hsk_secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    hsk_secp256k1_ge_set_gej(&Q, &Qj);
    hsk_secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}

#include "ecdh_impl.h"
#include "recovery_impl.h"
#include "elligator_impl.h"
