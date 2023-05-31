/*
 * Copyright 2018-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal EC functions for other submodules: not for application use */

#ifndef OSSL_CRYPTO_EC_H
# define OSSL_CRYPTO_EC_H
# ifndef RT_WITHOUT_PRAGMA_ONCE                                                                         /* VBOX */
# pragma once
# endif                                                                                                 /* VBOX */

# include <openssl/opensslconf.h>
# include <openssl/evp.h>

int ossl_ec_curve_name2nid(const char *name);
const char *ossl_ec_curve_nid2nist_int(int nid);
int ossl_ec_curve_nist2nid_int(const char *name);
int evp_pkey_ctx_set_ec_param_enc_prov(EVP_PKEY_CTX *ctx, int param_enc);

# ifndef OPENSSL_NO_EC
#  include <openssl/core.h>
#  include <openssl/ec.h>
#  include "crypto/types.h"

/*-
 * Computes the multiplicative inverse of x in the range
 * [1,EC_GROUP::order), where EC_GROUP::order is the cardinality of the
 * subgroup generated by the generator G:
 *
 *         res := x^(-1) (mod EC_GROUP::order).
 *
 * This function expects the following two conditions to hold:
 *  - the EC_GROUP order is prime, and
 *  - x is included in the range [1, EC_GROUP::order).
 *
 * This function returns 1 on success, 0 on error.
 *
 * If the EC_GROUP order is even, this function explicitly returns 0 as
 * an error.
 * In case any of the two conditions stated above is not satisfied,
 * the correctness of its output is not guaranteed, even if the return
 * value could still be 1 (as primality testing and a conditional modular
 * reduction round on the input can be omitted by the underlying
 * implementations for better SCA properties on regular input values).
 */
__owur int ossl_ec_group_do_inverse_ord(const EC_GROUP *group, BIGNUM *res,
                                        const BIGNUM *x, BN_CTX *ctx);

/*-
 * ECDH Key Derivation Function as defined in ANSI X9.63
 */
int ossl_ecdh_kdf_X9_63(unsigned char *out, size_t outlen,
                        const unsigned char *Z, size_t Zlen,
                        const unsigned char *sinfo, size_t sinfolen,
                        const EVP_MD *md, OSSL_LIB_CTX *libctx,
                        const char *propq);

int ossl_ec_key_public_check(const EC_KEY *eckey, BN_CTX *ctx);
int ossl_ec_key_public_check_quick(const EC_KEY *eckey, BN_CTX *ctx);
int ossl_ec_key_private_check(const EC_KEY *eckey);
int ossl_ec_key_pairwise_check(const EC_KEY *eckey, BN_CTX *ctx);
OSSL_LIB_CTX *ossl_ec_key_get_libctx(const EC_KEY *eckey);
const char *ossl_ec_key_get0_propq(const EC_KEY *eckey);
void ossl_ec_key_set0_libctx(EC_KEY *key, OSSL_LIB_CTX *libctx);

/* Backend support */
int ossl_ec_group_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
                         OSSL_PARAM params[], OSSL_LIB_CTX *libctx,
                         const char *propq,
                         BN_CTX *bnctx, unsigned char **genbuf);
int ossl_ec_group_fromdata(EC_KEY *ec, const OSSL_PARAM params[]);
int ossl_ec_group_set_params(EC_GROUP *group, const OSSL_PARAM params[]);
int ossl_ec_key_fromdata(EC_KEY *ecx, const OSSL_PARAM params[],
                         int include_private);
int ossl_ec_key_otherparams_fromdata(EC_KEY *ec, const OSSL_PARAM params[]);
int ossl_ec_key_is_foreign(const EC_KEY *ec);
EC_KEY *ossl_ec_key_dup(const EC_KEY *key, int selection);
int ossl_x509_algor_is_sm2(const X509_ALGOR *palg);
EC_KEY *ossl_ec_key_param_from_x509_algor(const X509_ALGOR *palg,
                                          OSSL_LIB_CTX *libctx,
                                          const char *propq);
EC_KEY *ossl_ec_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                               OSSL_LIB_CTX *libctx, const char *propq);

int ossl_ec_set_ecdh_cofactor_mode(EC_KEY *ec, int mode);
int ossl_ec_encoding_name2id(const char *name);
int ossl_ec_encoding_param2id(const OSSL_PARAM *p, int *id);
int ossl_ec_pt_format_name2id(const char *name);
int ossl_ec_pt_format_param2id(const OSSL_PARAM *p, int *id);
char *ossl_ec_pt_format_id2name(int id);

char *ossl_ec_check_group_type_id2name(int flags);
int ossl_ec_set_check_group_type_from_name(EC_KEY *ec, const char *name);

# endif /* OPENSSL_NO_EC */
#endif
