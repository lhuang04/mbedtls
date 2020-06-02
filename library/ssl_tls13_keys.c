/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "common.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "ssl_tls13_keys.h"

#include "mbedtls/hkdf.h"
#include <stdint.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#define MBEDTLS_SSL_TLS1_3_LABEL( name, string )       \
    .name = string,

struct mbedtls_ssl_tls1_3_labels_struct const mbedtls_ssl_tls1_3_labels =
{
    /* This seems to work in C, despite the string literal being one
     * character too long due to the 0-termination. */
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};

#undef MBEDTLS_SSL_TLS1_3_LABEL

/*
 * This function creates a HkdfLabel structure used in the TLS 1.3 key schedule.
 *
 * The HkdfLabel is specified in RFC 8446 as follows:
 *
 * struct HkdfLabel {
 *   uint16 length;            // Length of expanded key material
 *   opaque label<7..255>;     // Always prefixed by "tls13 "
 *   opaque context<0..255>;   // Usually a communication transcript hash
 * };
 *
 * Parameters:
 * - desired_length: Length of expanded key material
 *                   Even though the standard allows expansion to up to
 *                   2**16 Bytes, TLS 1.3 never uses expansion to more than
 *                   255 Bytes, so we require `desired_length` to be at most
 *                   255. This allows us to save a few Bytes of code by
 *                   hardcoding the writing of the high bytes.
 * - (label, llen): label + label length, without "tls13 " prefix
 *                  The label length MUST be less than or equal to
 *                  MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN
 *                  It is the caller's responsibility to ensure this.
 *                  All (label, label length) pairs used in TLS 1.3
 *                  can be obtained via MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN().
 * - (ctx, clen): context + context length
 *                The context length MUST be less than or equal to
 *                MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN
 *                It is the caller's responsibility to ensure this.
 * - dst: Target buffer for HkdfLabel structure,
 *        This MUST be a writable buffer of size
 *        at least SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN Bytes.
 * - dlen: Pointer at which to store the actual length of
 *         the HkdfLabel structure on success.
 */

static const char tls1_3_label_prefix[6] = "tls13 ";

#define SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( label_len, context_len ) \
    (   2                  /* expansion length           */ \
      + 1                  /* label length               */ \
      + label_len                                           \
      + 1                  /* context length             */ \
      + context_len )

#define SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN                      \
    SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN(                             \
                     sizeof(tls1_3_label_prefix) +                      \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN,     \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )

static void ssl_tls1_3_hkdf_encode_label(
                            size_t desired_length,
                            const unsigned char *label, size_t llen,
                            const unsigned char *ctx, size_t clen,
                            unsigned char *dst, size_t *dlen )
{
    size_t total_label_len =
        sizeof(tls1_3_label_prefix) + llen;
    size_t total_hkdf_lbl_len =
        SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( total_label_len, clen );

    unsigned char *p = dst;

    /* Add the size of the expanded key material.
     * We're hardcoding the high byte to 0 here assuming that we never use
     * TLS 1.3 HKDF key expansion to more than 255 Bytes. */
#if MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN > 255
#error "The implementation of ssl_tls1_3_hkdf_encode_label() is not fit for the \
        value of MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN"
#endif

    *p++ = 0;
    *p++ = (unsigned char)( ( desired_length >> 0 ) & 0xFF );

    /* Add label incl. prefix */
    *p++ = (unsigned char)( total_label_len & 0xFF );
    memcpy( p, tls1_3_label_prefix, sizeof(tls1_3_label_prefix) );
    p += sizeof(tls1_3_label_prefix);
    memcpy( p, label, llen );
    p += llen;

    /* Add context value */
    *p++ = (unsigned char)( clen & 0xFF );
    if( clen != 0 )
        memcpy( p, ctx, clen );

    /* Return total length to the caller.  */
    *dlen = total_hkdf_lbl_len;
}

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t slen,
                     const unsigned char *label, size_t llen,
                     const unsigned char *ctx, size_t clen,
                     unsigned char *buf, size_t blen )
{
    const mbedtls_md_info_t *md;
    unsigned char hkdf_label[ SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN ];
    size_t hkdf_label_len;

    if( llen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN )
    {
        /* Should never happen since this is an internal
         * function, and we know statically which labels
         * are allowed. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( clen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( blen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    ssl_tls1_3_hkdf_encode_label( blen,
                                  label, llen,
                                  ctx, clen,
                                  hkdf_label,
                                  &hkdf_label_len );

    return( mbedtls_hkdf_expand( md,
                                 secret, slen,
                                 hkdf_label, hkdf_label_len,
                                 buf, blen ) );
}

/*
 * The traffic keying material is generated from the following inputs:
 *
 *  - One secret value per sender.
 *  - A purpose value indicating the specific value being generated
 *  - The desired lengths of key and IV.
 *
 * The expansion itself is based on HKDF:
 *
 *   [sender]_write_key = HKDF-Expand-Label( Secret, "key", "", key_length )
 *   [sender]_write_iv  = HKDF-Expand-Label( Secret, "iv" , "", iv_length )
 *
 * [sender] denotes the sending side and the Secret value is provided
 * by the function caller. Note that we generate server and client side
 * keys in a single function call.
 */
int mbedtls_ssl_tls1_3_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_secret,
                     const unsigned char *server_secret,
                     size_t slen, size_t key_len, size_t iv_len,
                     mbedtls_ssl_key_set *keys )
{
    int ret = 0;

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    client_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->client_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    server_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->server_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    client_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->client_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    server_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->server_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    keys->key_len = key_len;
    keys->iv_len = iv_len;

    return( 0 );
}

int mbedtls_ssl_tls1_3_derive_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret, size_t slen,
                   const unsigned char *label, size_t llen,
                   const unsigned char *ctx, size_t clen,
                   int ctx_hashed,
                   unsigned char *dstbuf, size_t buflen )
{
    int ret;
    unsigned char hashed_context[ MBEDTLS_MD_MAX_SIZE ];

    const mbedtls_md_info_t *md;
    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( ctx_hashed == MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED )
    {
        ret = mbedtls_md( md, ctx, clen, hashed_context );
        if( ret != 0 )
            return( ret );
        clen = mbedtls_md_get_size( md );
    }
    else
    {
        if( clen > sizeof(hashed_context) )
        {
            /* This should never happen since this function is internal
             * and the code sets `ctx_hashed` correctly.
             * Let's double-check nonetheless to not run at the risk
             * of getting a stack overflow. */
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        memcpy( hashed_context, ctx, clen );
    }

    return( mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                                                  secret, slen,
                                                  label, llen,
                                                  hashed_context, clen,
                                                  dstbuf, buflen ) );
}

int mbedtls_ssl_tls1_3_evolve_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret_old,
                   const unsigned char *input, size_t input_len,
                   unsigned char *secret_new )
{
    int ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    size_t hlen, ilen;
    unsigned char tmp_secret[ MBEDTLS_MD_MAX_SIZE ] = { 0 };
    unsigned char tmp_input [ MBEDTLS_MD_MAX_SIZE ] = { 0 };

    const mbedtls_md_info_t *md;
    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    hlen = mbedtls_md_get_size( md );

    /* For non-initial runs, call Derive-Secret( ., "derived", "")
     * on the old secret. */
    if( secret_old != NULL )
    {
        ret = mbedtls_ssl_tls1_3_derive_secret(
                   hash_alg,
                   secret_old, hlen,
                   MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( derived ),
                   NULL, 0, /* context */
                   MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                   tmp_secret, hlen );
        if( ret != 0 )
            goto cleanup;
    }

    if( input != NULL )
    {
        memcpy( tmp_input, input, input_len );
        ilen = input_len;
    }
    else
    {
        ilen = hlen;
    }

    /* HKDF-Extract takes a salt and input key material.
     * The salt is the old secret, and the input key material
     * is the input secret (PSK / ECDHE). */
    ret = mbedtls_hkdf_extract( md,
                    tmp_secret, hlen,
                    tmp_input, ilen,
                    secret_new );
    if( ret != 0 )
        goto cleanup;

    ret = 0;

 cleanup:

    mbedtls_platform_zeroize( tmp_secret, sizeof(tmp_secret) );
    mbedtls_platform_zeroize( tmp_input,  sizeof(tmp_input)  );
    return( ret );
}

/*
 * The mbedtls_ssl_tls1_3_hkdf_encode_label() function creates the HkdfLabel structure.
 *
 * The function assumes that the info buffer space has been
 * allocated accordingly and no further length checking is needed.
 *
 * The HkdfLabel is specified in the TLS 1.3 spec as follows:
 *
 * struct HkdfLabel {
 *   uint16 length;
 *   opaque label<7..255>;
 *   opaque context<0..255>;
 * };
 *
 * - HkdfLabel.length is Length
 * - HkdfLabel.label is "tls13 " + Label
 * - HkdfLabel.context is HashValue.
 */

static int ssl_tls1_3_hkdf_encode_label(
                            const unsigned char *label, int llen,
                            const unsigned char *hashValue, int hlen,
                            unsigned char *info, int length )
{
    unsigned char *p = info;
    const char label_prefix[] = "tls13 ";
    int total_label_len;

    total_label_len = sizeof(label_prefix) + llen;

    // create header
    *p++ = (unsigned char)( ( length >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( length >> 0 ) & 0xFF );
    *p++ = (unsigned char)( total_label_len & 0xFF );

    // copy label
    memcpy( p, label_prefix, sizeof(label_prefix) );
    p += sizeof(label_prefix);

    memcpy( p, label, llen );
    p += llen;

    // copy hash length
    *p++ = (unsigned char)( hlen & 0xFF );

    // copy hash value
    memcpy( p, hashValue, hlen );

    return( 0 );
}

int mbedtls_ssl_tls1_3_derive_secret(
                   mbedtls_ssl_context *ssl, mbedtls_md_type_t hash_alg,
                   const unsigned char *secret, int slen,
                   const unsigned char *label, int llen,
                   const unsigned char *message, int mlen,
                   unsigned char *dstbuf, int buflen )
{
    int ret = 0;
    const mbedtls_md_info_t *md;
    int L;
    uint8_t *hashValue;

#if !defined(HKDF_DEBUG)
    ( ( void )ssl );
#endif /* !HKDF_DEBUG */

    md = mbedtls_md_info_from_type( hash_alg );
    L = mbedtls_md_get_size( md );

    if( L != 32 && L != 48 && L !=64 )
    {
        mbedtls_printf( "Length of hash function incorrect." );
        return( -1 );
    }

    hashValue = mbedtls_calloc( L, 1 );
    if( hashValue == NULL )
    {
        mbedtls_printf( "calloc() failed in mbedtls_ssl_tls1_3_derive_secret()." );
        return( -1 );
    }

    memset( hashValue, 0, L );

    if( mlen != L )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_derive_secret: Incorrect length of hash - mlen ( %d ) != L ( %d )\n", mlen, L );
        mbedtls_free( hashValue );
        return( -1 );
    }
    memcpy( hashValue, message, L );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, secret, slen, label, llen,
                           hashValue, L, L, dstbuf, buflen );

#if defined(HKDF_DEBUG)
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Derive-Secret" ) );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Label", label, llen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Secret", secret, slen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Hash", hashValue, L );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Derived Key", dstbuf, buflen );
#endif

    mbedtls_free( hashValue );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_hkdf_expand_label(): Error %d.\n", ret );
        return( ret );
    }

    return( ret );
}


/*
* The traffic keying material is generated from the following input values:
*  - A secret value
*  - A purpose value indicating the specific value being generated
*  - The length of the key
*
* The traffic keying material is generated from an input traffic
* secret value using:
*  [sender]_write_key = HKDF-Expand-Label( Secret, "key", "", key_length )
*  [sender]_write_iv  = HKDF-Expand-Label( Secret, "iv" , "", iv_length )
*
* [sender] denotes the sending side and the Secret value is provided by the function caller.
* We generate server and client side keys in a single function call.
*/
int mbedtls_ssl_tls1_3_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_key,
                     const unsigned char *server_key,
                     int slen,
                     int keyLen, int ivLen,
                     mbedtls_ssl_key_set *keys )
{
    int ret = 0;

    keys->clientWriteKey = mbedtls_calloc( keyLen,1 );
    if( keys->clientWriteKey == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating clientWriteKey.\n" );
        return( ( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, client_key, slen, (const unsigned char *) "key", 3,
                          (const unsigned char *)"", 0, keyLen,
                          keys->clientWriteKey, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for clientWriteKey %d.\n", ret );
        return( ( ret ) );
    }

    keys->serverWriteKey = mbedtls_calloc( keyLen,1 );
    if( keys->serverWriteKey == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating serverWriteKey.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, server_key, slen, (const unsigned char *)"key", 3,
                          (const unsigned char *)"", 0, keyLen,
                          keys->serverWriteKey, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for serverWriteKey %d.\n", ret );
        return( ( ret ) );
    }

    // Compute clientWriteIV
    keys->clientWriteIV = mbedtls_calloc( ivLen,1 );
    if( keys->clientWriteIV == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating clientWriteIV.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, client_key, slen, (const unsigned char *) "iv", 2,
                          (const unsigned char *)"", 0, ivLen,
                          keys->clientWriteIV, ivLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for clientWriteIV %d.\n", ret );
        return( ( ret ) );
    }

    // Compute serverWriteIV
    keys->serverWriteIV = mbedtls_calloc( ivLen,1 );
    if( keys->serverWriteIV == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating serverWriteIV.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, server_key, slen, (const unsigned char *) "iv", 2,
                          (const unsigned char *)"", 0, ivLen,
                          keys->serverWriteIV, ivLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for serverWriteIV %d.\n", ret );
        return( ( ret ) );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)

    // Compute client_sn_key
    keys->client_sn_key = mbedtls_calloc( keyLen, 1 );
    if( keys->client_sn_key == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating client_sn_key.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, client_key, slen, (const unsigned char *) "sn", 2,
                          (const unsigned char *)"", 0, keyLen,
                          keys->client_sn_key, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for client_sn_key %d.\n", ret );
        return( ( ret ) );
    }

    // Compute server_sn_key
    keys->server_sn_key = mbedtls_calloc( keyLen, 1 );
    if( keys->server_sn_key == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating server_sn_key.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, server_key, slen, (const unsigned char *) "sn", 2,
                          (const unsigned char *)"", 0, keyLen,
                          keys->server_sn_key, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for server_sn_key %d.\n", ret );
        return( ( ret ) );
    }

#endif /* MBEDTLS_SSL_PROTO_DTLS */


    // Set epoch value to "undefined"
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    keys->epoch = -1;
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    // Set key length
    // Set IV length
    keys->keyLen = keyLen;
    keys->ivLen = ivLen;
    return( 0 );
}

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg, const unsigned char *secret,
                     int slen, const unsigned char *label, int llen,
                     const unsigned char *hashValue, int hlen, int length,
                     unsigned char *buf, int blen )
{
    int ret = 0;
    int len;
    const mbedtls_md_info_t *md;
    unsigned char *info = NULL;

    /* Compute length of info, which
         * is computed as follows:
     *
     * struct {
     *  uint16 length = Length;
     *   opaque label<7..255> = "tls13 " + Label;
     *   opaque context<0..255> = Context;
     * } HkdfLabel;
         *
         */
    len = 2 + 1 + llen + 1 + hlen + 6;

#if defined(HKDF_DEBUG)
    // ----------------------------- DEBUG ---------------------------
    mbedtls_printf( "HKDF Expand with label [tls13 " );
    for ( int i = 0; i < llen; i++ )
    {
        mbedtls_printf( "%c", label[i] );
    }
    mbedtls_printf( "] ( %d )", llen );
    mbedtls_printf( ", requested length = %d\n", blen );

    mbedtls_printf( "PRK ( %d ):", slen );
    for ( int i = 0; i < slen; i++ )
    {
        mbedtls_printf( "%02x", secret[i] );
    }
    mbedtls_printf( "\n" );

    mbedtls_printf( "Hash ( %d ):", hlen );
    for ( int i = 0; i <hlen; i++ )
    {
        mbedtls_printf( "%02x", hashValue[i] );
    }
    mbedtls_printf( "\n" );
        // ----------------------------- DEBUG ---------------------------
#endif

        info = mbedtls_calloc( len,1 );

    if( info == NULL )
    {
        mbedtls_printf( "calloc() failed in mbedtls_ssl_tls1_3_hkdf_expand_label()." );
        return( ( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL ) );
    }

    ret = ssl_tls1_3_hkdf_encode_label( label, llen, hashValue, hlen, info, length );

    if( ret < 0 )
    {
        mbedtls_printf( "ssl_tls1_3_hkdf_encode_label(): Error %d.\n", ret );
        goto clean_up;
    }


#if defined(HKDF_DEBUG)
        // ----------------------------- DEBUG ---------------------------

        mbedtls_printf( "Info ( %d ):", len );
        for ( int i = 0; i < len; i++ )
        {
            mbedtls_printf( "%02x", info[i] );
        }
        mbedtls_printf( "\n" );

        // ----------------------------- DEBUG ---------------------------
#endif

        md = mbedtls_md_info_from_type( hash_alg );

        if( md == NULL )
        {
            mbedtls_printf( "mbedtls_md_info_from_type() failed in mbedtls_ssl_tls1_3_hkdf_expand_label()." );
            goto clean_up;
        }

    ret = mbedtls_hkdf_expand( md, secret, slen, info, len, buf, blen );

    if( ret != 0 )
    {
        mbedtls_printf( "hkdfExpand(): Error %d.\n", ret );
        goto clean_up;
    }

#if defined(HKDF_DEBUG)
    // ----------------------------- DEBUG ---------------------------

    mbedtls_printf( "Derived key ( %d ):", blen );
    for ( int i = 0; i < blen; i++ )
    {
        mbedtls_printf( "%02x", buf[i] );
    }
    mbedtls_printf( "\n" );

    // ----------------------------- DEBUG ---------------------------
#endif
clean_up:
    mbedtls_free( info );
    return( ret );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
