/*
 *  Handshake-related functions shared between the TLS/DTLS client
 *  and server ( ssl_tls13_client.c and ssl_tls13_server.c ).
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS ( https://tls.mbed.org )
 */


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#define SSL_DONT_FORCE_FLUSH 0
#define SSL_FORCE_FLUSH      1

#if defined(MBEDTLS_SSL_PROTO_DTLS)
#include "mbedtls/aes.h"
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#include "mbedtls/ssl_ticket.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/hkdf.h"
#include <string.h>

#if defined(MBEDTLS_X509_CRT_PARSE_C) &&                \
    defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
#include "mbedtls/oid.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_SHA256_C)
static int ssl_calc_finished_tls_sha256( mbedtls_ssl_context*, unsigned char*, int );
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
static int ssl_calc_finished_tls_sha384( mbedtls_ssl_context*, unsigned char*, int );
#endif /* MBEDTLS_SHA512_C */

#if defined(MBEDTLS_SSL_TLS13_CTLS)
static enum varint_length_enum set_varint_length( uint32_t input, uint32_t* output )
{
    if( input <= 127 )
    {
        *output = input;
        return( VARINT_LENGTH_1_BYTE );
    }
    else if( input <= 16383 )
    {
        *output = input;
        *output |= MBEDTLS_VARINT_HDR_1;
        *output &= ~( MBEDTLS_VARINT_HDR_2 );
        return( VARINT_LENGTH_2_BYTE );
    }
    else if( input <= 4194303 )
    {
        *output = input;
        *output |= MBEDTLS_VARINT_HDR_1;
        *output |= MBEDTLS_VARINT_HDR_2;
        return( VARINT_LENGTH_3_BYTE );
    }

    return( VARINT_LENGTH_FAILURE );
}



static uint8_t get_varint_length( const uint8_t input )
{
    /* Is bit 8 set? */
    if( input & MBEDTLS_VARINT_HDR_1 )
    {
        /* Is bit 7 set? */
        if( input & MBEDTLS_VARINT_HDR_2 )
        {
            /* length = 3 bytes */
            return ( 3 );
        }
        else
        {
            /* length = 2 bytes */
            return ( 2 );
        }
    }
    else
    {
        /* length = 1 bytes */
        return ( 1 );
    }

}

static uint32_t get_varint_value( const uint32_t input )
{
    uint32_t output;

    /* Is bit 8 set? */
    if( input & MBEDTLS_VARINT_HDR_1 )
    {
        /* Is bit 7 set? */
        if( input & MBEDTLS_VARINT_HDR_2 )
        {
            /* length = 3 bytes */
            output = input & ~( MBEDTLS_VARINT_HDR_1 );
            output = output & ~( MBEDTLS_VARINT_HDR_2 );
            return ( output );
        }
        else
        {
            /* length = 2 bytes */
            output = input & ~( MBEDTLS_VARINT_HDR_1 );
            return ( output );
        }
    }
    else
    {
        /* length = 1 bytes */
        return ( input );
    }

}
#endif /* MBEDTLS_SSL_TLS13_CTLS */

#if defined(MBEDTLS_SSL_USE_MPS)
int mbedtls_ssl_mps_fetch_full_hs_msg( mbedtls_ssl_context *ssl,
                                       unsigned hs_type,
                                       unsigned char **buf,
                                       size_t *buflen )
{
    int ret;
    mbedtls_mps_handshake_in msg;

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps.l4 ) );

    if( ret != MBEDTLS_MPS_MSG_HS )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps.l4,
                                                      &msg ) );

    if( msg.type != hs_type )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    ret = mbedtls_mps_reader_get_ext( msg.handle,
                                  msg.length,
                                  buf,
                                  NULL );

    if( ret == MBEDTLS_ERR_MPS_READER_OUT_OF_DATA )
    {
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_pause( &ssl->mps.l4 ) );
        ret = MBEDTLS_ERR_SSL_WANT_READ;
    }
    else
    {
        MBEDTLS_SSL_PROC_CHK( ret );

        /* *buf already set in mbedtls_mps_reader_get_ext() */
        *buflen = msg.length;
    }

cleanup:

    return( ret );
}

int mbedtls_ssl_mps_hs_consume_full_hs_msg( mbedtls_ssl_context *ssl )
{
    int ret;
    mbedtls_mps_handshake_in msg;

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps.l4,
                                                      &msg ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_commit_ext( msg.handle ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps.l4 ) );

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */

void mbedtls_ssl_add_hs_msg_to_checksum( mbedtls_ssl_context *ssl,
                                         unsigned hs_type,
                                         unsigned char const *msg,
                                         size_t msg_len )
{
    mbedtls_ssl_add_hs_hdr_to_checksum( ssl, hs_type, msg_len );
    ssl->handshake->update_checksum( ssl, msg, msg_len );
}

void mbedtls_ssl_add_hs_hdr_to_checksum( mbedtls_ssl_context *ssl,
                                         unsigned hs_type,
                                         size_t total_hs_len )
{
    unsigned char hs_hdr[4];

    /* Build HS header for checksum update. */
    hs_hdr[0] = hs_type;
    hs_hdr[1] = (unsigned char)( total_hs_len >> 16 );
    hs_hdr[2] = (unsigned char)( total_hs_len >>  8 );
    hs_hdr[3] = (unsigned char)( total_hs_len >>  0 );

    ssl->handshake->update_checksum( ssl, hs_hdr, sizeof( hs_hdr ) );
}

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/* mbedtls_ssl_create_binder():
 *
 *                0
 *                |
 *                v
 *   PSK ->  HKDF-Extract = Early Secret
 *                |
 *                +------> Derive-Secret( .,
 *                |                      "ext binder" |
 *                |                      "res binder",
 *                |                      "" )
 *                |                     = binder_key
 *                |
 *                +-----> Derive-Secret( ., "c e traffic",
 *                |                     ClientHello )
 *                |                     = client_early_traffic_secret
 *               ...
 */

int mbedtls_ssl_create_binder( mbedtls_ssl_context *ssl,
                               int is_external,
                               unsigned char *psk, size_t psk_len,
                               const mbedtls_md_info_t *md,
                               const mbedtls_ssl_ciphersuite_t *suite_info,
                               unsigned char *result )
{
    int ret = 0;
    int hash_length;
    unsigned char salt[MBEDTLS_MD_MAX_SIZE];
    unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
    size_t transcript_len;
    unsigned char binder_key[MBEDTLS_MD_MAX_SIZE];
    unsigned char finished_key[MBEDTLS_MD_MAX_SIZE];

    hash_length = mbedtls_hash_size_for_ciphersuite( suite_info );
    if( hash_length == -1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * Compute Early Secret with HKDF-Extract( 0, PSK )
     */
    memset( salt, 0x0, hash_length );
    ret = mbedtls_hkdf_extract( md, salt, hash_length,
                                psk, psk_len,
                                ssl->handshake->early_secret );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_hkdf_extract", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "HKDF Extract -- early_secret" ) );
    MBEDTLS_SSL_DEBUG_BUF( 5, "Salt", salt, hash_length );
    MBEDTLS_SSL_DEBUG_BUF( 5, "Input", psk, psk_len );
    MBEDTLS_SSL_DEBUG_BUF( 5, "Output", ssl->handshake->early_secret,
                           hash_length );

    /*
     * Compute binder_key with
     *
     *    Derive-Secret( early_secret, "ext binder" | "res binder", "" )
     */

    if( !is_external )
    {
        ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md ),
                            ssl->handshake->early_secret, hash_length,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, hash_length );
        MBEDTLS_SSL_DEBUG_MSG( 5, ( "Derive Early Secret with 'res binder'" ) );
    }
    else
    {
        ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md ),
                            ssl->handshake->early_secret, hash_length,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( ext_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, hash_length );
        MBEDTLS_SSL_DEBUG_MSG( 5, ( "Derive Early Secret with 'ext binder'" ) );
    }

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        return( ret );
    }

    /* Get current state of handshake transcript. */
    ret = mbedtls_ssl_get_handshake_transcript( ssl, suite_info->mac,
                                                transcript, sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
        return( ret );

    /*
     * finished_key =
     *    HKDF-Expand-Label( BaseKey, "finished", "", Hash.length )
     *
     * The binding_value is computed in the same way as the Finished message
     * but with the BaseKey being the binder_key.
     */

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( suite_info->mac, binder_key,
                            hash_length,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                            NULL, 0,
                            finished_key, hash_length );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "finished_key", finished_key, hash_length );

    /* compute mac and write it into the buffer */
    ret = mbedtls_md_hmac( md, finished_key, hash_length,
                           transcript, transcript_len,
                           result );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_md_hmac", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "verify_data of psk binder" ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Input", transcript, hash_length );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Key", finished_key, hash_length );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Output", result, hash_length );

exit:

    mbedtls_platform_zeroize( finished_key, sizeof( finished_key ) );
    mbedtls_platform_zeroize( binder_key,   sizeof( binder_key ) );
    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_SHA256_C)
static int ssl_calc_finished_tls_sha256(
    mbedtls_ssl_context* ssl, unsigned char* buf, int from )
{
    int ret;
    mbedtls_sha256_context sha256;
    unsigned char transcript[32];
    unsigned char* finished_key;
    const mbedtls_md_info_t* md;

    md = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );

    if( md == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "mbedtls_md_info_from_type failed" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mbedtls_sha256_init( &sha256 );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> calc finished tls sha256" ) );

    mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

    /*
      #if !defined(MBEDTLS_SHA256_ALT)
      MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha2 state", ( unsigned char * )
      sha256.state, sizeof( sha256.state ) );
      #endif
    */

    if( ( ret = mbedtls_sha256_finish_ret( &sha256, transcript ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_finish_ret", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 5, "handshake hash", transcript, 32 );

    /* TLS 1.3 Finished message
     *
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     *
     * verify_data =
     *     HMAC( finished_key, Hash(
     *         Handshake Context +
     *         Certificate* +
     *         CertificateVerify* )
     *    )
     *
     *   * Only included if present.
     */


    /*
     * finished_key =
     *    HKDF-Expand-Label( BaseKey, "finished", "", Hash.length )
     *
     * The binding_value is computed in the same way as the Finished message
     * but with the BaseKey being the binder_key.
     */

    /* create client finished_key */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( MBEDTLS_MD_SHA256,
                          ssl->handshake->client_handshake_traffic_secret, 32,
                          MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                          NULL, 0,
                          ssl->handshake->client_finished_key, 32 );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the client_finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "client_finished_key", ssl->handshake->client_finished_key, 32 );

    /* create server finished_key */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( MBEDTLS_MD_SHA256,
                           ssl->handshake->server_handshake_traffic_secret, 32,
                           MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                           NULL, 0,
                           ssl->handshake->server_finished_key, 32 );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the server_finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "server_finished_key", ssl->handshake->server_finished_key, 32 );

    if( from == MBEDTLS_SSL_IS_CLIENT )
    {
        /* In this case the server is receiving a finished message
         * sent by the client. It therefore needs to use the client_finished_key.
         */
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Using client_finished_key to compute mac ( for creating finished message )" ) );
        finished_key = ssl->handshake->client_finished_key;
    }
    else
    {
        /* If the server is sending a finished message then it needs to use
         * the server_finished_key.
         */
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Using server_finished_key to compute mac ( for verification procedure )" ) );
        finished_key = ssl->handshake->server_finished_key;
    }

    /* compute mac and write it into the buffer */
    ret = mbedtls_md_hmac( md, finished_key, 32, transcript, 32, buf );

    ssl->handshake->state_local.finished_out.digest_len = 32;

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_md_hmac", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "verify_data of Finished message" ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Input", transcript, 32 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Key", finished_key, 32 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Output", buf, 32 );

exit:
    mbedtls_sha256_free( &sha256 );
    mbedtls_platform_zeroize( transcript, sizeof( transcript ) );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
    return ( ret );
}
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
static int ssl_calc_finished_tls_sha384(
    mbedtls_ssl_context* ssl, unsigned char* buf, int from )
{
    mbedtls_sha512_context sha512;
    int ret;
    unsigned char padbuf[48];
    unsigned char* finished_key;
    const mbedtls_md_info_t* md;

    md = mbedtls_md_info_from_type( MBEDTLS_MD_SHA384 );

    if( md == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "mbedtls_md_info_from_type failed" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }


    mbedtls_sha512_init( &sha512 );

    if( ( ret = mbedtls_sha512_starts_ret( &sha512, 1 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_starts_ret", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> calc finished tls sha384" ) );

    mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

    /* TLS 1.3 Finished message
     *
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     *
     * verify_data =
     *     HMAC( finished_key, Hash(
     *         Handshake Context +
     *         Certificate* +
     *         CertificateVerify*
     *         )
     *    )
     *
     *   * Only included if present.
     */

    /*#if !defined(MBEDTLS_SHA512_ALT)
      MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha512 state", ( unsigned char * )
      sha512.state, sizeof( sha512.state ) );
      #endif
    */

    if( ( ret = mbedtls_sha512_finish_ret( &sha512, padbuf ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 5, "handshake hash", padbuf, 48 );

    /* create client finished_key */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( MBEDTLS_MD_SHA384,
                      ssl->handshake->client_handshake_traffic_secret, 48,
                      MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                      NULL, 0,
                      ssl->handshake->client_finished_key, 48 );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the client_finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "client_finished_key", ssl->handshake->client_finished_key, 48 );

    /* create server finished_key */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( MBEDTLS_MD_SHA384,
                          ssl->handshake->server_handshake_traffic_secret, 48,
                          MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                          NULL, 0,
                          ssl->handshake->server_finished_key, 48 );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the server_finished_key failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "server_finished_key", ssl->handshake->server_finished_key, 48 );


    if( from == MBEDTLS_SSL_IS_CLIENT )
    {
        /* In this case the server is receiving a finished message
         * sent by the client. It therefore needs to use the client_finished_key.
         */
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Using client_finished_key to compute mac ( for creating finished message )" ) );
        finished_key = ssl->handshake->client_finished_key;
    }
    else
    {
        /* If the server is sending a finished message then it needs to use
         * the server_finished_key.
         */
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Using server_finished_key to compute mac ( for verification procedure )" ) );
        finished_key = ssl->handshake->server_finished_key;
    }

    /* compute mac and write it into the buffer */
    ret = mbedtls_md_hmac( md, finished_key, 48, padbuf, 48, buf );

    ssl->handshake->state_local.finished_out.digest_len = 48;

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "mbedtls_md_hmac", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "verify_data of Finished message" ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Input", padbuf, 48 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Key", finished_key, 48 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Output", buf, 48 );

exit:
    mbedtls_sha512_free( &sha512 );

    mbedtls_platform_zeroize( padbuf, sizeof( padbuf ) );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
    return( 0 );
}
#endif /* MBEDTLS_SHA512_C */


#if defined(MBEDTLS_CID)
void ssl_write_cid_ext( mbedtls_ssl_context *ssl,
                        unsigned char* buf,
                        unsigned char* end,
                        size_t* olen )
{
    unsigned char *p = buf;
    int ret;
/*	const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_MAX_CONTENT_LEN; */

    *olen = 0;

    if( ssl->conf->cid == MBEDTLS_CID_CONF_DISABLED )
    {
        ssl->session_negotiate->cid = MBEDTLS_CID_DISABLED;
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "CID disabled." ) );
        return;
    }

    if( ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "CID can only be used with DTLS." ) );
        return;
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding cid extension" ) );

    if( end < p || (size_t)( end - p ) < ( 3 + MBEDTLS_CID_MAX_SIZE ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return;
    }

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_CID >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_CID ) & 0xFF );

    if( ssl->conf->cid == MBEDTLS_CID_CONF_ZERO_LENGTH )
    {

        *p++ = (unsigned char)( ( 1 >> 8 ) & 0xFF );
        *p++ = (unsigned char)( 1 & 0xFF );

        /* 1 byte length field set to zero */
        *p++ = 0;
        *olen = 5;
        ssl->out_cid_len = 0;
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "We don't want the peer to send CID in a packet." ) );
        return;
    }

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        ssl->session_negotiate->cid = MBEDTLS_CID_ENABLED;
    }
    ssl->in_cid_len = MBEDTLS_CID_MAX_SIZE;

    *p++ = (unsigned char)( ( ( ssl->in_cid_len + 1 ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( ssl->in_cid_len + 1 ) ) & 0xFF );

    /* Length field set to MBEDTLS_CID_MAX_SIZE */
    *p++ = MBEDTLS_CID_MAX_SIZE;

    /* allocate CID value */
    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng, ssl->in_cid, MBEDTLS_CID_MAX_SIZE ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "CID allocation failed." ) );
        return;
    }

    memcpy( p, ssl->in_cid, MBEDTLS_CID_MAX_SIZE );
    MBEDTLS_SSL_DEBUG_BUF( 3, "CID ( incoming )", p, MBEDTLS_CID_MAX_SIZE );
    p += MBEDTLS_CID_MAX_SIZE;

    *olen = 5 + MBEDTLS_CID_MAX_SIZE;
}



int ssl_parse_cid_ext( mbedtls_ssl_context *ssl,
                       const unsigned char *buf,
                       size_t len )
{
    const unsigned char *p = buf;
    uint8_t len_inner = 0;

    if( ssl->conf->cid == MBEDTLS_CID_CONF_DISABLED )
    {
        ssl->session_negotiate->cid = MBEDTLS_CID_DISABLED;
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "CID disabled." ) );
        return( 0 );
    }

    /* Read length of the CID */
    if( len > 1 ) len_inner = *p;

    if( len_inner == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 5, ( "No CID value will be placed in outgoing records." ) );
        ssl->out_cid_len = 0;
        memset( ssl->out_cid, '\0', MBEDTLS_CID_MAX_SIZE );
        return ( 0 );
    }

    /* Check for correct length and whether have enough space for the CID value */
    if( ( len_inner != ( len - 1 ) ) && ( len_inner < MBEDTLS_CID_MAX_SIZE ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Incorrect CID extension length" ) );

#if defined(MBEDTLS_SSL_CLI_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
            return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
#endif 	/* MBEDTLS_SSL_SRV_C */
    }

    /* skip the length field to read the cid value */
    p++;

    /* The other end provided us with the CID value it */
    /* would like us to use for packet sent to it. */

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        ssl->session_negotiate->cid = MBEDTLS_CID_CONF_ENABLED;
    }
    ssl->out_cid_len = len_inner;
    memcpy( ssl->out_cid, p, len_inner );

    MBEDTLS_SSL_DEBUG_BUF( 5, "CID ( outgoing )", p, len_inner );

    return( 0 );
}
#endif /* MBEDTLS_CID */

/*
 *
 * STATE HANDLING: Write ChangeCipherSpec
 *
 */

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)

 /* Main entry point; orchestrates the other functions */
int mbedtls_ssl_write_change_cipher_spec_process( mbedtls_ssl_context* ssl );

#define SSL_WRITE_CCS_NEEDED     0
#define SSL_WRITE_CCS_SKIP       1
static int ssl_write_change_cipher_spec_coordinate( mbedtls_ssl_context* ssl );

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_write_change_cipher_spec_write( mbedtls_ssl_context* ssl,
    unsigned char* buf,
    size_t buflen,
    size_t* olen );
#endif /* !MBEDTLS_SSL_USE_MPS */
static int ssl_write_change_cipher_spec_postprocess( mbedtls_ssl_context* ssl );


/*
 * Implementation
 */

int mbedtls_ssl_write_change_cipher_spec_process( mbedtls_ssl_context* ssl )
{
    int ret;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write change cipher spec" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_write_change_cipher_spec_coordinate( ssl ) );

    if( ret == SSL_WRITE_CCS_NEEDED )
    {
#if defined(MBEDTLS_SSL_USE_MPS)

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_ccs( &ssl->mps.l4 ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

#else /* MBEDTLS_SSL_USE_MPS */
        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

        /* Write CCS message */
        MBEDTLS_SSL_PROC_CHK( ssl_write_change_cipher_spec_write( ssl, ssl->out_msg,
            MBEDTLS_SSL_MAX_CONTENT_LEN,
            &ssl->out_msglen ) );

        ssl->out_msgtype = MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC;

        /* Dispatch message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_record( ssl, SSL_FORCE_FLUSH ) );

#endif /* MBEDTLS_SSL_USE_MPS */

        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_write_change_cipher_spec_postprocess( ssl ) );
    }
    else
    {
        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_write_change_cipher_spec_postprocess( ssl ) );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write change cipher spec" ) );
    return( ret );
}

static int ssl_write_change_cipher_spec_coordinate( mbedtls_ssl_context* ssl )
{
    int ret = SSL_WRITE_CCS_NEEDED;

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if( ssl->state == MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO )
        {
            /* Only transmit the CCS if we have not done so
             * earlier already after the HRR.
             */
            if( ssl->handshake->hello_retry_requests_sent == 0 )
                ret = SSL_WRITE_CCS_NEEDED;
            else
                ret = SSL_WRITE_CCS_SKIP;
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */
    return( ret );
}

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_write_change_cipher_spec_write( mbedtls_ssl_context* ssl,
                                               unsigned char* buf,
                                               size_t buflen,
                                               size_t* olen )
{
    ((void) ssl);

    if( buflen < 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    buf[0] = 1;
    *olen = 1;
    return( 0 );
}
#endif /* !MBEDTLS_SSL_USE_MPS */

static int ssl_write_change_cipher_spec_postprocess( mbedtls_ssl_context* ssl )
{

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        switch( ssl->state )
        {
            case MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO:
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
                ssl->handshake->ccs_sent++;
                break;

            case MBEDTLS_SSL_SERVER_CCS_AFTER_HRR:
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SECOND_CLIENT_HELLO );
                ssl->handshake->ccs_sent++;
                break;

            default:
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        switch( ssl->state )
        {
            case MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO:
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_EARLY_APP_DATA );
                break;
            case MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO:
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SECOND_CLIENT_HELLO );
                break;
            case MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED:
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE );
                break;
            default:
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */

    return( 0 );
}
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */


#if defined(MBEDTLS_SSL_PROTO_DTLS)

/***********************
 *
 * ACK Message Handling
 *
 ***********************/
void mbedtls_ack_clear_all( mbedtls_ssl_context* ssl, int mode )
{
    if( mode == MBEDTLS_SSL_ACK_RECORDS_SENT )
        memset( ssl->record_numbers_sent, 0x0, sizeof( ssl->record_numbers_sent ) );
    else
        memset( ssl->record_numbers_received, 0x0, sizeof( ssl->record_numbers_received ) );
}

int mbedtls_ack_add_record( mbedtls_ssl_context* ssl, uint8_t record, int mode )
{
    int i = 0;
    uint8_t* p;

    if( mode == MBEDTLS_SSL_ACK_RECORDS_SENT ) p = &ssl->record_numbers_sent[0];
    else  p = &ssl->record_numbers_received[0];

    do {
        if( p[i] == 0 )
        {
            p[i] = record;
            break;
        }
        else i++;
    } while ( i <= 7 );

    /* something went terribly wrong */
    if( p[i] != record )
        return ( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR );

    return( 0 );
}
int mbedtls_ssl_parse_ack( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    uint8_t record_numbers[8];

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse ack" ) );

    if( ssl->in_msglen != 8 || ssl->in_msglen > MBEDTLS_SSL_MAX_CONTENT_LEN )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad ack message" ) );
        return( MBEDTLS_ERR_SSL_BAD_ACK );
    }

    mbedtls_ssl_safer_memcmp( ssl->in_msg + mbedtls_ssl_hs_hdr_len( ssl ),
                              record_numbers, sizeof( record_numbers ) );

    /* Determine whether we received every message or not. */
    /* TBD: Do ack processing here */

    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        mbedtls_ssl_recv_flight_completed( ssl );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse ack" ) );

    return( ret );
}

int mbedtls_ssl_write_ack( mbedtls_ssl_context *ssl )
{
    int ret;
    int size;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write Ack msg" ) );

    /* Do we have space for the fixed length part of the ticket */
    if( MBEDTLS_SSL_MAX_CONTENT_LEN < 1 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_ack: not enough space", ret );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }
    size = sizeof( ssl->record_numbers_received );

    /* Length = 8 bytes for record_numbers + 1 byte for content length */
    ssl->out_msglen = 1+size;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_ACK;
    memcpy( ssl->out_msg, ssl->record_numbers_received, size );
    ssl->out_msg[size] = MBEDTLS_SSL_MSG_ACK;

    if( ( ret = mbedtls_ssl_write_record( ssl, SSL_FORCE_FLUSH ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
        return( ret );
    }

    if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flush_output", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write Ack msg" ) );

    return( 0 );
}
#endif /* MBEDTLS_SSL_PROTO_DTLS */


/*
 * mbedtls_ssl_write_signature_algorithms_ext( )
 *
 * enum {
 *    ....
 *   ecdsa_secp256r1_sha256( 0x0403 ),
 *	ecdsa_secp384r1_sha384( 0x0503 ),
 *	ecdsa_secp521r1_sha512( 0x0603 ),
 *    ....
 * } SignatureScheme;
 *
 * struct {
 *    SignatureScheme supported_signature_algorithms<2..2^16-2>;
 * } SignatureSchemeList;
 *
 * Only if we handle at least one key exchange that needs signatures.
 */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
int mbedtls_ssl_write_signature_algorithms_ext( mbedtls_ssl_context *ssl,
                                        unsigned char* buf,
                                        unsigned char* end,
                                        size_t* olen )
{
    unsigned char *p = buf;
    size_t sig_alg_len = 0;
    const int *md;
    unsigned char *sig_alg_list = buf + 6;

    *olen = 0;

    /* Skip the extension on the client if all allowed key exchanges
     * are PSK-based. */
#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
        !mbedtls_ssl_conf_tls13_some_ecdhe_enabled( ssl ) )
    {
        return( 0 );
    }
#endif /* MBEDTLS_SSL_CLI_C */

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding signature_algorithms extension" ) );

    /*
     * Determine length of the signature scheme list
     */
    for ( md = ssl->conf->sig_hashes; *md != SIGNATURE_NONE; md++ )
    {
        sig_alg_len += 2;
    }

    if( sig_alg_len == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No signature algorithms defined." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( end < p || (size_t)( end - p ) < sig_alg_len + 6 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /*
     * Write signature schemes
     */

    for ( md = ssl->conf->sig_hashes; *md != SIGNATURE_NONE; md++ )
    {
        *sig_alg_list++ = (unsigned char)( ( *md >> 8 ) & 0xFF );
        *sig_alg_list++ = (unsigned char)( ( *md ) & 0xFF );
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "signature scheme [%x]", *md ) );
    }

    /*
     * Write extension header
     */

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SIG_ALG >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SIG_ALG ) & 0xFF );

    *p++ = (unsigned char)( ( ( sig_alg_len + 2 ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( sig_alg_len + 2 ) ) & 0xFF );

    *p++ = (unsigned char)( ( sig_alg_len >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( sig_alg_len ) & 0xFF );

    *olen = 6 + sig_alg_len;

    ssl->handshake->extensions_present |= SIGNATURE_ALGORITHM_EXTENSION;
    return( 0 );
}

int mbedtls_ssl_parse_signature_algorithms_ext( mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        size_t len )
{
    size_t sig_alg_list_size; /* size of receive signature algorithms list */
    const unsigned char *p; /* pointer to individual signature algorithm */
    const unsigned char *end = buf + len; /* end of buffer */
    const int *md_cur; /* iterate through configured signature schemes */
    int signature_scheme; /* store received signature algorithm scheme */
    int got_common_sig_alg = 0;  /* record whether there is a match between configured and received signature algorithms */
    size_t num_supported_hashes;
    uint32_t i; /* iterature through received_signature_schemes_list */

    sig_alg_list_size = ( ( buf[0] << 8 ) | ( buf[1] ) );
    if( sig_alg_list_size + 2 != len ||
        sig_alg_list_size % 2 != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad signature_algorithms extension" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /* Determine the number of signature algorithms we support. */
    num_supported_hashes = 0;
    if( ssl->conf->sig_hashes != NULL )
    {
        for( md_cur = ssl->conf->sig_hashes; *md_cur != SIGNATURE_NONE; md_cur++ )
            num_supported_hashes++;
    }

    /* Clear previously allocated memory */
    if( ssl->handshake->received_signature_schemes_list != NULL )
        mbedtls_free( ssl->handshake->received_signature_schemes_list );

    /* Store the received and compatible signature algorithms for later use. */
    ssl->handshake->received_signature_schemes_list =
        mbedtls_calloc( num_supported_hashes + 1, sizeof(uint32_t) );
    /* TODO: Remove heap buffer here */
    if( ssl->handshake->received_signature_schemes_list == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "malloc failed in ssl_parse_signature_algorithms_ext( )" ) );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    i = 0;
    for( p = buf + 2; p < end; p += 2 )
    {
        signature_scheme = ( p[0] << 8 ) | p[1];

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "received signature algorithm: 0x%x", signature_scheme ) );

        for( md_cur = ssl->conf->sig_hashes; *md_cur != SIGNATURE_NONE; md_cur++ )
        {
            if( *md_cur == signature_scheme )
            {
                ssl->handshake->received_signature_schemes_list[i] = signature_scheme;
                i++;
                got_common_sig_alg = 1;
            }
        }

    }

    if( got_common_sig_alg == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "no signature algorithm in common" ) );
        mbedtls_free( ssl->handshake->received_signature_schemes_list );
        return( MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE );
    }

    ssl->handshake->received_signature_schemes_list[i] = SIGNATURE_NONE;

    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

#if !defined(MBEDTLS_SSL_USE_MPS)
void mbedtls_ssl_set_inbound_transform( mbedtls_ssl_context *ssl,
                                       mbedtls_ssl_transform *transform )
{
    if( ssl->transform_in == transform )
        return;

    ssl->transform_in = transform;
    memset( ssl->in_ctr, 0, 8 );

#if defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        ssl_dtls_replay_reset( ssl );
#endif /* MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_SSL_DTLS_ANTI_REPLAY */
}

void mbedtls_ssl_set_outbound_transform( mbedtls_ssl_context *ssl,
                                         mbedtls_ssl_transform *transform )
{
    ssl->transform_out = transform;
    memset( ssl->cur_out_ctr, 0, 8 );
}
#endif /* !MBEDTLS_SSL_USE_MPS */

/* mbedtls_ssl_generate_handshake_traffic_keys() generates keys necessary for
 * protecting the handshake messages, as described in Section 7 of TLS 1.3. */
int mbedtls_ssl_generate_handshake_traffic_keys( mbedtls_ssl_context *ssl,
                                                 mbedtls_ssl_key_set *traffic_keys )
{
    int ret = 0;
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    size_t keylen, ivlen;

#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_context sha256;
#endif
#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_context sha512;
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_generate_handshake_traffic_keys" ) );

    cipher_info = mbedtls_cipher_info_from_type(
                                  handshake->ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found",
                                    handshake->ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    md_info = mbedtls_md_info_from_type( handshake->ciphersuite_info->mac );
    if( md_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found",
                                    handshake->ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    suite_info = mbedtls_ssl_ciphersuite_from_id(
                                  ssl->session_negotiate->ciphersuite );
    if( suite_info == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
#if defined(MBEDTLS_SHA256_C)
        handshake->calc_finished = ssl_calc_finished_tls_sha256;
#else
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif /* MBEDTLS_SHA256_C */
    }

    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
#if defined(MBEDTLS_SHA512_C)
        handshake->calc_finished = ssl_calc_finished_tls_sha384;
#else
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif /* MBEDTLS_SHA512_C */
    }

    if( ( mbedtls_hash_size_for_ciphersuite( suite_info ) != 32 ) &&
        ( mbedtls_hash_size_for_ciphersuite( suite_info ) != 48 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(MBEDTLS_SHA256_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
        mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

        if( ( ret = mbedtls_sha256_finish_ret( &sha256, hash ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
        mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

        if( ( ret = mbedtls_sha512_finish_ret( &sha512, hash ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA512_C */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "rolling hash", hash,
                 mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     *
     * Handshake Secret
     * |
     * +-----> Derive-Secret( ., "c hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = client_handshake_traffic_secret
     * |
     * +-----> Derive-Secret( ., "s hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = server_handshake_traffic_secret
     *
     */


    /*
     * Compute client_handshake_traffic_secret with
     *	 Derive-Secret( ., "c hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
             (const unsigned char*) ssl->handshake->handshake_secret,
             (int) mbedtls_hash_size_for_ciphersuite( suite_info ),
             MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_hs_traffic ),
             (const unsigned char * ) hash,
             (int) mbedtls_hash_size_for_ciphersuite( suite_info ),
             MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
             (unsigned char *) ssl->handshake->client_handshake_traffic_secret,
             (int) mbedtls_hash_size_for_ciphersuite( suite_info ) );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        goto exit;
    }

    /*
     * Export client handshake traffic secret
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                ssl->handshake->client_handshake_traffic_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    MBEDTLS_SSL_DEBUG_BUF( 4, "Client handshake traffic secret",
                           ssl->handshake->client_handshake_traffic_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Compute server_handshake_traffic_secret with
     *   Derive-Secret( ., "s hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->handshake_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_hs_traffic ),
                         hash, mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->server_handshake_traffic_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );
    if( ret != 0 )
        goto exit;

    /*
     * Export server handshake traffic secret
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET,
                ssl->handshake->server_handshake_traffic_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    MBEDTLS_SSL_DEBUG_BUF( 4, "Server handshake traffic secret",
                           ssl->handshake->server_handshake_traffic_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Compute exporter_secret with
     *   mbedtls_ssl_tls1_3_derive_secret( Master Secret,
     *                                     "exp master",
     *                                     ClientHello...Server Finished )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( exp_master ),
                         hash, mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->exporter_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );
    if( ret != 0 )
        goto exit;

    MBEDTLS_SSL_DEBUG_BUF( 4, "Exporter secret",
                           ssl->handshake->exporter_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Export exporter master secret
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_EXPORTER_MASTER_SECRET,
                ssl->handshake->exporter_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    MBEDTLS_SSL_DEBUG_BUF( 5, "exporter_secret",
                           ssl->handshake->exporter_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    keylen = cipher_info->key_bitlen / 8;
    ivlen = cipher_info->iv_size;

    if( ( ret = mbedtls_ssl_tls1_3_make_traffic_keys( mbedtls_md_get_type( md_info ),
                                 ssl->handshake->client_handshake_traffic_secret,
                                 ssl->handshake->server_handshake_traffic_secret,
                                 mbedtls_hash_size_for_ciphersuite( suite_info ),
                                 keylen, ivlen, traffic_keys ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_make_traffic_keys failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "client_handshake write_key",
                           traffic_keys->client_write_key,
                           traffic_keys->key_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "server_handshake write_key",
                           traffic_keys->server_write_key,
                           traffic_keys->key_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "client_handshake write_iv",
                           traffic_keys->client_write_iv,
                           traffic_keys->iv_len);

    MBEDTLS_SSL_DEBUG_BUF( 4, "server_handshake write_iv",
                           traffic_keys->server_write_iv,
                           traffic_keys->iv_len);

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= derive traffic keys" ) );

exit:
#if defined(MBEDTLS_SHA256_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
        mbedtls_sha256_free( &sha256 );
    }
    else
#endif
#if defined(MBEDTLS_SHA512_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
        mbedtls_sha512_free( &sha512 );
    }
    else
#endif
    {
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( ret );
}

    /*
     * The mbedtls_ssl_create_verify_structure() creates the verify structure.
     * As input, it requires the transcript hash.
     *
     * The structure is computed per TLS 1.3 specification as:
     *   - 64 bytes of octet 32,
     *   - 33 bytes for the context string
     *        (which is either "TLS 1.3, client CertificateVerify"
     *         or "TLS 1.3, server CertificateVerify"),
     *   - 1 byte for the octet 0x0, which servers as a separator,
     *   - 32 or 48 bytes for the Transcript-Hash(Handshake Context, Certificate)
     *     (depending on the size of the transcript_hash)
     *
     * This results in a total size of
     * - 130 bytes for a SHA256-based transcript hash, or
     *   (64 + 33 + 1 + 32 bytes)
     * - 146 bytes for a SHA384-based transcript hash.
     *   (64 + 33 + 1 + 48 bytes)
     *
     * The caller has to ensure that the buffer has this size.
     */
static void mbedtls_ssl_create_verify_structure(
                                        unsigned char *transcript_hash,
                                        size_t transcript_hash_len,
                                        unsigned char *verify_buffer,
                                        size_t *verify_buffer_len,
                                        int from )
{
    /* The length of context_string_[client|server] is
     * sizeof( "TLS 1.3, xxxxxx CertificateVerify" ) - 1, i.e. 33 bytes.
     */
    const unsigned int content_string_len = sizeof( "TLS 1.3, xxxxxx CertificateVerify" ) - 1;
    const unsigned char context_string_client[] = "TLS 1.3, client CertificateVerify";
    const unsigned char context_string_server[] = "TLS 1.3, server CertificateVerify";

    memset( verify_buffer, 32, 64 );

    if( from == MBEDTLS_SSL_IS_CLIENT )
    {
        memcpy( verify_buffer + 64, context_string_client, content_string_len );
    }
    else
    { /* from == MBEDTLS_SSL_IS_SERVER */
        memcpy( verify_buffer + 64, context_string_server, content_string_len );
    }

    verify_buffer[64 + content_string_len] = 0x0;
    memcpy( verify_buffer + 64 + content_string_len + 1, transcript_hash, transcript_hash_len );

    *verify_buffer_len = 64 + content_string_len + 1 + transcript_hash_len;
}


/* mbedtls_ssl_tls1_3_derive_master_secret( )
 *
 * Generates the keys based on the TLS 1.3 key hierachy:
 *
 *                    0
 *                    |
 *                    v
 *     PSK ->  HKDF-Extract = Early Secret
 *                    |
 *                    v
 *     Derive-Secret( ., "derived", "" )
 *                    |
 *                    v
 *  (EC)DHE -> HKDF-Extract = Handshake Secret
 *                    |
 *                    v
 *     Derive-Secret( ., "derived", "" )
 *                    |
 *                    v
 *     0 -> HKDF-Extract = Master Secret
 *
 */
int mbedtls_ssl_tls1_3_derive_master_secret( mbedtls_ssl_context *ssl )
{
    unsigned char ECDHE[66];

    size_t ECDHE_len;
    int ret = 0;
    const mbedtls_md_info_t *md;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    unsigned char *psk;
    size_t psk_len;
    unsigned int psk_allocated = 0;
    int hash_size;

    if( ssl->session_negotiate == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "session_negotiate == NULL, mbedtls_ssl_tls1_3_derive_master_secret failed" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    md = mbedtls_md_info_from_type( ssl->handshake->ciphersuite_info->mac );
    if( md == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "md == NULL, mbedtls_ssl_tls1_3_derive_master_secret failed" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session_negotiate->ciphersuite );
    if( suite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "suite_info == NULL, mbedtls_ssl_tls1_3_derive_master_secret failed" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Determine hash size */
    hash_size = mbedtls_hash_size_for_ciphersuite( suite_info );
    if( hash_size == -1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_hash_size_for_ciphersuite( ) failed" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * Compute PSK for first stage of secret evolution.
     */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    psk = ssl->conf->psk;
    psk_len = ssl->conf->psk_len;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    /* If the psk callback was called, use its result */
    if( ( ssl->handshake->psk != NULL ) &&
        ( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
          ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK ) )
    {
        psk = ssl->handshake->psk;
        psk_len = ssl->handshake->psk_len;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    if( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA )
    {

        /* If we are not using a PSK-based ciphersuite then the
         * psk identity is set to a 0 vector.
         */

        psk = mbedtls_calloc( hash_size,1 );
        if( psk == NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "malloc for psk == NULL, mbedtls_ssl_tls1_3_derive_master_secret failed" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        psk_allocated = 1;
        memset( psk, 0x0, hash_size );
        psk_len = hash_size;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

    /*
     * Compute ECDHE secret for second stage of secret evolution.
     */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
    if( ( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK ) ||
        ( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA ) )
    {
        if( ( ret = mbedtls_ecdh_calc_secret( &ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected],
                                              &ECDHE_len,
                                              ECDHE,
                                              sizeof( ECDHE ),
                                              ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_calc_secret", ret );
            if( psk_allocated == 1 ) mbedtls_free( psk );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_MPI( 3, "ECDHE:", &ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected].z );

    } else
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK )
    {
        memset( ECDHE, 0x0, hash_size );
        MBEDTLS_SSL_DEBUG_BUF( 3, "ECDHE", ECDHE, hash_size );
        ECDHE_len=hash_size;
    } else
#endif	/* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported key exchange -- mbedtls_ssl_tls1_3_derive_master_secret failed." ) );
        if( psk_allocated == 1 ) mbedtls_free( psk );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }


    /*
     * Compute EarlySecret
     */

    ret = mbedtls_ssl_tls1_3_evolve_secret( ssl->handshake->ciphersuite_info->mac,
                                            NULL, /* use 0 as old secret */
                                            psk, psk_len,
                                            ssl->handshake->early_secret );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_evolve_secret", ret );
        if( psk_allocated == 1 )
            mbedtls_free( psk );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Early secret", ssl->handshake->early_secret, hash_size );

    /*
     * Compute HandshakeSecret
     */

    ret = mbedtls_ssl_tls1_3_evolve_secret(
                              ssl->handshake->ciphersuite_info->mac,
                              ssl->handshake->early_secret,
                              ECDHE, ECDHE_len,
                              ssl->handshake->handshake_secret );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_hkdf_extract( ) with early_secret", ret );
        if( psk_allocated == 1 ) mbedtls_free( psk );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Handshake secret", ssl->handshake->handshake_secret, hash_size );

    /*
     * Compute MasterSecret
     */

    ret = mbedtls_ssl_tls1_3_evolve_secret(
                              ssl->handshake->ciphersuite_info->mac,
                              ssl->handshake->handshake_secret,
                              NULL, 0,
                              ssl->handshake->master_secret );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_hkdf_extract( ) with early_secret", ret );
        if( psk_allocated == 1 ) mbedtls_free( psk );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Master secret", ssl->handshake->master_secret, hash_size );

    if( psk_allocated == 1 ) mbedtls_free( psk );

    /*
     * Export client early traffic secret
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_CLIENT_EARLY_TRAFFIC_SECRET,
                ssl->handshake->early_secret, hash_size );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */


    return( 0 );
}



/*
 *
 * STATE HANDLING: CertificateVerify
 *
 */

/*
 * Overview
 */

/* Main entry point: orchestrates the other functions. */
int mbedtls_ssl_certificate_verify_process( mbedtls_ssl_context* ssl );

/* Coordinate: Check whether a certificate verify message should be sent.
 * Returns a negative value on failure, and otherwise
 * - SSL_CERTIFICATE_VERIFY_SKIP
 * - SSL_CERTIFICATE_VERIFY_SEND
 * to indicate if the CertificateVerify message should be sent or not.
 */
#define SSL_CERTIFICATE_VERIFY_SKIP 0
#define SSL_CERTIFICATE_VERIFY_SEND 1
static int ssl_certificate_verify_coordinate( mbedtls_ssl_context* ssl );
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_certificate_verify_write( mbedtls_ssl_context* ssl,
                                         unsigned char* buf,
                                         size_t buflen,
                                         size_t* olen );
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
static int ssl_certificate_verify_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */

int mbedtls_ssl_certificate_verify_process( mbedtls_ssl_context* ssl )
{
    int ret = 0;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate verify" ) );

    /* Coordination step: Check if we need to send a CertificateVerify */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_certificate_verify_coordinate( ssl ) );

    if( ret == SSL_CERTIFICATE_VERIFY_SEND )
    {
#if defined(MBEDTLS_SSL_USE_MPS)
        mbedtls_mps_handshake_out msg;
        unsigned char *buf;
        mbedtls_mps_size_t buf_len, msg_len;

        msg.type   = MBEDTLS_SSL_HS_CERTIFICATE_VERIFY;
        msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                           &msg, NULL, NULL ) );

        /* Request write-buffer */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get_ext( msg.handle, MBEDTLS_MPS_SIZE_MAX,
                                                      &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_certificate_verify_write(
                                  ssl, buf, buf_len, &msg_len ) );

        mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                                            buf, msg_len );

        /* Commit message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial_ext( msg.handle,
                                                                 buf_len - msg_len ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

#else  /* MBEDTLS_SSL_USE_MPS */

        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

        /* Prepare CertificateVerify message in output buffer. */
        MBEDTLS_SSL_PROC_CHK( ssl_certificate_verify_write( ssl, ssl->out_msg,
                                                            MBEDTLS_SSL_MAX_CONTENT_LEN,
                                                            &ssl->out_msglen ) );

        ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
        ssl->out_msg[0] = MBEDTLS_SSL_HS_CERTIFICATE_VERIFY;

        /* Dispatch message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg( ssl ) );

        /* NOTE: With the new messaging layer, the postprocessing
         *       step might come after the dispatching step if the
         *       latter doesn't send the message immediately.
         *       At the moment, we must do the postprocessing
         *       prior to the dispatching because if the latter
         *       returns WANT_WRITE, we want the handshake state
         *       to be updated in order to not enter
         *       this function again on retry.
         *
         *       Further, once the two calls can be re-ordered, the two
         *       calls to ssl_certificate_verify_postprocess( ) can be
         *       consolidated. */

#endif /* MBEDTLS_SSL_USE_MPS */
    }

    /* Update state */
    MBEDTLS_SSL_PROC_CHK( ssl_certificate_verify_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate verify" ) );
    return( ret );
}

static int ssl_certificate_verify_coordinate( mbedtls_ssl_context* ssl )
{
    int have_own_cert = 1;
#if defined(MBEDTLS_SHA256_C) || defined(MBEDTLS_SHA512_C)
    int ret;
#endif /* MBEDTLS_SHA256_C || MBEDTLS_SHA512_C */

    if( ssl->session_negotiate->key_exchange != MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate verify" ) );
        return( SSL_CERTIFICATE_VERIFY_SKIP );
    }

#if !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else
    if( mbedtls_ssl_own_cert( ssl ) == NULL ) have_own_cert = 0;

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        if( ssl->client_auth == 0 || have_own_cert == 0 || ssl->conf->authmode == MBEDTLS_SSL_VERIFY_NONE )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate verify" ) );
            return( 0 );
        }
    }

    if( have_own_cert == 0 && ssl->client_auth == 1 && ssl->conf->authmode != MBEDTLS_SSL_VERIFY_NONE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no certificate" ) );
        return( MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED );
    }

    /*
     * Check whether the signature scheme corresponds to the key we are using
     */
    if( mbedtls_ssl_sig_from_pk( mbedtls_ssl_own_key( ssl ) ) != MBEDTLS_SSL_SIG_ECDSA )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Certificate Verify: Only ECDSA signature algorithm is currently supported." ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    /* Calculate the transcript hash */
    ret = mbedtls_ssl_get_handshake_transcript( ssl,
      ssl->handshake->ciphersuite_info->mac,
      ssl->handshake->state_local.certificate_verify_out.handshake_hash,
      sizeof( ssl->handshake->state_local.certificate_verify_out.handshake_hash ),
      &ssl->handshake->state_local.certificate_verify_out.handshake_hash_len );
    if( ret != 0 )
        return( ret );

    MBEDTLS_SSL_DEBUG_BUF( 3, "handshake hash",
        ssl->handshake->state_local.certificate_verify_out.handshake_hash,
        ssl->handshake->state_local.certificate_verify_out.handshake_hash_len);

    return( SSL_CERTIFICATE_VERIFY_SEND );
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
}


#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_certificate_verify_write( mbedtls_ssl_context* ssl,
                                         unsigned char* buf,
                                         size_t buflen,
                                         size_t* olen )
{
    int ret;
    size_t n = 0;
    unsigned char verify_buffer[ MBEDTLS_SSL_VERIFY_STRUCT_MAX_SIZE ];
    const int *sig_scheme; /* iterate through configured signature schemes */
    size_t verify_buffer_len;
    mbedtls_pk_context *own_key;
    size_t own_key_size;
    unsigned int md_alg;
    int sig_alg;
    unsigned char verify_hash[ MBEDTLS_MD_MAX_SIZE ];
    size_t verify_hash_len;
    unsigned char *p;

#if defined(MBEDTLS_SSL_USE_MPS)
    p = buf;
    if( buflen < 2 + MBEDTLS_MD_MAX_SIZE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too short" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

#else
    p = buf + 4;
    /* TBD: Check whether the signature fits into the buffer. */
    if( buflen < ( mbedtls_ssl_hs_hdr_len( ssl ) + 2 + MBEDTLS_MD_MAX_SIZE ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too short" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }
#endif /* MBEDTLS_SSL_USE_MPS */

    /* Create verify structure */
    mbedtls_ssl_create_verify_structure(
            ssl->handshake->state_local.certificate_verify_out.handshake_hash,
            ssl->handshake->state_local.certificate_verify_out.handshake_hash_len,
            verify_buffer,
            &verify_buffer_len,
            ssl->conf->endpoint );

    /*
     *  struct {
     *    SignatureScheme algorithm;
     *    opaque signature<0..2^16-1>;
     *  } CertificateVerify;
     */

    /* Determine size of key */
    own_key = mbedtls_ssl_own_key( ssl );
    if( own_key != NULL)
    {
        own_key_size = mbedtls_pk_get_bitlen( own_key );
        switch( own_key_size)
        {
            case 256:
                md_alg = MBEDTLS_MD_SHA256;
                sig_alg = SIGNATURE_ECDSA_SECP256r1_SHA256;
                break;
            case 384:
                md_alg =  MBEDTLS_MD_SHA384;
                sig_alg = SIGNATURE_ECDSA_SECP384r1_SHA384;
                break;
            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "unknown key size: %d bits",
                               own_key_size ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
    {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Verify whether we can use signature algorithm */
    ssl->handshake->signature_scheme_client = SIGNATURE_NONE;

    if( ssl->handshake->received_signature_schemes_list != NULL )
    {
        for( sig_scheme = ssl->handshake->received_signature_schemes_list;
             *sig_scheme != SIGNATURE_NONE; sig_scheme++ )
        {
            if( *sig_scheme == sig_alg )
            {
                ssl->handshake->signature_scheme_client = *sig_scheme;
                break;
            }
        }
    }

    if( ssl->handshake->signature_scheme_client == SIGNATURE_NONE )
    {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    *(p++) = (unsigned char)( ( ssl->handshake->signature_scheme_client >> 8 ) & 0xFF );
    *(p++) = (unsigned char)( ( ssl->handshake->signature_scheme_client >> 0 ) & 0xFF );

    /* Hash verify buffer with indicated hash function */
#if defined(MBEDTLS_SHA256_C)
    if( md_alg == MBEDTLS_MD_SHA256 )
    {
        verify_hash_len = 32;
        if( ( ret = mbedtls_sha256_ret( verify_buffer,
            verify_buffer_len, verify_hash, 0 /* 0 for SHA-256 instead of SHA-224 */ )  ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_ret", ret );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
        }
    }
    else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
    if( md_alg == MBEDTLS_MD_SHA384 )
    {
        verify_hash_len = 48;
        if( ( ret = mbedtls_sha512_ret( verify_buffer,
                                    verify_buffer_len,
                                    verify_hash,
                                    1 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_ret", ret );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
        }
    }
    else
#endif /* MBEDTLS_SHA512_C */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "verify hash", verify_hash, verify_hash_len );

    if( ( ret = mbedtls_pk_sign( mbedtls_ssl_own_key( ssl ),
                                 md_alg,
                                 verify_hash, verify_hash_len,
                                 p + 2, &n,
                                 ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_pk_sign", ret );
        return( ret );
    }

    p[0] = (unsigned char)( n >> 8 );
    p[1] = (unsigned char)( n >> 0 );

    p += 2 + n;

    *olen = (size_t)( p - buf );
    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

static int ssl_certificate_verify_postprocess( mbedtls_ssl_context* ssl )
{
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
            mbedtls_ack_add_record( ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, MBEDTLS_SSL_ACK_RECORDS_SENT );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_FINISHED );
    }
    else
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
    }
    return( 0 );
}

/*
 *
 * STATE HANDLING: Read CertificateVerify
 *
 */

/*
 * Overview
 */

/* Main entry point; orchestrates the other functions */
int mbedtls_ssl_read_certificate_verify_process( mbedtls_ssl_context* ssl );

/* Coordinate: Check whether a certificate verify message is expected.
 * Returns a negative value on failure, and otherwise
 * - SSL_CERTIFICATE_VERIFY_SKIP
 * - SSL_CERTIFICATE_VERIFY_READ
 * to indicate if the CertificateVerify message should be present or not.
 */
#define SSL_CERTIFICATE_VERIFY_SKIP 0
#define SSL_CERTIFICATE_VERIFY_READ 1
static int ssl_read_certificate_verify_coordinate( mbedtls_ssl_context* ssl );

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_read_certificate_verify_fetch( mbedtls_ssl_context* ssl,
                                              unsigned char** buf,
                                              size_t* buflen );
#endif /* MBEDTLS_SSL_USE_MPS */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/* Parse and validate CertificateVerify message
 *
 * Note: The size of the hash buffer is assumed to be large enough to
 *       hold the transcript given the selected hash algorithm.
 *       No bounds-checking is done inside the function.
 */
static int ssl_read_certificate_verify_parse( mbedtls_ssl_context* ssl,
                                              unsigned char const* buf,
                                              size_t buflen,
                                              unsigned char const* hash,
                                              size_t hashlen );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/* Update handshake state machine */
static int ssl_read_certificate_verify_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */

int mbedtls_ssl_read_certificate_verify_process( mbedtls_ssl_context* ssl )
{
    int ret;
    unsigned char verify_buffer[ MBEDTLS_SSL_VERIFY_STRUCT_MAX_SIZE ];
    size_t verify_buffer_len;
    unsigned char transcript[ MBEDTLS_MD_MAX_SIZE ];
    size_t transcript_len;

    /* Coordination step */
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate verify" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_read_certificate_verify_coordinate( ssl ) );

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) // TBD: double-check
    if( ret == SSL_CERTIFICATE_VERIFY_READ )
    {
        unsigned char *buf;
        size_t buflen;

        /* Need to calculate the hash of the transcript first
         * before reading the message since otherwise it gets
         * included in the transcript
         */
        ret = mbedtls_ssl_get_handshake_transcript( ssl,
                               ssl->handshake->ciphersuite_info->mac,
                               transcript, sizeof( transcript ),
                               &transcript_len );
        if( ret != 0 )
            return( ret );

        MBEDTLS_SSL_DEBUG_BUF( 3, "handshake hash", transcript,
                               transcript_len );

        /* Create verify structure */
        mbedtls_ssl_create_verify_structure( transcript,
                                     transcript_len,
                                     verify_buffer,
                                     &verify_buffer_len,
                                     !ssl->conf->endpoint );

#if defined(MBEDTLS_SSL_USE_MPS)

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_fetch_full_hs_msg( ssl,
                                              MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                                              &buf, &buflen ) );

        mbedtls_ssl_add_hs_msg_to_checksum(
            ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, buf, buflen );

        /* Process the message contents */
        MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_verify_parse( ssl, buf, buflen,
                                                                 verify_buffer,
                                                                 verify_buffer_len ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );

#else /* MBEDTLS_SSL_USE_MPS */

        MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_verify_fetch( ssl, &buf, &buflen ) );

        /* Process the message contents */
        MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_verify_parse( ssl, buf, buflen,
                                                                 verify_buffer,
                                                                 verify_buffer_len ) );

#endif /* MBEDTLS_SSL_USE_MPS */


    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
    if( ret == SSL_CERTIFICATE_VERIFY_SKIP )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate verify" ) );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Update state machine and handshake checksum state.
     *
     * The manual update of the checksum state only needs to be
     * done manually here because we couldn't have it done automatically
     * when reading the message.
     */
    MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_verify_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate verify" ) );
    return( ret );
}

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_read_certificate_verify_fetch( mbedtls_ssl_context *ssl,
                                              unsigned char **buf,
                                              size_t *buflen )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE         ||
        ssl->in_msg[0]  != MBEDTLS_SSL_HS_CERTIFICATE_VERIFY )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate verify message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

    *buf    = ssl->in_msg   + 4;
    *buflen = ssl->in_hslen - 4;

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_read_certificate_verify_coordinate( mbedtls_ssl_context* ssl )
{
    if( ssl->session_negotiate->key_exchange != MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA )
    {
        return( SSL_CERTIFICATE_VERIFY_SKIP );
    }

#if !defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else
    if( ssl->session_negotiate->peer_cert == NULL )
        return( SSL_CERTIFICATE_VERIFY_SKIP );

    return( SSL_CERTIFICATE_VERIFY_READ );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
}


#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

static int ssl_read_certificate_verify_parse( mbedtls_ssl_context* ssl,
                                              unsigned char const* buf,
                                              size_t buflen,
                                              unsigned char const* verify_buffer,
                                              size_t verify_buffer_len )
{
    int ret;
    int signature_scheme;
    size_t sig_len;
    mbedtls_pk_type_t sig_alg;
    mbedtls_md_type_t md_alg;
    unsigned char verify_hash[ MBEDTLS_MD_MAX_SIZE ];
    size_t verify_hash_len;

    void const *opts_ptr = NULL;
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_pk_rsassa_pss_options opts;
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    /*
     * struct {
     *     SignatureScheme algorithm;
     *     opaque signature<0..2^16-1>;
     * } CertificateVerify;
     *
     */

    if( buflen < 2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate verify message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    signature_scheme = ( buf[0] << 8 ) | buf[1];

    /* We currently only support ECDSA-based signatures */
    switch ( signature_scheme ) {
        case SIGNATURE_ECDSA_SECP256r1_SHA256:
            md_alg = MBEDTLS_MD_SHA256;
            sig_alg = MBEDTLS_PK_ECDSA;
            break;
        case SIGNATURE_ECDSA_SECP384r1_SHA384:
            md_alg = MBEDTLS_MD_SHA384;
            sig_alg = MBEDTLS_PK_ECDSA;
            break;
        case SIGNATURE_ECDSA_SECP521r1_SHA512:
            md_alg = MBEDTLS_MD_SHA512;
            sig_alg = MBEDTLS_PK_ECDSA;
            break;
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
        case SIGNATURE_RSA_PSS_RSAE_SHA256:
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "Certificate Verify: using RSA" ) );
            md_alg = MBEDTLS_MD_SHA256;
            sig_alg = MBEDTLS_PK_RSASSA_PSS;
            break;
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Certificate Verify: Unknown signature algorithm." ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Certificate Verify: Signature algorithm ( %04x )", signature_scheme ) );

    buflen -= 2;
    buf += 2;

    /*
     * Signature
     */

    /*
     * Check the certificate's key type matches the signature alg
     */
    if( !mbedtls_pk_can_do( &ssl->session_negotiate->peer_cert->pk, sig_alg ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "signature algorithm doesn't match cert key" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    if( buflen < 2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate verify message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    sig_len = ( buf[0] << 8 ) | buf[1];
    buf += 2;
    buflen -= 2;

    if( buflen != sig_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate verify message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    /* Hash verify buffer with indicated hash function */
#if defined(MBEDTLS_SHA256_C)
    if( md_alg == MBEDTLS_MD_SHA256 )
    {
        verify_hash_len = 32;
        if( ( ret = mbedtls_sha256_ret( verify_buffer,
            verify_buffer_len, verify_hash, 0 /* 0 for SHA-256 instead of SHA-224 */ )  ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_ret", ret );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
        }
    }
    else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
    if( md_alg == MBEDTLS_MD_SHA384 )
    {
        verify_hash_len = 48;
        if( ( ret = mbedtls_sha512_ret( verify_buffer,
                                    verify_buffer_len,
                                    verify_hash,
                                    1 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_ret", ret );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
        }
    }
    else
#endif /* MBEDTLS_SHA512_C */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Certificate Verify: Unknown signature algorithm." ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "verify hash", verify_hash, verify_hash_len );
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    if( sig_alg == MBEDTLS_PK_RSASSA_PSS )
    {
        const mbedtls_md_info_t* md_info;
        opts.mgf1_hash_id = md_alg;
        if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        {
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        opts.expected_salt_len = mbedtls_md_get_size( md_info );
        opts_ptr = (const void*) &opts;
    }
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    if( ( ret = mbedtls_pk_verify_ext(
              sig_alg,
              opts_ptr,
              &ssl->session_negotiate->peer_cert->pk,
              md_alg,
              verify_hash,
              verify_hash_len,
              buf,
              sig_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_pk_verify_ext", ret );
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */


static int ssl_read_certificate_verify_postprocess( mbedtls_ssl_context* ssl )
{
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_FINISHED );
    }
    else
#endif /* MBEDTLS_SSL_SRV_C */
    {

#if	defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            mbedtls_ack_add_record( ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, MBEDTLS_SSL_ACK_RECORDS_RECEIVED );
        }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
    }

    return( 0 );
}



/*
 *
 * STATE HANDLING: Outgoing Certificate
 *
 */

/*
 * Overview
 */

/* Main state-handling entry point; orchestrates the other functions. */
int mbedtls_ssl_write_certificate_process( mbedtls_ssl_context* ssl );

/* Check if a certificate should be written, and if yes,
 * if it is available.
 * Returns a negative error code on failure ( such as no certificate
 * being available on the server ), and otherwise
 * SSL_WRITE_CERTIFICATE_AVAILABLE or
 * SSL_WRITE_CERTIFICATE_SKIP
 * indicating that a Certificate message should be written based
 * on the configured certificate, or whether it should be silently skipped.
 */

#define SSL_WRITE_CERTIFICATE_AVAILABLE  0
#define SSL_WRITE_CERTIFICATE_SKIP       1
static int ssl_write_certificate_coordinate( mbedtls_ssl_context* ssl );
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/* Write certificate message based on the configured certificate */
static int ssl_write_certificate_write( mbedtls_ssl_context* ssl,
                                        unsigned char* buf,
                                        size_t buflen,
                                        size_t* olen );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
/* Update the state after handling the outgoing certificate message. */
static int ssl_write_certificate_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */

int mbedtls_ssl_write_certificate_process( mbedtls_ssl_context* ssl )
{
    int ret;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    /* Coordination: Check if we need to send a certificate. */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_write_certificate_coordinate( ssl ) );

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    if( ret == SSL_WRITE_CERTIFICATE_AVAILABLE )
    {
#if defined(MBEDTLS_SSL_USE_MPS)
        mbedtls_mps_handshake_out msg;
        unsigned char *buf;
        mbedtls_mps_size_t buf_len, msg_len;

        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

        msg.type   = MBEDTLS_SSL_HS_CERTIFICATE;
        msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                           &msg, NULL, NULL ) );

        /* Request write-buffer */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get_ext( msg.handle, MBEDTLS_MPS_SIZE_MAX,
                                                      &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_write_certificate_write(
                                  ssl, buf, buf_len, &msg_len ) );

        mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                                            buf, msg_len );

        /* Commit message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial_ext( msg.handle,
                                                                 buf_len - msg_len ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

#else  /* MBEDTLS_SSL_USE_MPS */

        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

        /* Write certificate to message buffer. */
        MBEDTLS_SSL_PROC_CHK( ssl_write_certificate_write( ssl, ssl->out_msg,
                                                           MBEDTLS_SSL_MAX_CONTENT_LEN,
                                                           &ssl->out_msglen ) );

        ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
        ssl->out_msg[0] = MBEDTLS_SSL_HS_CERTIFICATE;

        /* Dispatch message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg( ssl ) );

#endif /* MBEDTLS_SSL_USE_MPS */

    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
    }

    /* Update state */
    MBEDTLS_SSL_PROC_CHK( ssl_write_certificate_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate" ) );
    return( ret );
}


static int ssl_write_certificate_coordinate( mbedtls_ssl_context* ssl )
{
#if defined(MBEDTLS_SSL_SRV_C)
    int have_own_cert = 1;
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
                  ( "Switch to handshake traffic keys for outbound traffic" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
        {
            int ret;

            /* Use new transform for outgoing data. */
            ret = mbedtls_mps_set_outgoing_keys( &ssl->mps.l4,
                                                 ssl->epoch_handshake );
            if( ret != 0 )
                return( ret );
        }
#else
        mbedtls_ssl_set_outbound_transform( ssl, ssl->transform_handshake );
#endif /* MBEDTLS_SSL_USE_MPS */
    }
#endif /* MBEDTLS_SSL_CLI_C */

    /* For PSK and ECDHE-PSK ciphersuites there is no certificate to exchange. */
    if( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
        ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
        return( SSL_WRITE_CERTIFICATE_SKIP );
    }

#if !defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        /* The client MUST send a Certificate message if and only
         * if the server has requested client authentication via a
         * CertificateRequest message.
         *
         * client_auth indicates whether the server had requested
         * client authentication.
         */
        if( ssl->client_auth == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
            return( SSL_WRITE_CERTIFICATE_SKIP );
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if( have_own_cert == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no certificate to send" ) );
            return( MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED );
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

    return( SSL_WRITE_CERTIFICATE_AVAILABLE );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
}



#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
static int ssl_write_certificate_write( mbedtls_ssl_context* ssl,
                                        unsigned char* buf,
                                        size_t buflen,
                                        size_t* olen )
{
    size_t i, n, total_len;
    const mbedtls_x509_crt* crt;
    unsigned char* start;

    /* TODO: Add bounds checks! Only then remove the next line. */
    ((void) buflen );

#if !defined(MBEDTLS_SSL_USE_MPS)
    /*
     *  Handshake Header is 4 ( before adding DTLS-specific fields, which is done later )
     *  Certificate Request Context: 1 byte
     *  Length of CertificateEntry: 3 bytes
     *     Length of cert. 1: 2 bytes
     *     cert_data: n bytes
     *	   Extension: 2 bytes
     *     Extension value: m bytes
     */
    i = 4;
#else /* MBEDTLS_SSL_USE_MPS */
    i = 0;
#endif /* MBEDTLS_SSL_USE_MPS */

    /* empty certificate_request_context with length 0 */
    buf[i] = 0;
    /* Skip length of certificate_request_context and
     * the length of CertificateEntry
     */
    i += 1;

#if defined(MBEDTLS_SSL_CLI_C)
    /* If the server requests client authentication but no suitable
     * certificate is available, the client MUST send a
     * Certificate message containing no certificates
     * ( i.e., with the "certificate_list" field having length 0 ).
     *
     * authmode indicates whether the client configuration required authentication.
     */
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT && ( ( mbedtls_ssl_own_cert( ssl ) == NULL ) || ssl->conf->authmode == MBEDTLS_SSL_VERIFY_NONE ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write empty client certificate" ) );
        buf[i] = 0;
        buf[i + 1] = 0;
        buf[i + 2] = 0;
        i += 3;

        goto empty_cert;
    }
#endif /* MBEDTLS_SSL_CLI_C */

    start = &buf[i];
    crt = mbedtls_ssl_own_cert( ssl );
    MBEDTLS_SSL_DEBUG_CRT( 3, "own certificate", mbedtls_ssl_own_cert( ssl ) );

    i += 3;

    while ( crt != NULL )
    {
        n = crt->raw.len;
        if( n > buflen - 3 - i )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "certificate too large, %d > %d",
                                        i + 3 + n, MBEDTLS_SSL_MAX_CONTENT_LEN ) );
            return( MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE );
        }

        buf[i] = (unsigned char)( n >> 16 );
        buf[i + 1] = (unsigned char)( n >> 8 );
        buf[i + 2] = (unsigned char)( n );

        i += 3; memcpy( buf + i, crt->raw.p, n );
        i += n; crt = crt->next;

        /* Currently, we don't have any certificate extensions defined.
         * Hence, we are sending an empty extension with length zero.
         */
        buf[i] = 0;
        buf[i + 1] = 0;
        i += 2;
    }
    total_len = &buf[i] - start - 3;
    *start++ = (unsigned char)( ( total_len ) >> 16 );
    *start++ = (unsigned char)( ( total_len ) >> 8 );
    *start++ = (unsigned char)( ( total_len ) );

#if defined(MBEDTLS_SSL_CLI_C)
empty_cert:
#endif /* MBEDTLS_SSL_CLI_C */

    *olen = i;

    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */



/* Update the state after handling the outgoing certificate message. */
static int ssl_write_certificate_postprocess( mbedtls_ssl_context* ssl )
{
#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
            mbedtls_ack_clear_all( ssl, MBEDTLS_SSL_ACK_RECORDS_RECEIVED );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
            mbedtls_ack_add_record( ssl, MBEDTLS_SSL_HS_CERTIFICATE, MBEDTLS_SSL_ACK_RECORDS_SENT );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY );

        return( 0 );
    }
    else
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
        {
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_VERIFY );
            return( 0 );
        }
#endif /* MBEDTLS_SSL_SRV_C */

    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}



/*
 *
 * STATE HANDLING: Incoming Certificate
 *
 */

/*
 * Overview
 */

/* Main state-handling entry point; orchestrates the other functions. */
int mbedtls_ssl_read_certificate_process( mbedtls_ssl_context* ssl );

/* Coordination: Check if a certificate is expected.
 * Returns a negative error code on failure, and otherwise
 * SSL_CERTIFICATE_EXPECTED or
 * SSL_CERTIFICATE_SKIP
 * indicating whether a Certificate message is expected or not.
 */
#define SSL_CERTIFICATE_EXPECTED   0
#define SSL_CERTIFICATE_SKIP       1
static int ssl_read_certificate_coordinate( mbedtls_ssl_context* ssl );

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_read_certificate_fetch( mbedtls_ssl_context* ssl,
                                       unsigned char** buf,
                                       size_t* buflen );
#endif /* MBEDTLS_SSL_USE_MPS */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
/* Parse certificate chain send by the peer. */
static int ssl_read_certificate_parse( mbedtls_ssl_context* ssl,
                                       unsigned char const* buf,
                                       size_t buflen );
/* Validate certificate chain sent by the peer. */
static int ssl_read_certificate_validate( mbedtls_ssl_context* ssl );

#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

/* Update the state after handling the incoming certificate message. */
static int ssl_read_certificate_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */

int mbedtls_ssl_read_certificate_process( mbedtls_ssl_context* ssl )
{
    int ret;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

    /* Coordination:
     * Check if we expect a certificate, and if yes,
     * check if a non-empty certificate has been sent. */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_read_certificate_coordinate( ssl ) );
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    if( ret == SSL_CERTIFICATE_EXPECTED )
    {
        unsigned char *buf;
        size_t buflen;

#if defined(MBEDTLS_SSL_USE_MPS)

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_fetch_full_hs_msg( ssl,
                                          MBEDTLS_SSL_HS_CERTIFICATE,
                                          &buf, &buflen ) );

        mbedtls_ssl_add_hs_msg_to_checksum(
            ssl, MBEDTLS_SSL_HS_CERTIFICATE, buf, buflen );

        /* Parse the certificate chain sent by the peer. */
        MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_parse( ssl, buf, buflen ) );
        /* Validate the certificate chain and set the verification results. */
        MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_validate( ssl ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );

#else /* MBEDTLS_SSL_USE_MPS */

        MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_fetch( ssl, &buf, &buflen ) );

        /* Parse the certificate chain sent by the peer. */
        MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_parse( ssl, buf, buflen ) );
        /* Validate the certificate chain and set the verification results. */
        MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_validate( ssl ) );

#endif /* MBEDTLS_SSL_USE_MPS */

    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
    if( ret == SSL_CERTIFICATE_SKIP )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Update state */
    MBEDTLS_SSL_PROC_CHK( ssl_read_certificate_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate" ) );
    return( ret );
}

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_read_certificate_fetch( mbedtls_ssl_context *ssl,
                                       unsigned char **buf,
                                       size_t *buflen )
{
    int ret;

    /* Reading step */
    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        /* mbedtls_ssl_read_record may have sent an alert already. We
           let it decide whether to alert. */
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ||
        ssl->in_msg[0] != MBEDTLS_SSL_HS_CERTIFICATE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

    *buf    = ssl->in_msg   + 4;
    *buflen = ssl->in_hslen - 4;

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_read_certificate_coordinate( mbedtls_ssl_context* ssl )
{
#if defined(MBEDTLS_SSL_SRV_C)
    int authmode = ssl->conf->authmode;
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to handshake keys for inbound traffic" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
        {
            int ret;
            ret = mbedtls_mps_set_incoming_keys( &ssl->mps.l4,
                                                 ssl->epoch_handshake );
            if( ret != 0 )
                return( ret );
        }
#else
        mbedtls_ssl_set_inbound_transform( ssl, ssl->transform_handshake );
#endif /* MBEDTLS_SSL_USE_MPS */
    }
#endif /* MBEDTLS_SSL_SRV_C */

    if( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
        ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
    {
        return( SSL_CERTIFICATE_SKIP );
    }

#if !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    ( ( void )authmode );
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        /* If SNI was used, overwrite authentication mode
         * from the configuration. */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        if( ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET )
            authmode = ssl->handshake->sni_authmode;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

        if( authmode == MBEDTLS_SSL_VERIFY_NONE )
        {
            /* NOTE: Is it intentional that we set verify_result
             * to SKIP_VERIFY on server-side only? */
            ssl->session_negotiate->verify_result =
                MBEDTLS_X509_BADCERT_SKIP_VERIFY;
            return( SSL_CERTIFICATE_SKIP );
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

    return( SSL_CERTIFICATE_EXPECTED );
#endif /* !MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
}

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
/* Write certificate message based on the configured certificate */
static int ssl_read_certificate_parse( mbedtls_ssl_context* ssl,
                                       unsigned char const* buf,
                                       size_t buflen )
{
    int ret;
    size_t i, n, certificate_request_context_len;

#if defined(MBEDTLS_SSL_SRV_C)
    int authmode = ssl->conf->authmode;

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        /* read certificate request context length */
        certificate_request_context_len = (size_t) buf[0];

        /* verify message length */
        if( buflen < 3 + certificate_request_context_len + 1 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                  MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        /* check whether we got an empty certificate message */
        if( memcmp( buf + 1 + certificate_request_context_len , "\0\0\0", 3 ) == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "client has no certificate - empty certificate message received" ) );

            ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_MISSING;
            if( authmode == MBEDTLS_SSL_VERIFY_OPTIONAL )
                return( 0 );
            else
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "client certificate required" ) );
                SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_REQUIRED,
                                      MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE );
                return( MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE );
            }
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

    if( buflen < 3 + 3 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    i = 0;

    /* length information of certificate_request_context */
    certificate_request_context_len = buf[i + 1];

    /* skip certificate_request_context */
    i += certificate_request_context_len + 1;

    n = ( buf[i + 1] << 8 ) | buf[i + 2];

    if( buf[i] != 0 ||
        buflen != ( n + 3 + certificate_request_context_len + 1 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    /* In case we tried to reuse a session but it failed */
    if( ssl->session_negotiate->peer_cert != NULL )
    {
        mbedtls_x509_crt_free( ssl->session_negotiate->peer_cert );
        mbedtls_free( ssl->session_negotiate->peer_cert );
    }

    if( ( ssl->session_negotiate->peer_cert = mbedtls_calloc( 1,
                                                              sizeof( mbedtls_x509_crt ) ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc( %d bytes ) failed",
                                    sizeof( mbedtls_x509_crt ) ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                              MBEDTLS_ERR_SSL_ALLOC_FAILED );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    mbedtls_x509_crt_init( ssl->session_negotiate->peer_cert );

    i += 3;

    while ( i < buflen )
    {
        if( buf[i] != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                  MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        n = ( ( unsigned int )buf[i + 1] << 8 )
            | ( unsigned int )buf[i + 2];
        i += 3;

        if( n < 128 || i + n > buflen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                  MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        ret = mbedtls_x509_crt_parse_der( ssl->session_negotiate->peer_cert,
                                          buf + i, n );

        switch ( ret )
        {
            case 0: /*ok*/
            case MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND:
                /* Ignore certificate with an unknown algorithm: maybe a
                   prior certificate was already trusted. */
                break;

            case MBEDTLS_ERR_X509_ALLOC_FAILED:
                SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                      MBEDTLS_ERR_X509_ALLOC_FAILED );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );

            case MBEDTLS_ERR_X509_UNKNOWN_VERSION:
                SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                                      MBEDTLS_ERR_X509_UNKNOWN_VERSION );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );

            default:
                SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_BAD_CERT,
                                      ret );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );
        }

        i += n;

        /* length information of certificate extensions */
        n = ( buf[i] << 8 ) | buf[i + 1];

        /* we ignore the certificate extension right now */
        i += 2 + n;
    }

    MBEDTLS_SSL_DEBUG_CRT( 3, "peer certificate", ssl->session_negotiate->peer_cert );

    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_read_certificate_validate( mbedtls_ssl_context* ssl )
{
    int ret = 0;
    int authmode = ssl->conf->authmode;
    mbedtls_x509_crt* ca_chain;
    mbedtls_x509_crl* ca_crl;

    /* If SNI was used, overwrite authentication mode
     * from the configuration. */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET )
        authmode = ssl->handshake->sni_authmode;
#endif

    /*
     * If the client hasn't sent a certificate ( i.e. it sent
     * an empty certificate chain ), this is reflected in the peer CRT
     * structure being unset.
     * Check for that and handle it depending on the
     * server's authentication mode.
     */
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
        ssl->session_negotiate->peer_cert == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "client has no certificate" ) );

        /* The client was asked for a certificate but didn't send
           one. The client should know what's going on, so we
           don't send an alert. */

        /* Note that for authmode == VERIFY_NONE we don't end up in this
         * routine in the first place, because ssl_read_certificate_coordinate
         * will return CERTIFICATE_SKIP. */
        ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_MISSING;
        if( authmode == MBEDTLS_SSL_VERIFY_OPTIONAL )
            return( 0 );
        else
            return( MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE );
    }
#endif /* MBEDTLS_SSL_SRV_C */


    if( authmode == MBEDTLS_SSL_VERIFY_NONE )
    {
        /* NOTE: This happens on client-side only, with the
         * server-side case of VERIFY_NONE being handled earlier
         * and leading to `ssl->verify_result` being set to
         * MBEDTLS_X509_BADCERT_SKIP_VERIFY --
         * is this difference intentional? */
        return( 0 );
    }

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_ca_chain != NULL )
    {
        ca_chain = ssl->handshake->sni_ca_chain;
        ca_crl = ssl->handshake->sni_ca_crl;
    }
    else
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
    {
        ca_chain = ssl->conf->ca_chain;
        ca_crl = ssl->conf->ca_crl;
    }

    /*
     * Main check: verify certificate
     */
    ret = mbedtls_x509_crt_verify_with_profile(
        ssl->session_negotiate->peer_cert,
        ca_chain, ca_crl,
        ssl->conf->cert_profile,
        ssl->hostname,
        &ssl->session_negotiate->verify_result,
        ssl->conf->f_vrfy, ssl->conf->p_vrfy );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "x509_verify_cert", ret );
    }

    /*
     * Secondary checks: always done, but change 'ret' only if it was 0
     */

#if defined(MBEDTLS_ECP_C)
    {
        const mbedtls_pk_context* pk = &ssl->session_negotiate->peer_cert->pk;

        /* If certificate uses an EC key, make sure the curve is OK */
        if( mbedtls_pk_can_do( pk, MBEDTLS_PK_ECKEY ) &&
            mbedtls_ssl_check_curve( ssl, mbedtls_pk_ec( *pk )->grp.id ) != 0 )
        {
            ssl->session_negotiate->verify_result |= MBEDTLS_X509_BADCERT_BAD_KEY;

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate ( EC key curve )" ) );
            if( ret == 0 )
                ret = MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE;
        }
    }
#endif /* MBEDTLS_ECP_C */

    if( mbedtls_ssl_check_cert_usage( ssl->session_negotiate->peer_cert,
                                      ssl->session_negotiate->key_exchange,/*		ciphersuite_info, */
                                      !ssl->conf->endpoint,
                                      &ssl->session_negotiate->verify_result ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate ( usage extensions )" ) );
        if( ret == 0 )
            ret = MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE;
    }

    /* mbedtls_x509_crt_verify_with_profile is supposed to report a
     * verification failure through MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
     * with details encoded in the verification flags. All other kinds
     * of error codes, including those from the user provided f_vrfy
     * functions, are treated as fatal and lead to a failure of
     * ssl_parse_certificate even if verification was optional. */
    if( authmode == MBEDTLS_SSL_VERIFY_OPTIONAL &&
        ( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ||
          ret == MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE ) )
    {
        ret = 0;
    }

    if( ca_chain == NULL && authmode == MBEDTLS_SSL_VERIFY_REQUIRED )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no CA chain" ) );
        ret = MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED;
    }

    if( ret != 0 )
    {
        /* The certificate may have been rejected for several reasons.
           Pick one and send the corresponding alert. Which alert to send
           may be a subject of debate in some cases. */
        if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_OTHER )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED, ret );
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_CN_MISMATCH )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_BAD_CERT, ret );
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_KEY_USAGE )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT, ret );
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_EXT_KEY_USAGE )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT, ret );
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_NS_CERT_TYPE )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT, ret );
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_BAD_PK )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT, ret );
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_BAD_KEY )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT, ret );
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_EXPIRED )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED, ret );
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_REVOKED )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED, ret );
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_NOT_TRUSTED )
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA, ret );
        else
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN, ret );
    }

#if defined(MBEDTLS_DEBUG_C)
    if( ssl->session_negotiate->verify_result != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "! Certificate verification flags %x",
                                    ssl->session_negotiate->verify_result ) );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Certificate verification flags clear" ) );
    }
#endif /* MBEDTLS_DEBUG_C */

    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

static int ssl_read_certificate_postprocess( mbedtls_ssl_context* ssl )
{

#if	defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        mbedtls_ack_add_record( ssl, MBEDTLS_SSL_HS_CERTIFICATE, MBEDTLS_SSL_ACK_RECORDS_RECEIVED );
#endif /* MBEDTLS_SSL_PROTO_DTLS */


#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY );

        /*
          if( ret != 0 ) {
          MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_parse_certificate", ret );
          switch ( ret ) {
          case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE:
          mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_BAD_CERT );
          break;
          case MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
          mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
          break;
          case MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE:
          mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_CERT_REQUIRED );
          break;
          case MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED:
          mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA );
          break;
          default:
          mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT );
          }
          return ( ret );
          }
	*/
    }
    else
#endif /* MBEDTLS_SSL_SRV_C */
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_VERIFY );
    }
    return( 0 );
}

/* Generate resumption_master_secret for use with the ticket exchange. */

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
int mbedtls_ssl_generate_resumption_master_secret( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    const mbedtls_md_info_t *md_info;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];

#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_context sha256;
#endif

#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_context sha512;
#endif

    suite_info = ssl->handshake->ciphersuite_info;

    md_info = mbedtls_md_info_from_type( suite_info->mac );
    if( md_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found",
                                    ssl->handshake->ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

#if defined(MBEDTLS_SHA256_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
        mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

        if( ( ret = mbedtls_sha256_finish_ret( &sha256, hash ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
        mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

        if( ( ret = mbedtls_sha512_finish_ret( &sha512, hash ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA512_C */
    {
        /* Should never happen */
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * Compute resumption_master_secret with
     *   mbedtls_ssl_tls1_3_derive_secret( Master Secret,
     *                                     "res master",
     *                                     ClientHello...client Finished )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_master ),
                         hash, mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->session_negotiate->resumption_master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );

    if( ret != 0 )
        goto exit;

    MBEDTLS_SSL_DEBUG_BUF( 5, "resumption_master_secret",
                           ssl->session_negotiate->resumption_master_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );


exit:
#if defined(MBEDTLS_SHA256_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 32 )
    {
        mbedtls_sha256_free( &sha256 );
    }
    else
#endif
#if defined(MBEDTLS_SHA512_C)
    if( mbedtls_hash_size_for_ciphersuite( suite_info ) == 48 )
    {
        mbedtls_sha512_free( &sha512 );
    }
    else
#endif
    {
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( ret );
}
#else
int mbedtls_ssl_generate_resumption_master_secret( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( 0 );
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

/* Generate application traffic keys since any records following a 1-RTT Finished message
 * MUST be encrypted under the application traffic key.
 */
int mbedtls_ssl_generate_application_traffic_keys(
                                        mbedtls_ssl_context *ssl,
                                        mbedtls_ssl_key_set *traffic_keys )
{
    int ret;
    const mbedtls_md_info_t *md_info;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    const mbedtls_cipher_info_t *cipher_info;
    size_t keylen, ivlen;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> derive application traffic keys" ) );

    cipher_info = mbedtls_cipher_info_from_type(
                              ssl->handshake->ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found",
                               ssl->handshake->ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    md_info = mbedtls_md_info_from_type( ssl->handshake->ciphersuite_info->mac );
    if( md_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found",
                               ssl->handshake->ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session_negotiate->ciphersuite );
    if( suite_info == NULL )
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );

    ivlen = cipher_info->iv_size;
    keylen = cipher_info->key_bitlen / 8;

    MBEDTLS_SSL_DEBUG_BUF( 4, "Transcript hash (including Server.Finished):",
                              ssl->handshake->server_finished_digest,
                              mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /* Generate client_application_traffic_secret_0
     *
     * Master Secret
     * |
     * +-----> Derive-Secret( ., "c ap traffic",
     * |                     ClientHello...server Finished )
     * |                     = client_application_traffic_secret_0
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_ap_traffic ),
                         ssl->handshake->server_finished_digest,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->client_traffic_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "Client application traffic secret",
                           ssl->handshake->client_traffic_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Export client application traffic secret 0
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET_0,
                ssl->handshake->client_traffic_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    /* Generate server_application_traffic_secret_0
     *
     * Master Secret
     * |
     * +---------> Derive-Secret( ., "s ap traffic",
     * |                         ClientHello...Server Finished )
     * |                         = server_application_traffic_secret_0
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md_info ),
                         ssl->handshake->master_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_ap_traffic ),
                         ssl->handshake->server_finished_digest,
                         mbedtls_hash_size_for_ciphersuite( suite_info ),
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->server_traffic_secret,
                         mbedtls_hash_size_for_ciphersuite( suite_info ) );
    if( ret != 0 )
        return( ret );

    MBEDTLS_SSL_DEBUG_BUF( 4, "Server application traffic secret",
                           ssl->handshake->server_traffic_secret,
                           mbedtls_hash_size_for_ciphersuite( suite_info ) );

    /*
     * Export server application traffic secret 0
     */
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_secret != NULL )
    {
        ssl->conf->f_export_secret( ssl->conf->p_export_secret,
                ssl->handshake->randbytes,
                MBEDTLS_SSL_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET_0,
                ssl->handshake->server_traffic_secret,
                (size_t) mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

    /* Generate application traffic keys since any records following a
     * 1-RTT Finished message MUST be encrypted under the application
     * traffic key. */

    if( ( ret = mbedtls_ssl_tls1_3_make_traffic_keys( mbedtls_md_get_type( md_info ),
                              ssl->handshake->client_traffic_secret,
                              ssl->handshake->server_traffic_secret,
                              mbedtls_hash_size_for_ciphersuite( suite_info ),
                              keylen, ivlen, traffic_keys ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_make_traffic_keys failed", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "client application_write_key:",
                              traffic_keys->client_write_key, keylen );
    MBEDTLS_SSL_DEBUG_BUF( 4, "server application write key",
                              traffic_keys->server_write_key, keylen );
    MBEDTLS_SSL_DEBUG_BUF( 4, "client application write IV",
                              traffic_keys->client_write_iv, ivlen );
    MBEDTLS_SSL_DEBUG_BUF( 4, "server application write IV",
                              traffic_keys->server_write_iv, ivlen );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= derive application traffic keys" ) );

    return( 0 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
static void ssl_setup_seq_protection_keys( mbedtls_ssl_context *ssl,
                                           mbedtls_ssl_transform *transform )
{
    unsigned char temp[ MBEDTLS_MAX_KEY_LEN ];

    if( ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM ||
        ssl->conf->endpoint  != MBEDTLS_SSL_IS_SERVER)
    {
        return;
    }

    /* Swap the keys for server */
    memcpy( temp, transform->traffic_keys.client_sn_key,
            sizeof( transform->traffic_keys.client_sn_key ) );
    memcpy( transform->traffic_keys.client_sn_key,
            transform->traffic_keys.server_sn_key,
            sizeof( transform->transform.client_sn_key ) );
    memcpy( transform->traffic_keys.client_sn_key,
            temp, sizeof( temp ) );
}
#endif /* MBEDTLS_SSL_PROTO_DTLS */

int mbedtls_ssl_tls13_populate_transform( mbedtls_ssl_transform *transform,
                                          int endpoint,
                                          int ciphersuite,
                                          mbedtls_ssl_key_set const *traffic_keys,
                                          mbedtls_ssl_context *ssl /* DEBUG ONLY */ )
{
    int ret;
    mbedtls_cipher_info_t const *cipher_info;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    unsigned char const *key_enc;
    unsigned char const *iv_enc;
    unsigned char const *key_dec;
    unsigned char const *iv_dec;

#if !defined(MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for those cases */
    (void) ssl;
#endif

    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( ciphersuite );

    cipher_info = mbedtls_cipher_info_from_type( ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * Setup cipher contexts in target transform
     */

    if( ( ret = mbedtls_cipher_setup( &transform->cipher_ctx_enc,
                                      cipher_info ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup", ret );
        return( ret );
    }

    if( ( ret = mbedtls_cipher_setup( &transform->cipher_ctx_dec,
                                      cipher_info ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_SRV_C)
    if( endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        key_enc = traffic_keys->server_write_key;
        key_dec = traffic_keys->client_write_key;
        iv_enc = traffic_keys->server_write_iv;
        iv_dec = traffic_keys->client_write_iv;
    }
    else
#endif /* MBEDTLS_SSL_SRV_C */
#if defined(MBEDTLS_SSL_CLI_C)
    if( endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        key_enc = traffic_keys->client_write_key;
        key_dec = traffic_keys->server_write_key;
        iv_enc = traffic_keys->client_write_iv;
        iv_dec = traffic_keys->server_write_iv;
    }
    else
#endif /* MBEDTLS_SSL_CLI_C */
    {
        /* should not happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    memcpy( transform->iv_enc, iv_enc, traffic_keys->iv_len );
    memcpy( transform->iv_dec, iv_dec, traffic_keys->iv_len );

    if( ( ret = mbedtls_cipher_setkey( &transform->cipher_ctx_enc,
                                       key_enc, cipher_info->key_bitlen,
                                       MBEDTLS_ENCRYPT ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setkey", ret );
        return( ret );
    }

    if( ( ret = mbedtls_cipher_setkey( &transform->cipher_ctx_dec,
                                       key_dec, cipher_info->key_bitlen,
                                       MBEDTLS_DECRYPT ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setkey", ret );
        return( ret );
    }

    /*
     * Setup other fields in SSL transform
     */

    if( ( ciphersuite_info->flags & MBEDTLS_CIPHERSUITE_SHORT_TAG ) != 0 )
        transform->taglen  = 8;
    else
        transform->taglen  = 16;

    transform->ivlen       = traffic_keys->iv_len;
    transform->maclen      = 0;
    transform->fixed_ivlen = transform->ivlen;
    transform->minlen      = transform->taglen + 1;
    transform->minor_ver   = MBEDTLS_SSL_MINOR_VERSION_4;

    return( 0 );
}

#if defined(MBEDTLS_ZERO_RTT)
/* Early Data Key Derivation for TLS 1.3 */
int mbedtls_ssl_generate_early_data_keys( mbedtls_ssl_context *ssl,
                                          mbedtls_ssl_key_set *traffic_keys )
{
    int ret;
    int hash_length;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md;
    unsigned char padbuf[MBEDTLS_MD_MAX_SIZE];
    size_t keylen, ivlen;

#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_context sha256;
#endif

#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_context sha512;
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_generate_early_data_keys" ) );

    ciphersuite_info = ssl->handshake->ciphersuite_info;
    cipher_info = mbedtls_cipher_info_from_type( ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found",
                                    ssl->handshake->ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    md = mbedtls_md_info_from_type( ssl->handshake->ciphersuite_info->mac );
    if( md == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found",
                                    ssl->handshake->ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    hash_length = mbedtls_hash_size_for_ciphersuite( ciphersuite_info );
    if( hash_length == -1 )
    {
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl_dtls_replay_reset( ssl );
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_SSL_DTLS_ANTI_REPLAY */

    if( ciphersuite_info->mac == MBEDTLS_MD_SHA256 )
    {
#if defined(MBEDTLS_SHA256_C)
        mbedtls_sha256_init( &sha256 );

        if( ( ret = mbedtls_sha256_starts_ret( &sha256, 0 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_starts_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha256 state",
                               (unsigned char *) sha256.state,
                               sizeof( sha256.state ) );

        mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

        if( ( ret = mbedtls_sha256_finish_ret( &sha256, padbuf ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_finish_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "handshake hash", padbuf, 32 );
#else
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif
    }
    else if( ciphersuite_info->mac == MBEDTLS_MD_SHA384 )
    {
#if defined(MBEDTLS_SHA512_C)
        mbedtls_sha512_init( &sha512 );

        if( ( ret = mbedtls_sha512_starts_ret( &sha512, 1 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_starts_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha384 state",
                               (unsigned char *)sha512.state, 48 );

        mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

        if( ( ret = mbedtls_sha512_finish_ret( &sha512, padbuf ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "handshake hash", padbuf, 48 );
#else
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif
    }
    else if( ciphersuite_info->mac == MBEDTLS_MD_SHA512 )
    {
#if defined(MBEDTLS_SHA512_C)
        mbedtls_sha512_init( &sha512 );

        if( ( ret = mbedtls_sha512_starts_ret( &sha512, 0 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_starts_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "finished sha512state", ( unsigned char * )sha512.state, 64 );

        mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

        if( ( ret = mbedtls_sha512_finish_ret( &sha512, padbuf ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
            goto exit;
        }
        MBEDTLS_SSL_DEBUG_BUF( 4, "handshake hash for psk binder", padbuf, 64 );
    }
    else
    {
#else
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_ssl_tls1_3_derive_master_secret: Unknow hash function." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif
    }

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
     *            |                     = binder_key
     *            |
     *            +-----> Derive-Secret(., "c e traffic", ClientHello)
     *            |                     = client_early_traffic_secret
     *            |
     *            +-----> Derive-Secret(., "e exp master", ClientHello)
     *            |                     = early_exporter_master_secret
     *            v
     */

    /* Create client_early_traffic_secret */
    ret = mbedtls_ssl_tls1_3_derive_secret( mbedtls_md_get_type( md ),
                         ssl->handshake->early_secret, hash_length,
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_e_traffic ),
                         padbuf, hash_length, MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         ssl->handshake->client_early_traffic_secret, hash_length );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        goto exit;
    }


    MBEDTLS_SSL_DEBUG_BUF( 4, "client_early_traffic_secret",
                           ssl->handshake->client_early_traffic_secret,
                           hash_length );

    MBEDTLS_SSL_DEBUG_MSG( 4, ( "mbedtls_ssl_tls1_3_derive_secret with 'c e traffic'" ) );


    keylen = cipher_info->key_bitlen / 8;
    ivlen = cipher_info->iv_size;

    if( ( ret = mbedtls_ssl_tls1_3_make_traffic_keys( mbedtls_md_get_type( md ),
                                 ssl->handshake->client_early_traffic_secret,
                                 ssl->handshake->client_early_traffic_secret,
                                 mbedtls_hash_size_for_ciphersuite( ciphersuite_info ),
                                 keylen, ivlen, traffic_keys ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_make_traffic_keys failed", ret );
        goto exit;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_generate_early_data_keys" ) );

exit:
#if defined(MBEDTLS_SHA256_C)
    if( ciphersuite_info->mac == MBEDTLS_MD_SHA256 )
    {
        mbedtls_sha256_free( &sha256 );
    }
    else
#endif
#if defined(MBEDTLS_SHA512_C)
    if( ciphersuite_info->mac == MBEDTLS_MD_SHA384 ||
        ciphersuite_info->mac == MBEDTLS_MD_SHA512 )
    {
        mbedtls_sha512_free( &sha512 );
    }
    else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_ssl_tls1_3_derive_master_secret: Unknow hash function." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( ret );
}
#endif /* MBEDTLS_ZERO_RTT */

/* Key Derivation for TLS 1.3
 *
 * Three tasks:
 *   - Switch transform for inbound data
 *   - Generate master key
 *   - Generate handshake traffic keys
 */
int mbedtls_ssl_handshake_key_derivation( mbedtls_ssl_context *ssl, mbedtls_ssl_key_set *traffic_keys )
{
    int ret;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_ssl_handshake_key_derivation" ) );

    /* Creating the Master Secret */
    if( ( ret = mbedtls_ssl_tls1_3_derive_master_secret( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_master_secret", ret );
        return( ret );
    }

    /* Creating the handshake traffic keys */
    if( ( ret = mbedtls_ssl_generate_handshake_traffic_keys( ssl, traffic_keys ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_generate_handshake_traffic_keys", ret );
        return( ret );
    }

#if !defined(MBEDTLS_SSL_USE_MPS)
    /*
     * Set the in_msg pointer to the correct location based on IV length
     * For TLS 1.3 the record layer header has changed and hence we need to accomodate for it.
     */
    ssl->in_msg = ssl->in_iv;
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_ssl_handshake_key_derivation" ) );
    return( 0 );
}



void mbedtls_ssl_handshake_wrapup( mbedtls_ssl_context *ssl )
{

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> handshake wrapup" ) );


    /*
     * Free the previous session and switch in the current one
     */
    if( ssl->session )
    {

        mbedtls_ssl_session_free( ssl->session );
        mbedtls_free( ssl->session );
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;

    /* With DTLS 1.3 we keep the handshake and transform structures alive. */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "skip freeing handshake and transform" ) );
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= handshake wrapup" ) );
}

/*
 *
 * STATE HANDLING: Outgoing Finished
 *
 */

/*
 * Overview
 */

/* Main entry point: orchestrates the other functions */
int mbedtls_ssl_finished_out_process( mbedtls_ssl_context* ssl );

static int ssl_finished_out_prepare( mbedtls_ssl_context* ssl );
static int ssl_finished_out_write( mbedtls_ssl_context* ssl,
                                   unsigned char* buf,
                                   size_t buflen,
                                   size_t* olen );
static int ssl_finished_out_postprocess( mbedtls_ssl_context* ssl );


/*
 * Implementation
 */


int mbedtls_ssl_finished_out_process( mbedtls_ssl_context* ssl )
{
    int ret;
#if defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_mps_handshake_out msg;
    unsigned char *buf;
    mbedtls_mps_size_t buf_len, msg_len;
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write finished" ) );

    if( !ssl->handshake->state_local.finished_out.preparation_done )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_finished_out_prepare( ssl ) );
        ssl->handshake->state_local.finished_out.preparation_done = 1;
    }

#if defined(MBEDTLS_SSL_USE_MPS)

    msg.type   = MBEDTLS_SSL_HS_FINISHED;
    msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                       &msg, NULL, NULL ) );

    /* Request write-buffer */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get_ext( msg.handle, MBEDTLS_MPS_SIZE_MAX,
                                                  &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_finished_out_write(
                              ssl, buf, buf_len, &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_FINISHED,
                                        buf, msg_len );

    /* Commit message */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial_ext( msg.handle,
                                                             buf_len - msg_len ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );
    MBEDTLS_SSL_PROC_CHK( ssl_finished_out_postprocess( ssl ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

#else /* MBEDTLS_SSL_USE_MPS */

    /* Make sure we can write a new message. */
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

    MBEDTLS_SSL_PROC_CHK( ssl_finished_out_write( ssl, ssl->out_msg,
                                                  MBEDTLS_SSL_MAX_CONTENT_LEN,
                                                  &ssl->out_msglen ) );
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_FINISHED;

    /* TODO: This doesn't work if mbedtls_ssl_write_handshake_msg() fails
     * because the underlying transport isn't ready. */
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg( ssl ) );
    MBEDTLS_SSL_PROC_CHK( ssl_finished_out_postprocess( ssl ) );


#endif /* MBEDTLS_SSL_USE_MPS */

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write finished" ) );
    return( ret );
}

static int ssl_finished_out_prepare( mbedtls_ssl_context* ssl )
{
    int ret;

    /*
     * Set the out_msg pointer to the correct location based on IV length
     */
#if !defined(MBEDTLS_SSL_USE_MPS)
#if !defined(MBEDTLS_SSL_PROTO_DTLS)
    ssl->out_msg = ssl->out_iv;
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#endif /* !MBEDTLS_SSL_USE_MPS */

    /* Compute transcript of handshake up to now. */
    ret = ssl->handshake->calc_finished( ssl,
                                   ssl->handshake->state_local.finished_out.digest,
                                   ssl->conf->endpoint );

    if( ret != 0 )
    {
         MBEDTLS_SSL_DEBUG_RET( 1, "calc_finished failed", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_activate != NULL )
    {
        if( ( ret = mbedtls_ssl_hw_record_activate( ssl, MBEDTLS_SSL_CHANNEL_OUTBOUND ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_activate", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        mbedtls_ssl_send_flight_completed( ssl );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    return( 0 );
}

static int ssl_finished_out_postprocess( mbedtls_ssl_context* ssl )
{
    int ret = 0;

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
            mbedtls_ack_add_record( ssl, MBEDTLS_SSL_HS_FINISHED, MBEDTLS_SSL_ACK_RECORDS_SENT );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

        /* Compute resumption_master_secret */
        ret = mbedtls_ssl_generate_resumption_master_secret( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_generate_resumption_master_secret ", ret );
            return ( ret );
        }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        traffic_keys.epoch = 3;
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        /* epoch value ( 3 ) is used for payloads protected using keys
         * derived from the initial traffic_secret_0.
         */
        ssl->in_epoch = 3;
        ssl->out_epoch = 3;
#endif /* MBEDTLS_SSL_PROTO_DTLS */

        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_FINISH_ACK );
        else
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_FLUSH_BUFFERS );

    }
    else
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        size_t transcript_len;

        ret = mbedtls_ssl_get_handshake_transcript( ssl,
                              ssl->handshake->ciphersuite_info->mac,
                              ssl->handshake->server_finished_digest,
                              sizeof(ssl->handshake->server_finished_digest),
                              &transcript_len );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_get_handshake_transcript",
                                   ret );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_BUF( 3, "Transcript hash (incl. Server.Finished):",
                               ssl->handshake->server_finished_digest,
                               transcript_len );


        mbedtls_ssl_key_set traffic_keys;
        ret = mbedtls_ssl_generate_application_traffic_keys( ssl,
                                                             &traffic_keys );

        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1,
                    "mbedtls_ssl_generate_application_traffic_keys", ret );
            return( ret );
        }

        ret = mbedtls_ssl_tls13_populate_transform( ssl->transform_application,
                                               ssl->conf->endpoint,
                                               ssl->session_negotiate->ciphersuite,
                                               &traffic_keys,
                                               ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
            return( ret );
        }

#if defined(MBEDTLS_SSL_USE_MPS)
        {
            mbedtls_ssl_transform *transform_application =
                mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
            if( transform_application == NULL )
                return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

            ret = mbedtls_ssl_tls13_populate_transform(
                         transform_application,
                         ssl->conf->endpoint,
                         ssl->session_negotiate->ciphersuite,
                         &traffic_keys,
                         ssl );

            /* Register transform with MPS. */
            ret = mbedtls_mps_add_key_material( &ssl->mps.l4,
                                                transform_application,
                                                &ssl->epoch_application );
            if( ret != 0 )
                return( ret );
        }
#endif /* MBEDTLS_SSL_USE_MPS */

        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_EARLY_APP_DATA );
    }
    else
#endif /* MBEDTLS_SSL_SRV_C */
    {
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( 0 );
}

static int ssl_finished_out_write( mbedtls_ssl_context* ssl,
                                   unsigned char* buf,
                                   size_t buflen,
                                   size_t* olen )
{
    unsigned char *p;
    size_t finished_len;

#if defined(MBEDTLS_SSL_USE_MPS)

    p = buf;
    finished_len = ssl->handshake->state_local.finished_out.digest_len;

#else /* MBEDTLS_SSL_USE_MPS */

    size_t const tls_hs_hdr_len = 4;
    finished_len = tls_hs_hdr_len +
        ssl->handshake->state_local.finished_out.digest_len;
    p = buf + 4;

#endif /* MBEDTLS_SSL_USE_MPS */

    /* Note: Even if DTLS is used, the current message writing functions
     * write TLS headers, and it is only at sending time that the actual
     * DTLS header is generated. That's why we unconditionally shift by
     * 4 bytes here as opposed to mbedtls_ssl_hs_hdr_len( ssl ). */

    if( buflen < finished_len )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    memcpy( p,
            ssl->handshake->state_local.finished_out.digest,
            ssl->handshake->state_local.finished_out.digest_len );
    p += ssl->handshake->state_local.finished_out.digest_len;

    *olen = (size_t)( p - buf );

    return( 0 );
}

/*
 *
 * STATE HANDLING: Incoming Finished
 *
 */

/*
 * Overview
 */

/* Main entry point: orchestrates the other functions */
int mbedtls_ssl_finished_in_process( mbedtls_ssl_context* ssl );

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_read_finished_fetch( mbedtls_ssl_context* ssl,
                                    unsigned char** buf,
                                    size_t* buflen );
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_finished_in_preprocess( mbedtls_ssl_context* ssl );
static int ssl_finished_in_postprocess( mbedtls_ssl_context* ssl );
static int ssl_finished_in_parse( mbedtls_ssl_context* ssl,
                                  const unsigned char* buf,
                                  size_t buflen );

/*
 * Implementation
 */

int mbedtls_ssl_finished_in_process( mbedtls_ssl_context* ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buflen;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse finished" ) );

    /* Preprocessing step: Compute handshake digest */
    MBEDTLS_SSL_PROC_CHK( ssl_finished_in_preprocess( ssl ) );

#if defined(MBEDTLS_SSL_USE_MPS)

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_fetch_full_hs_msg( ssl,
                                              MBEDTLS_SSL_HS_FINISHED,
                                              &buf, &buflen ) );

    mbedtls_ssl_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_FINISHED, buf, buflen );

    /* Process the message contents */
    MBEDTLS_SSL_PROC_CHK( ssl_finished_in_parse( ssl, buf, buflen ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );

#else /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_PROC_CHK( ssl_read_finished_fetch( ssl, &buf, &buflen ) );
    MBEDTLS_SSL_PROC_CHK( ssl_finished_in_parse( ssl, buf, buflen ) );

#endif /* MBEDTLS_SSL_USE_MPS */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        mbedtls_ssl_recv_flight_completed( ssl );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    /* Postprocessing step: Update state machine */
    MBEDTLS_SSL_PROC_CHK( ssl_finished_in_postprocess( ssl ) );

cleanup:

    /* In the MPS one would close the read-port here to
     * ensure there's no overlap of reading and writing. */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse finished" ) );
    return( ret );
}

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_read_finished_fetch( mbedtls_ssl_context *ssl,
                                    unsigned char **buf,
                                    size_t *buflen )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE  ||
        ssl->in_msg[0]  != MBEDTLS_SSL_HS_FINISHED    )
    {
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

    *buf    = ssl->in_msg   + 4;
    *buflen = ssl->in_hslen - 4;

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_finished_in_preprocess( mbedtls_ssl_context* ssl )
{
    unsigned int hash_len;
    const mbedtls_ssl_ciphersuite_t* suite_info;

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session_negotiate->ciphersuite );

    if( suite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_ssl_ciphersuite_from_id in ssl_finished_in_preprocess failed" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    hash_len = mbedtls_hash_size_for_ciphersuite( suite_info );
    if( hash_len == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    ssl->handshake->state_local.finished_in.digest_len = hash_len;

    ssl->handshake->calc_finished( ssl,
                                   ssl->handshake->state_local.finished_in.digest,
                                   ssl->conf->endpoint ^ 1 );

    return( 0 );
}

static int ssl_finished_in_parse( mbedtls_ssl_context* ssl,
                                  const unsigned char* buf,
                                  size_t buflen )
{
    /* Structural validation */
    if( buflen != ssl->handshake->state_local.finished_in.digest_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );

        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_FINISHED );
        return( MBEDTLS_ERR_SSL_BAD_HS_FINISHED );
    }

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "Verify finished message" ) );

    MBEDTLS_SSL_DEBUG_BUF( 5, "Hash ( self-computed ):",
                           ssl->handshake->state_local.finished_in.digest,
                           ssl->handshake->state_local.finished_in.digest_len );
    MBEDTLS_SSL_DEBUG_BUF( 5, "Hash ( received message ):", buf,
                           ssl->handshake->state_local.finished_in.digest_len );

    /* Semantic validation */
    if( mbedtls_ssl_safer_memcmp( buf,
                   ssl->handshake->state_local.finished_in.digest,
                   ssl->handshake->state_local.finished_in.digest_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );

        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_FINISHED );
        return( MBEDTLS_ERR_SSL_BAD_HS_FINISHED );
    }
    return( 0 );
}

#if defined(MBEDTLS_SSL_CLI_C)
static int ssl_finished_in_postprocess_cli( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    const mbedtls_ssl_ciphersuite_t *suite_info =
        mbedtls_ssl_ciphersuite_from_id( ssl->session_negotiate->ciphersuite );
    const mbedtls_cipher_info_t *cipher_info;

    mbedtls_md_type_t hash_type;

    /* Compute hash over transcript of all messages sent up to the Finished
     * message sent by the server and store it in the digest variable of the
     * handshake state. This digest will be needed later when computing the
     * application traffic secrets. */
    cipher_info = mbedtls_cipher_info_from_type(
                                ssl->handshake->ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found",
                                  ssl->handshake->ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    if( suite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_ssl_ciphersuite_from_id in "
                                  "mbedtls_ssl_generate_handshake_traffic_keys failed" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    hash_type = suite_info->mac;

#if defined(MBEDTLS_SHA256_C)
    if( hash_type == MBEDTLS_MD_SHA256 )
    {
        mbedtls_sha256_context sha256;
        mbedtls_sha256_init( &sha256 );

        if( ( ret = mbedtls_sha256_starts_ret( &sha256, 0 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_starts_ret", ret );
            goto exit;
        }

        mbedtls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

        ret = mbedtls_sha256_finish_ret( &sha256,
                               ssl->handshake->server_finished_digest );

        mbedtls_sha256_free( &sha256 );

        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha256_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
    if( hash_type == MBEDTLS_MD_SHA384 )
    {
        mbedtls_sha512_context sha512;
        mbedtls_sha512_init( &sha512 );

        if( ( ret = mbedtls_sha512_starts_ret( &sha512, 1 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_starts_ret", ret );
            goto exit;
        }

        mbedtls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

        ret = mbedtls_sha512_finish_ret( &sha512,
                                  ssl->handshake->server_finished_digest );

        mbedtls_sha512_free( &sha512 );

        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_sha512_finish_ret", ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_SHA512_C */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mbedtls_ssl_key_set traffic_keys;
    ret = mbedtls_ssl_generate_application_traffic_keys( ssl, &traffic_keys );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_generate_application_traffic_keys", ret );
        return( ret );
    }

    ret = mbedtls_ssl_tls13_populate_transform(
                                    ssl->transform_application,
                                    ssl->conf->endpoint,
                                    ssl->session_negotiate->ciphersuite,
                                    &traffic_keys,
                                    ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_USE_MPS)
    {
        mbedtls_ssl_transform *transform_application =
            mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
        if( transform_application == NULL )
            return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

        ret = mbedtls_ssl_tls13_populate_transform(
                              transform_application,
                              ssl->conf->endpoint,
                              ssl->session_negotiate->ciphersuite,
                              &traffic_keys,
                              ssl );

        /* Register transform with MPS. */
        ret = mbedtls_mps_add_key_material( &ssl->mps.l4,
                                            transform_application,
                                            &ssl->epoch_application );
        if( ret != 0 )
            return( ret );
    }
#endif /* MBEDTLS_SSL_USE_MPS */

exit:

    if( ret == 0 )
    {
        MBEDTLS_SSL_DEBUG_BUF( 3, "Transcript hash (incl. Srv.Finished):",
                             ssl->handshake->server_finished_digest,
                             mbedtls_hash_size_for_ciphersuite( suite_info ) );
    }

    return( ret );
}
#endif /* MBEDTLS_SSL_CLI_C */

static int ssl_finished_in_postprocess( mbedtls_ssl_context* ssl )
{
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        /* Nothing to be done in this case. */
        return( 0 );
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        return( ssl_finished_in_postprocess_cli( ssl ) );
    }
#endif /* MBEDTLS_SSL_CLI_C */

    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

#if defined(MBEDTLS_CID)
void mbedtls_ssl_conf_cid( mbedtls_ssl_config *conf, unsigned int cid )
{
    if( cid == MBEDTLS_CID_CONF_DISABLED || cid == MBEDTLS_CID_CONF_ENABLED ||
        cid == MBEDTLS_CID_CONF_ZERO_LENGTH )
        conf->cid = cid;
}
#endif


#if defined(MBEDTLS_ZERO_RTT)
void mbedtls_ssl_conf_early_data( mbedtls_ssl_config *conf, int early_data, char *buffer, unsigned int len, int( *early_data_callback )( mbedtls_ssl_context *,
                                                                                                                                         unsigned char *, size_t ) )
{
#if !defined(MBEDTLS_SSL_SRV_C)
    ( (void ) early_data_callback );
#endif /* !MBEDTLS_SSL_SRV_C */

    if( conf != NULL )
    {
        conf->early_data = early_data;
        if( buffer != NULL && len >0 && early_data==MBEDTLS_SSL_EARLY_DATA_ENABLED )
        {
            conf->early_data_buf = buffer;
            conf->early_data_len = len;
#if defined(MBEDTLS_SSL_SRV_C)
            /* Only the server uses the early data callback.
             * For the client this parameter is not used.
             */
            conf->early_data_callback = early_data_callback;
#endif /* MBEDTLS_SSL_SRV_C */
        }
    }
}
#endif /* MBEDTLS_ZERO_RTT */


#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET) && defined(MBEDTLS_SSL_CLI_C)

/*
 * Overview
 */

/* The mbedtls_ssl_new_session_ticket_process( ) function is used by the
 * client to process the NewSessionTicket message, which contains
 * the ticket and meta-data provided by the server in a post-
 * handshake message.
 */
int mbedtls_ssl_new_session_ticket_process( mbedtls_ssl_context* ssl );

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_new_session_ticket_fetch( mbedtls_ssl_context* ssl,
                                         unsigned char** buf,
                                         size_t* buflen );
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_new_session_ticket_parse( mbedtls_ssl_context* ssl,
                                  unsigned char* buf,
                                  size_t buflen );

static int ssl_new_session_ticket_postprocess( mbedtls_ssl_context* ssl, int ret );


/*
 * Implementation
 */

int mbedtls_ssl_new_session_ticket_process( mbedtls_ssl_context* ssl )
{
    int ret;
    unsigned char* buf;
    size_t buflen;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse new session ticket" ) );

#if defined(MBEDTLS_SSL_USE_MPS)

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_fetch_full_hs_msg( ssl,
                                          MBEDTLS_SSL_HS_NEW_SESSION_TICKET,
                                          &buf, &buflen ) );

    /* Process the message contents */
    MBEDTLS_SSL_PROC_CHK( ssl_new_session_ticket_parse( ssl, buf, buflen ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );

#else /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_PROC_CHK( ssl_new_session_ticket_fetch( ssl, &buf, &buflen ) );
    MBEDTLS_SSL_PROC_CHK( ssl_new_session_ticket_parse( ssl, buf, buflen ) );

#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_PROC_CHK( ssl_new_session_ticket_postprocess( ssl, ret ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    /* TBD: Return ACK message */
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        mbedtls_ssl_recv_flight_completed( ssl );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse new session ticket" ) );
    return( ret );
}

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_new_session_ticket_fetch( mbedtls_ssl_context* ssl,
                                         unsigned char** dst,
                                         size_t* dstlen )
{
    *dst = ssl->in_msg + mbedtls_ssl_hs_hdr_len( ssl );
    *dstlen = ssl->in_hslen - mbedtls_ssl_hs_hdr_len( ssl );

    return( 0 );
}
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_new_session_ticket_parse( mbedtls_ssl_context* ssl,
                                         unsigned char* buf,
                                         size_t buflen )
{
    int ret;
    uint16_t ticket_len, ext_len;
    unsigned char *ticket;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    size_t used = 0;
    int hash_length;

    /*
     * struct {
     *    uint32 ticket_lifetime;
     *    uint32 ticket_age_add;
     *    opaque ticket_nonce<0..255>;
     *    opaque ticket<1..2^16-1>;
     *    Extension extensions<0..2^16-2>;
     * } NewSessionTicket;
     *
     */
    used += 4   /* ticket_lifetime */
          + 4   /* ticket_age_add */
          + 1   /* ticket_nonce length */
          + 2   /* ticket length */
          + 2;  /* extension length */

    if( used > buflen )
    {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad new session ticket message" ) );
         return( MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET );
    }

    /* Ticket lifetime */
    ssl->session->ticket_lifetime =
        ( (unsigned) buf[0] << 24 ) | ( (unsigned) buf[1] << 16 ) |
        ( (unsigned) buf[2] << 8  ) | ( (unsigned) buf[3] << 0 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->lifetime: %d", ssl->session->ticket_lifetime ) );

    /* Ticket Age Add */
    ssl->session->ticket_age_add =
                     ( (unsigned) buf[4] << 24 ) |
                     ( (unsigned) buf[5] << 16 ) |
                     ( (unsigned) buf[6] << 8  ) |
                     ( (unsigned) buf[7] << 0  );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->ticket_age_add: %u", ssl->session->ticket_age_add ) );

    /* Ticket Nonce */
    /* Check if we previously received a ticket already. If we did, then we should
     * re-use already allocated nonce-space.
     */
    if( ssl->session->ticket_nonce != NULL && ssl->session->ticket_nonce_len > 0 )
    {
        mbedtls_free( ssl->session->ticket_nonce );
        ssl->session->ticket_nonce = NULL;
        ssl->session->ticket_nonce_len = 0;
    }

    ssl->session->ticket_nonce_len = buf[8];

    used += ssl->session->ticket_nonce_len;

    if( used > buflen )
    {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad new session ticket message" ) );
         return( MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET );
    }

    if( ssl->session->ticket_nonce_len > 0 )
    {
        if( ( ssl->session->ticket_nonce = mbedtls_calloc( 1,
            ssl->session->ticket_nonce_len ) ) == NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "ticket_nonce alloc failed" ) );
            return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
        }

        memcpy( ssl->session->ticket_nonce, &buf[9], ssl->session->ticket_nonce_len );

        MBEDTLS_SSL_DEBUG_BUF( 3, "ticket->nonce:", (unsigned char*)&buf[9],
        ssl->session->ticket_nonce_len );

    }

    /* Ticket */
    ticket_len = ( buf[9 + ssl->session->ticket_nonce_len] << 8 ) |
                 ( buf[10 + ssl->session->ticket_nonce_len] );

    used += ticket_len;

    if( used > buflen )
    {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad new session ticket message" ) );
         return( MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->length: %d", ticket_len ) );

    /* Ticket Extension */
    ext_len = ( (unsigned) buf[ 11 + ssl->session->ticket_nonce_len + ticket_len ] << 8 ) |
              ( (unsigned) buf[ 12 + ssl->session->ticket_nonce_len + ticket_len ] );

    used += ext_len;

    if( used != buflen )
    {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad new session ticket message" ) );
         return( MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET );
    }

    /* Check if we previously received a ticket already. */
    if( ssl->session->ticket != NULL || ssl->session->ticket_len > 0 )
    {
        mbedtls_free( ssl->session->ticket );
        ssl->session->ticket = NULL;
        ssl->session->ticket_len = 0;
    }

    if( ( ticket = mbedtls_calloc( 1, ticket_len ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ticket alloc failed" ) );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    memcpy( ticket, buf + 11 + ssl->session->ticket_nonce_len, ticket_len );
    ssl->session->ticket = ticket;
    ssl->session->ticket_len = ticket_len;

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "ticket->extension length: %d", ext_len ) );

    /* We are not storing any extensions at the moment */
    MBEDTLS_SSL_DEBUG_BUF( 3, "ticket->extension",
                           &buf[ 13 + ssl->session->ticket_nonce_len + ticket_len ],
                           ext_len );

    /* Compute PSK based on received nonce and resumption_master_secret
     * in the following style:
     *
     *  HKDF-Expand-Label( resumption_master_secret,
     *                    "resumption", ticket_nonce, Hash.length )
     */

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session->ciphersuite );

    if( suite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    hash_length = mbedtls_hash_size_for_ciphersuite( suite_info );

    if( hash_length == -1 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    MBEDTLS_SSL_DEBUG_BUF( 3, "resumption_master_secret",
                           ssl->session->resumption_master_secret,
                           hash_length );

    /* Computer resumption key
     *
     *  HKDF-Expand-Label( resumption_master_secret,
     *                    "resumption", ticket_nonce, Hash.length )
     */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( suite_info->mac,
                    ssl->session->resumption_master_secret,
                    hash_length,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( resumption ),
                    ssl->session->ticket_nonce,
                    ssl->session->ticket_nonce_len,
                    ssl->session->key,
                    hash_length );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the ticket-resumed PSK failed", ret );
        return ( ret );
    }

    ssl->session->resumption_key_len = mbedtls_hash_size_for_ciphersuite( suite_info );

    MBEDTLS_SSL_DEBUG_BUF( 3, "Ticket-resumed PSK", ssl->session->key,
                           ssl->session->resumption_key_len );

#if defined(MBEDTLS_HAVE_TIME)
    /* Store ticket creation time */
    ssl->session->ticket_received = time( NULL );
#endif

    MBEDTLS_SSL_DEBUG_BUF( 5, "ticket", buf, buflen );

    return( 0 );
}

static int ssl_new_session_ticket_postprocess( mbedtls_ssl_context* ssl, int ret )
{
    ((void ) ssl);
    ((void ) ret);
    return( 0 );
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET && MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
void mbedtls_ssl_conf_signature_algorithms( mbedtls_ssl_config *conf,
                     const int* sig_algs )
{
    conf->sig_hashes = sig_algs;
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

/* Early Data Extension
 *
 * struct {} Empty;
 *
 * struct {
 *   select ( Handshake.msg_type ) {
 *     case new_session_ticket:   uint32 max_early_data_size;
 *     case client_hello:         Empty;
 *     case encrypted_extensions: Empty;
 *   };
 * } EarlyDataIndication;
 */
#if defined(MBEDTLS_ZERO_RTT)
int mbedtls_ssl_write_early_data_ext( mbedtls_ssl_context *ssl,
                                      unsigned char *buf,
                                      size_t buflen,
                                      size_t *olen )
{
    unsigned char *p = buf;
    const unsigned char* end = buf + buflen;

    *olen = 0;

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if( ( ssl->handshake->extensions_present & EARLY_DATA_EXTENSION ) == 0 )
            return( 0 );

        if( ssl->conf->key_exchange_modes != MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_KE ||
            ssl->conf->early_data == MBEDTLS_SSL_EARLY_DATA_DISABLED ) {

            MBEDTLS_SSL_DEBUG_MSG( 2, ( "skip write early_data extension" ) );
            ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_OFF;
            *olen = 0;
            return( 0 );
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        if( ssl->conf->key_exchange_modes == MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_ECDHE_ECDSA ||
            ssl->conf->early_data == MBEDTLS_SSL_EARLY_DATA_DISABLED ) {

            MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= skip write early_data extension" ) );
            ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_OFF;
            *olen = 0;
            return( 0 );
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */

    if( (size_t)( end - p ) < 4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return ( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding early_data extension" ) );
        /* We're using rejected once we sent the EarlyData extension,
           and change it to accepted upon receipt of the server extension. */
        ssl->early_data_status = MBEDTLS_SSL_EARLY_DATA_REJECTED;
    }
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding early_data extension" ) );
    }
#endif /* MBEDTLS_SSL_SRV_C */

    ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_ON;

    /* Write extension header */
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_EARLY_DATA >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_EARLY_DATA ) & 0xFF );

    /* Write total extension length */
    *p++ = 0;
    *p++ = 0;

    *olen = 4;
    return( 0 );
}
#endif /* MBEDTLS_ZERO_RTT */


#if defined(MBEDTLS_ECDH_C)
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef mbedtls_ecdh_context mbedtls_ecdh_context_mbed;
#endif

#define ECDH_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )

static int ecdh_make_tls_13_params_internal( mbedtls_ecdh_context_mbed *ctx,
                                      size_t *olen, int point_format,
                                      unsigned char *buf, size_t blen,
                                      int (*f_rng)(void *,
                                                   unsigned char *,
                                                   size_t),
                                      void *p_rng,
                                      int restart_enabled )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t grp_len, pt_len;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if( ctx->grp.pbits == 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( restart_enabled )
        rs_ctx = &ctx->rs;
#else
    (void) restart_enabled;
#endif


#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( ( ret = ecdh_gen_public_restartable( &ctx->grp, &ctx->d, &ctx->Q,
                                             f_rng, p_rng, rs_ctx ) ) != 0 )
        return( ret );
#else
    if( ( ret = mbedtls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q,
                                         f_rng, p_rng ) ) != 0 )
        return( ret );
#endif /* MBEDTLS_ECP_RESTARTABLE */

    if( ( ret = mbedtls_ecp_tls_13_write_group( &ctx->grp, &grp_len, buf,
                                             blen ) ) != 0 )
        return( ret );

    buf += grp_len;
    blen -= grp_len;

    if( ( ret = mbedtls_ecp_tls_13_write_point( &ctx->grp, &ctx->Q, point_format,
                                             &pt_len, buf, blen ) ) != 0 )
        return( ret );

    *olen = grp_len + pt_len;
    return( 0 );
}

int mbedtls_ecdh_make_tls_13_params( mbedtls_ecdh_context *ctx, size_t *olen,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    int restart_enabled = 0;
    ECDH_VALIDATE_RET( ctx != NULL );
    ECDH_VALIDATE_RET( olen != NULL );
    ECDH_VALIDATE_RET( buf != NULL );
    ECDH_VALIDATE_RET( f_rng != NULL );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#else
    (void) restart_enabled;
#endif

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( ecdh_make_tls_13_params_internal( ctx, olen, ctx->point_format, buf, blen,
                                       f_rng, p_rng, restart_enabled ) );
#else
    switch( ctx->var )
    {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return( mbedtls_everest_make_params( &ctx->ctx.everest_ecdh, olen,
                                                 buf, blen, f_rng, p_rng ) );
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( ecdh_make_params_internal( &ctx->ctx.mbed_ecdh, olen,
                                               ctx->point_format, buf, blen,
                                               f_rng, p_rng,
                                               restart_enabled ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_read_tls_13_params_internal( mbedtls_ecdh_context_mbed *ctx,
                                      const unsigned char **buf,
                                      const unsigned char *end )
{
    return( mbedtls_ecp_tls_13_read_point( &ctx->grp, &ctx->Qp, buf,
                                        end - *buf ) );
}

int mbedtls_ecdh_read_tls_13_params( mbedtls_ecdh_context *ctx,
                              const unsigned char **buf,
                              const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group_id grp_id;
    ECDH_VALIDATE_RET( ctx != NULL );
    ECDH_VALIDATE_RET( buf != NULL );
    ECDH_VALIDATE_RET( *buf != NULL );
    ECDH_VALIDATE_RET( end != NULL );

    if( ( ret = mbedtls_ecp_tls_13_read_group_id( &grp_id, buf, end - *buf ) )
            != 0 )
        return( ret );

    if( ( ret = mbedtls_ecdh_setup( ctx, grp_id ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( ecdh_read_tls_13_params_internal( ctx, buf, end ) );
#else
    switch( ctx->var )
    {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return( mbedtls_everest_read_params( &ctx->ctx.everest_ecdh,
                                                 buf, end) );
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( ecdh_read_params_internal( &ctx->ctx.mbed_ecdh,
                                               buf, end ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_make_tls_13_public_internal( mbedtls_ecdh_context_mbed *ctx,
                                      size_t *olen, int point_format,
                                      unsigned char *buf, size_t blen,
                                      int (*f_rng)(void *,
                                                   unsigned char *,
                                                   size_t),
                                      void *p_rng,
                                      int restart_enabled )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if( ctx->grp.pbits == 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( restart_enabled )
        rs_ctx = &ctx->rs;
#else
    (void) restart_enabled;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( ( ret = ecdh_gen_public_restartable( &ctx->grp, &ctx->d, &ctx->Q,
                                             f_rng, p_rng, rs_ctx ) ) != 0 )
        return( ret );
#else
    if( ( ret = mbedtls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q,
                                         f_rng, p_rng ) ) != 0 )
        return( ret );
#endif /* MBEDTLS_ECP_RESTARTABLE */

    return mbedtls_ecp_tls_13_write_point( &ctx->grp, &ctx->Q, point_format, olen,
                                        buf, blen );
}

/*
 * Setup and export the client public value
 */
int mbedtls_ecdh_make_tls_13_public( mbedtls_ecdh_context *ctx, size_t *olen,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    int restart_enabled = 0;
    ECDH_VALIDATE_RET( ctx != NULL );
    ECDH_VALIDATE_RET( olen != NULL );
    ECDH_VALIDATE_RET( buf != NULL );
    ECDH_VALIDATE_RET( f_rng != NULL );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#endif

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( ecdh_make_tls_13_public_internal( ctx, olen, ctx->point_format, buf, blen,
                                       f_rng, p_rng, restart_enabled ) );
#else
    switch( ctx->var )
    {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return( mbedtls_everest_make_public( &ctx->ctx.everest_ecdh, olen,
                                                 buf, blen, f_rng, p_rng ) );
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( ecdh_make_public_internal( &ctx->ctx.mbed_ecdh, olen,
                                               ctx->point_format, buf, blen,
                                               f_rng, p_rng,
                                               restart_enabled ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_read_tls_13_public_internal( mbedtls_ecdh_context_mbed *ctx,
                                      const unsigned char *buf, size_t blen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;

    if( ( ret = mbedtls_ecp_tls_13_read_point( &ctx->grp, &ctx->Qp, &p,
                                            blen ) ) != 0 )
        return( ret );

    if( (size_t)( p - buf ) != blen )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    return( 0 );
}

/*
 * Parse and import the client's TLS 1.3 public value
 */
int mbedtls_ecdh_read_tls_13_public( mbedtls_ecdh_context *ctx,
                              const unsigned char *buf, size_t blen )
{
    ECDH_VALIDATE_RET( ctx != NULL );
    ECDH_VALIDATE_RET( buf != NULL );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( ecdh_read_tls_13_public_internal( ctx, buf, blen ) );
#else
    switch( ctx->var )
    {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return( mbedtls_everest_read_public( &ctx->ctx.everest_ecdh,
                                                 buf, blen ) );
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( ecdh_read_public_internal( &ctx->ctx.mbed_ecdh,
                                                       buf, blen ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}
#endif /* MBEDTLS_ECDH_C */

#if defined(MBEDTLS_ECP_C)
#define ECP_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )

int mbedtls_ecp_tls_13_read_point( const mbedtls_ecp_group *grp,
                                mbedtls_ecp_point *pt,
                                const unsigned char **buf, size_t buf_len )
{
    unsigned char data_len;
    const unsigned char *buf_start;
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( pt  != NULL );
    ECP_VALIDATE_RET( buf != NULL );
    ECP_VALIDATE_RET( *buf != NULL );

    if( buf_len < 3 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    data_len = ( *( *buf ) << 8 ) | *( *buf+1 );
    *buf += 2;

    if( data_len < 1 || data_len > buf_len - 2 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Save buffer start for read_binary and update buf
     */
    buf_start = *buf;
    *buf += data_len;

    return( mbedtls_ecp_point_read_binary( grp, pt, buf_start, data_len ) );
}

int mbedtls_ecp_tls_13_write_point( const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt,
                         int format, size_t *olen,
                         unsigned char *buf, size_t blen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( pt   != NULL );
    ECP_VALIDATE_RET( olen != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( format == MBEDTLS_ECP_PF_UNCOMPRESSED ||
                      format == MBEDTLS_ECP_PF_COMPRESSED );

    if( blen < 2 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecp_point_write_binary( grp, pt, format,
                    olen, buf + 2, blen - 2) ) != 0 )
        return( ret );

    // Length
    *buf++ = (unsigned char)( ( *olen >> 8 ) & 0xFF );
    *buf++ = (unsigned char)( ( *olen ) & 0xFF );
    *olen += 2;

    return( 0 );
}

/*
 * Read a group id from an ECParameters record (TLS 1.3) and convert it to
 * mbedtls_ecp_group_id.
 */
int mbedtls_ecp_tls_13_read_group_id( mbedtls_ecp_group_id *grp,
                                   const unsigned char **buf, size_t len )
{
    uint16_t tls_id;
    const mbedtls_ecp_curve_info *curve_info;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( *buf != NULL );

    if( len < 2 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Next two bytes are the namedcurve value
     */
    tls_id = *(*buf)++;
    tls_id <<= 8;
    tls_id |= *(*buf)++;

    if( ( curve_info = mbedtls_ecp_curve_info_from_tls_id( tls_id ) ) == NULL )
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );

    *grp = curve_info->grp_id;

    return( 0 );
}

/*
 * Write the ECParameters record corresponding to a group (TLS 1.3)
 */
int mbedtls_ecp_tls_13_write_group( const mbedtls_ecp_group *grp, size_t *olen,
                         unsigned char *buf, size_t blen )
{
    const mbedtls_ecp_curve_info *curve_info;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( olen != NULL );

    if( ( curve_info = mbedtls_ecp_curve_info_from_grp_id( grp->id ) ) == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    *olen = 2;
    if( blen < *olen )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    // Two bytes for named curve
    buf[0] = curve_info->tls_id >> 8;
    buf[1] = curve_info->tls_id & 0xFF;

    return( 0 );
}

#endif /* MBEDTLS_ECP_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#endif /* MBEDTLS_SSL_TLS_C */
