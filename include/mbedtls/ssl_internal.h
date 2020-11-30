/**
 * \file ssl_internal.h
 *
 * \brief Internal functions shared by the SSL modules
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
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
#ifndef MBEDTLS_SSL_INTERNAL_H
#define MBEDTLS_SSL_INTERNAL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/ssl.h"
#include "mbedtls/cipher.h"

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif

#if defined(MBEDTLS_MD5_C)
#include "mbedtls/md5.h"
#endif

#if defined(MBEDTLS_SHA1_C)
#include "mbedtls/sha1.h"
#endif

#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif

#if defined(MBEDTLS_SHA512_C)
#include "mbedtls/sha512.h"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#include "mbedtls/ecjpake.h"
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/* Determine minimum supported version */
#define MBEDTLS_SSL_MIN_MAJOR_VERSION           MBEDTLS_SSL_MAJOR_VERSION_3

#if defined(MBEDTLS_SSL_PROTO_SSL3)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_0
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_1
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_1)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_2
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_3
#else /* MBEDTLS_SSL_PROTO_TLS1_2 */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_4
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 */
#endif /* MBEDTLS_SSL_PROTO_TLS1   */
#endif /* MBEDTLS_SSL_PROTO_SSL3   */

#define MBEDTLS_SSL_MIN_VALID_MINOR_VERSION MBEDTLS_SSL_MINOR_VERSION_4
#define MBEDTLS_SSL_MIN_VALID_MAJOR_VERSION MBEDTLS_SSL_MAJOR_VERSION_3

/* Determine maximum supported version */
#define MBEDTLS_SSL_MAX_MAJOR_VERSION           MBEDTLS_SSL_MAJOR_VERSION_3


#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_4
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_3
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_1)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_2
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_1
#else
#if defined(MBEDTLS_SSL_PROTO_SSL3)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_0
#endif /* MBEDTLS_SSL_PROTO_SSL3   */
#endif /* MBEDTLS_SSL_PROTO_TLS1   */
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

/* Shorthand for restartable ECC */
#if defined(MBEDTLS_ECP_RESTARTABLE) && \
    defined(MBEDTLS_SSL_CLI_C) && \
    (defined(MBEDTLS_SSL_PROTO_TLS1_2) || defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)) && \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
#define MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED
#endif

#define MBEDTLS_SSL_INITIAL_HANDSHAKE           0
#define MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS   1   /* In progress */
#define MBEDTLS_SSL_RENEGOTIATION_DONE          2   /* Done or aborted */
#define MBEDTLS_SSL_RENEGOTIATION_PENDING       3   /* Requested (server only) */


/* For use with cTLS only */
#define MBEDTLS_SSL_TLS13_CTLS_DO_NOT_USE         0
#define MBEDTLS_SSL_TLS13_CTLS_USE                1

// Constants for use with varint data type introduced by cTLS
#define MBEDTLS_VARINT_HDR_1 128
#define MBEDTLS_VARINT_HDR_2 64
enum varint_length_enum { VARINT_LENGTH_FAILURE = 0, VARINT_LENGTH_1_BYTE = 1, VARINT_LENGTH_2_BYTE = 2, VARINT_LENGTH_3_BYTE = 3 };

#define MBEDTLS_SSL_PROC_CHK(f) do { if( ( ret = f ) < 0 ) goto cleanup; } while( 0 )

/*
 * DTLS retransmission states, see RFC 6347 4.2.4
 *
 * The SENDING state is merged in PREPARING for initial sends,
 * but is distinct for resends.
 *
 * Note: initial state is wrong for server, but is not used anyway.
 */
#define MBEDTLS_SSL_RETRANS_PREPARING       0
#define MBEDTLS_SSL_RETRANS_SENDING         1
#define MBEDTLS_SSL_RETRANS_WAITING         2
#define MBEDTLS_SSL_RETRANS_FINISHED        3

/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256)
 * and allow for a maximum of 1024 of compression expansion if
 * enabled.
 */
#if defined(MBEDTLS_ZLIB_SUPPORT)
#define MBEDTLS_SSL_COMPRESSION_ADD          1024
#else
#define MBEDTLS_SSL_COMPRESSION_ADD             0
#endif

#if defined(MBEDTLS_SSL_PROTO_SSL3)   ||                              \
    defined(MBEDTLS_SSL_PROTO_TLS1)   ||                              \
    defined(MBEDTLS_SSL_PROTO_TLS1_1) ||                              \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)

/* This macro determines whether CBC is supported. */
#if defined(MBEDTLS_CIPHER_MODE_CBC) &&                               \
    ( defined(MBEDTLS_AES_C)      ||                                  \
      defined(MBEDTLS_CAMELLIA_C) ||                                  \
      defined(MBEDTLS_ARIA_C)     ||                                  \
      defined(MBEDTLS_DES_C) )
#define MBEDTLS_SSL_SOME_SUITES_USE_CBC
#endif

/* This macro determines whether the CBC construct used in TLS 1.0-1.2 (as
 * opposed to the very different CBC construct used in SSLv3) is supported. */
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC) && \
    ( defined(MBEDTLS_SSL_PROTO_TLS1) ||        \
      defined(MBEDTLS_SSL_PROTO_TLS1_1) ||      \
      defined(MBEDTLS_SSL_PROTO_TLS1_2) )
#define MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC
#endif

#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER) ||   \
    defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC)
#define MBEDTLS_SSL_SOME_MODES_USE_MAC
#endif

#endif /* TLS <= 1.2 */

#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
/* Ciphersuites using HMAC */
#if defined(MBEDTLS_SHA512_C)
#define MBEDTLS_SSL_MAC_ADD                 48  /* SHA-384 used for HMAC */
#elif defined(MBEDTLS_SHA256_C)
#define MBEDTLS_SSL_MAC_ADD                 32  /* SHA-256 used for HMAC */
#else
#define MBEDTLS_SSL_MAC_ADD                 20  /* SHA-1   used for HMAC */
#endif
#else /* MBEDTLS_SSL_SOME_MODES_USE_MAC */
/* AEAD ciphersuites: GCM and CCM use a 128 bits tag */
#define MBEDTLS_SSL_MAC_ADD                 16
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
#define MBEDTLS_SSL_PADDING_ADD            256
#else
#define MBEDTLS_SSL_PADDING_ADD              0
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_MAX_CID_EXPANSION      MBEDTLS_SSL_CID_PADDING_GRANULARITY
#else
#define MBEDTLS_SSL_MAX_CID_EXPANSION        0
#endif

#define MBEDTLS_SSL_PAYLOAD_OVERHEAD ( MBEDTLS_SSL_COMPRESSION_ADD +    \
                                       MBEDTLS_MAX_IV_LENGTH +          \
                                       MBEDTLS_SSL_MAC_ADD +            \
                                       MBEDTLS_SSL_PADDING_ADD +        \
                                       MBEDTLS_SSL_MAX_CID_EXPANSION    \
                                       )

#define MBEDTLS_SSL_IN_PAYLOAD_LEN ( MBEDTLS_SSL_PAYLOAD_OVERHEAD + \
                                     ( MBEDTLS_SSL_IN_CONTENT_LEN ) )

#define MBEDTLS_SSL_OUT_PAYLOAD_LEN ( MBEDTLS_SSL_PAYLOAD_OVERHEAD + \
                                      ( MBEDTLS_SSL_OUT_CONTENT_LEN ) )

/* The maximum number of buffered handshake messages. */
#define MBEDTLS_SSL_MAX_BUFFERED_HS 4

/* Maximum length we can advertise as our max content length for
   RFC 6066 max_fragment_length extension negotiation purposes
   (the lesser of both sizes, if they are unequal.)
 */
#define MBEDTLS_TLS_EXT_ADV_CONTENT_LEN (                            \
        (MBEDTLS_SSL_IN_CONTENT_LEN > MBEDTLS_SSL_OUT_CONTENT_LEN)   \
        ? ( MBEDTLS_SSL_OUT_CONTENT_LEN )                            \
        : ( MBEDTLS_SSL_IN_CONTENT_LEN )                             \
        )

/* Maximum size in bytes of list in sig-hash algorithm ext., RFC 5246 */
#define MBEDTLS_SSL_MAX_SIG_HASH_ALG_LIST_LEN  65534

/* Maximum size in bytes of list in supported elliptic curve ext., RFC 4492 */
#define MBEDTLS_SSL_MAX_CURVE_LIST_LEN         65535

/*
 * Check that we obey the standard's message size bounds
 */

#if MBEDTLS_SSL_MAX_CONTENT_LEN > 16384
#error "Bad configuration - record content too large."
#endif

#if MBEDTLS_SSL_IN_CONTENT_LEN > MBEDTLS_SSL_MAX_CONTENT_LEN
#error "Bad configuration - incoming record content should not be larger than MBEDTLS_SSL_MAX_CONTENT_LEN."
#endif

#if MBEDTLS_SSL_OUT_CONTENT_LEN > MBEDTLS_SSL_MAX_CONTENT_LEN
#error "Bad configuration - outgoing record content should not be larger than MBEDTLS_SSL_MAX_CONTENT_LEN."
#endif

#if MBEDTLS_SSL_IN_PAYLOAD_LEN > MBEDTLS_SSL_MAX_CONTENT_LEN + 2048
#error "Bad configuration - incoming protected record payload too large."
#endif

#if MBEDTLS_SSL_OUT_PAYLOAD_LEN > MBEDTLS_SSL_MAX_CONTENT_LEN + 2048
#error "Bad configuration - outgoing protected record payload too large."
#endif

/* Calculate buffer sizes */

/* Note: Even though the TLS record header is only 5 bytes
   long, we're internally using 8 bytes to store the
   implicit sequence number. */
#define MBEDTLS_SSL_HEADER_LEN 13

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ( ( MBEDTLS_SSL_HEADER_LEN ) + ( MBEDTLS_SSL_IN_PAYLOAD_LEN ) )
#else
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ( ( MBEDTLS_SSL_HEADER_LEN ) + ( MBEDTLS_SSL_IN_PAYLOAD_LEN ) \
      + ( MBEDTLS_SSL_CID_IN_LEN_MAX ) )
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_OUT_BUFFER_LEN  \
    ( ( MBEDTLS_SSL_HEADER_LEN ) + ( MBEDTLS_SSL_OUT_PAYLOAD_LEN ) )
#else
#define MBEDTLS_SSL_OUT_BUFFER_LEN                               \
    ( ( MBEDTLS_SSL_HEADER_LEN ) + ( MBEDTLS_SSL_OUT_PAYLOAD_LEN )    \
      + ( MBEDTLS_SSL_CID_OUT_LEN_MAX ) )
#endif

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
static inline uint32_t mbedtls_ssl_get_output_buflen( const mbedtls_ssl_context *ctx )
{
#if defined (MBEDTLS_SSL_DTLS_CONNECTION_ID)
    return (uint32_t) mbedtls_ssl_get_output_max_frag_len( ctx )
               + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD
               + MBEDTLS_SSL_CID_OUT_LEN_MAX;
#else
    return (uint32_t) mbedtls_ssl_get_output_max_frag_len( ctx )
               + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD;
#endif
}

static inline uint32_t mbedtls_ssl_get_input_buflen( const mbedtls_ssl_context *ctx )
{
#if defined (MBEDTLS_SSL_DTLS_CONNECTION_ID)
    return (uint32_t) mbedtls_ssl_get_input_max_frag_len( ctx )
               + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD
               + MBEDTLS_SSL_CID_IN_LEN_MAX;
#else
    return (uint32_t) mbedtls_ssl_get_input_max_frag_len( ctx )
               + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD;
#endif
}
#endif

#ifdef MBEDTLS_ZLIB_SUPPORT
/* Compression buffer holds both IN and OUT buffers, so should be size of the larger */
#define MBEDTLS_SSL_COMPRESS_BUFFER_LEN (                               \
        ( MBEDTLS_SSL_IN_BUFFER_LEN > MBEDTLS_SSL_OUT_BUFFER_LEN )      \
        ? MBEDTLS_SSL_IN_BUFFER_LEN                                     \
        : MBEDTLS_SSL_OUT_BUFFER_LEN                                    \
        )
#endif

/*
 * TLS extension flags (for extensions with outgoing ServerHello content
 * that need it (e.g. for RENEGOTIATION_INFO the server already knows because
 * of state of the renegotiation flag, so no indicator is required)
 */
#define MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT (1 << 0)
#define MBEDTLS_TLS_EXT_ECJPAKE_KKPP_OK                 (1 << 1)

/**
 * \brief        This function checks if the remaining size in a buffer is
 *               greater or equal than a needed space.
 *
 * \param cur    Pointer to the current position in the buffer.
 * \param end    Pointer to one past the end of the buffer.
 * \param need   Needed space in bytes.
 *
 * \return       Zero if the needed space is available in the buffer, non-zero
 *               otherwise.
 */
static inline int mbedtls_ssl_chk_buf_ptr( const uint8_t *cur,
                                           const uint8_t *end, size_t need )
{
    return( ( cur > end ) || ( need > (size_t)( end - cur ) ) );
}

/**
 * \brief        This macro checks if the remaining size in a buffer is
 *               greater or equal than a needed space. If it is not the case,
 *               it returns an SSL_BUFFER_TOO_SMALL error.
 *
 * \param cur    Pointer to the current position in the buffer.
 * \param end    Pointer to one past the end of the buffer.
 * \param need   Needed space in bytes.
 *
 */
#define MBEDTLS_SSL_CHK_BUF_PTR( cur, end, need )                        \
    do {                                                                 \
        if( mbedtls_ssl_chk_buf_ptr( ( cur ), ( end ), ( need ) ) != 0 ) \
        {                                                                \
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );                  \
        }                                                                \
    } while( 0 )

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/*
 * Abstraction for a grid of allowed signature-hash-algorithm pairs.
 */
struct mbedtls_ssl_sig_hash_set_t
{
    /* At the moment, we only need to remember a single suitable
     * hash algorithm per signature algorithm. As long as that's
     * the case - and we don't need a general lookup function -
     * we can implement the sig-hash-set as a map from signatures
     * to hash algorithms. */
    mbedtls_md_type_t rsa;
    mbedtls_md_type_t ecdsa;
};
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 &&
          MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

typedef int  mbedtls_ssl_tls_prf_cb( const unsigned char *secret, size_t slen,
                                     const char *label,
                                     const unsigned char *random, size_t rlen,
                                     unsigned char *dstbuf, size_t dlen );

/* cipher.h exports the maximum IV, key and block length from
 * all ciphers enabled in the config, regardless of whether those
 * ciphers are actually usable in SSL/TLS. Notably, XTS is enabled
 * in the default configuration and uses 64 Byte keys, but it is
 * not used for record protection in SSL/TLS.
 *
 * In order to prevent unnecessary inflation of key structures,
 * we introduce SSL-specific variants of the max-{key,block,IV}
 * macros here which are meant to only take those ciphers into
 * account which can be negotiated in SSL/TLS.
 *
 * Since the current definitions of MBEDTLS_MAX_{KEY|BLOCK|IV}_LENGTH
 * in cipher.h are rough overapproximations of the real maxima, here
 * we content ourselves with replicating those overapproximations
 * for the maximum block and IV length, and excluding XTS from the
 * computation of the maximum key length. */
#define MBEDTLS_SSL_MAX_BLOCK_LENGTH 16
#define MBEDTLS_SSL_MAX_IV_LENGTH    16
#define MBEDTLS_SSL_MAX_KEY_LENGTH   32

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

/* cipher.h exports the maximum IV, key and block length from
 * all ciphers enabled in the config, regardless of whether those
 * ciphers are actually usable in SSL/TLS. Notably, XTS is enabled
 * in the default configuration and uses 64 Byte keys, but it is
 * not used for record protection in SSL/TLS.
 *
 * In order to prevent unnecessary inflation of key structures,
 * we introduce SSL-specific variants of the max-{key,block,IV}
 * macros here which are meant to only take those ciphers into
 * account which can be negotiated in SSL/TLS.
 *
 * Since the current definitions of MBEDTLS_MAX_{KEY|BLOCK|IV}_LENGTH
 * in cipher.h are rough overapproximations of the real maxima, here
 * we content ourselves with replicating those overapproximations
 * for the maximum block and IV length, and excluding XTS from the
 * computation of the maximum key length. */
#define MBEDTLS_SSL_MAX_BLOCK_LENGTH 16
#define MBEDTLS_SSL_MAX_IV_LENGTH    16
#define MBEDTLS_SSL_MAX_KEY_LENGTH   32

/**
 * \brief   The data structure holding the cryptographic material (key and IV)
 *          used for record protection in TLS 1.3.
 */
struct mbedtls_ssl_key_set
{
    /*! The key for client->server records. */
    unsigned char client_write_key[ MBEDTLS_SSL_MAX_KEY_LENGTH ];
    /*! The key for server->client records. */
    unsigned char server_write_key[ MBEDTLS_SSL_MAX_KEY_LENGTH ];
    /*! The IV  for client->server records. */
    unsigned char client_write_iv[ MBEDTLS_SSL_MAX_IV_LENGTH ];
    /*! The IV  for server->client records. */
    unsigned char server_write_iv[ MBEDTLS_SSL_MAX_IV_LENGTH ];

    size_t key_len; /*!< The length of client_write_key and
                     *   server_write_key, in Bytes. */
    size_t iv_len;  /*!< The length of client_write_iv and
                     *   server_write_iv, in Bytes. */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    int epoch;
    unsigned char iv[ MBEDTLS_MAX_IV_LENGTH ];

    /* The [sender]_sn_key is indirectly used to
     * encrypt the sequence number in the record layer.
     *
     * The client_sn_key is used to encrypt the
     * sequence number for outgoing transmission.
     * server_sn_key is used for incoming payloads.
     */
    unsigned char server_sn_key[ MBEDTLS_MAX_KEY_LENGTH ];
    unsigned char client_sn_key[ MBEDTLS_MAX_KEY_LENGTH ];
#endif /* MBEDTLS_SSL_PROTO_DTLS */

};
typedef struct mbedtls_ssl_key_set mbedtls_ssl_key_set;
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */


/*
 * This structure contains the parameters only needed during handshake.
 */
struct mbedtls_ssl_handshake_params
{
    /*
     * Handshake specific crypto variables
     */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    int signature_scheme;                        /*!<  Signature scheme  */
    int signature_scheme_client;  /*!<  Signature scheme to use by client-initiated CertificateVerify */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    int *received_signature_schemes_list;              /*!<  Received signature algorithms */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
    mbedtls_ecp_curve_info server_preferred_curve; /*!<  Preferred curve requested by server (obtained in HelloRetryRequest  */
#if defined(MBEDTLS_SSL_CLI_C)
    int hello_retry_requests_received; /*!<  Number of Hello Retry Request messages received from the server.  */
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(MBEDTLS_SSL_SRV_C)
    int hello_retry_requests_sent; /*!<  Number of Hello Retry Request messages sent by the server.  */
#endif /* MBEDTLS_SSL_SRV_C */
#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
    int ccs_sent; /* Number of CCS messages sent */
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    mbedtls_ssl_sig_hash_set_t hash_algs;             /*!<  Set of suitable sig-hash pairs */
#endif
#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_context dhm_ctx;                /*!<  DHM key exchange        */
#endif
/* Adding guard for MBEDTLS_ECDSA_C to ensure no compile errors due
 * to guards also being in ssl_srv.c and ssl_cli.c. There is a gap
 * in functionality that access to ecdh_ctx structure is needed for
 * MBEDTLS_ECDSA_C which does not seem correct.
 */
#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    // For TLS 1.3 we might need to store more than one key exchange payload
    mbedtls_ecdh_context ecdh_ctx[MBEDTLS_SSL_MAX_KEY_SHARES]; /*!<  ECDH key exchange       */
    int ecdh_ctx_selected; /*!< Selected ECDHE context */
    int ecdh_ctx_max; /* !< Maximum number of used structures */
#else
    mbedtls_ecdh_context ecdh_ctx;              /*!<  ECDH key exchange       */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_key_type_t ecdh_psa_type;
    uint16_t ecdh_bits;
    psa_key_id_t ecdh_psa_privkey;
    unsigned char ecdh_psa_peerkey[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t ecdh_psa_peerkey_len;
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    mbedtls_ecjpake_context ecjpake_ctx;        /*!< EC J-PAKE key exchange */
#if defined(MBEDTLS_SSL_CLI_C)
    unsigned char *ecjpake_cache;               /*!< Cache for ClientHello ext */
    size_t ecjpake_cache_len;                   /*!< Length of cached data */
#endif
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    const mbedtls_ecp_curve_info **curves;      /*!<  Supported elliptic curves */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_key_id_t psk_opaque;            /*!< Opaque PSK from the callback   */
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    unsigned char *psk;                 /*!<  PSK from the callback         */
    size_t psk_len;                     /*!<  Length of PSK from callback   */
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_key_cert *key_cert;     /*!< chosen key/cert pair (server)  */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    int sni_authmode;                   /*!< authmode from SNI callback     */
    mbedtls_ssl_key_cert *sni_key_cert; /*!< key/cert list from SNI         */
    mbedtls_x509_crt *sni_ca_chain;     /*!< trusted CAs from SNI callback  */
    mbedtls_x509_crl *sni_ca_crl;       /*!< trusted CAs CRLs from SNI      */
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    int ecrs_enabled;                   /*!< Handshake supports EC restart? */
    mbedtls_x509_crt_restart_ctx ecrs_ctx;  /*!< restart context            */
    enum { /* this complements ssl->state with info on intra-state operations */
        ssl_ecrs_none = 0,              /*!< nothing going on (yet)         */
        ssl_ecrs_crt_verify,            /*!< Certificate: crt_verify()      */
        ssl_ecrs_ske_start_processing,  /*!< ServerKeyExchange: pk_verify() */
        ssl_ecrs_cke_ecdh_calc_secret,  /*!< ClientKeyExchange: ECDH step 2 */
        ssl_ecrs_crt_vrfy_sign,         /*!< CertificateVerify: pk_sign()   */
    } ecrs_state;                       /*!< current (or last) operation    */
    mbedtls_x509_crt *ecrs_peer_cert;   /*!< The peer's CRT chain.          */
    size_t ecrs_n;                      /*!< place for saving a length      */
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C) && \
    !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    mbedtls_pk_context peer_pubkey;     /*!< The public key from the peer.  */
#endif /* MBEDTLS_X509_CRT_PARSE_C && !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

#if (defined(MBEDTLS_SSL_PROTO_DTLS) || defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL))
   /* Prior to TLS 1.3 cookies were only used with DTLS. In TLS 1.3 a cookie
    * mechanism has been introduced.
    */

    unsigned char* verify_cookie;       /*!<  Cli: HelloVerifyRequest cookie
                                          Srv: unused                    */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    size_t verify_cookie_len;
#else
    unsigned char verify_cookie_len;    /*!<  Cli: cookie length
                                              Srv: flag for sending a cookie */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL*/
#endif /* MBEDTLS_SSL_PROTO_DTLS || MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned int out_msg_seq;           /*!<  Outgoing handshake sequence number */
    unsigned int in_msg_seq;            /*!<  Incoming handshake sequence number */
    uint32_t retransmit_timeout;        /*!<  Current value of timeout       */
    unsigned char retransmit_state;     /*!<  Retransmission state           */
    mbedtls_ssl_flight_item *flight;    /*!<  Current outgoing flight        */
    mbedtls_ssl_flight_item *cur_msg;   /*!<  Current message in flight      */
    unsigned char *cur_msg_p;           /*!<  Position in current message    */
    unsigned int in_flight_start_seq;   /*!<  Minimum message sequence in the
                                              flight being received          */
    mbedtls_ssl_transform *alt_transform_out;   /*!<  Alternative transform for
                                              resending messages             */
    unsigned char alt_out_ctr[8];       /*!<  Alternative record epoch/counter
                                              for resending messages         */

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /* The state of CID configuration in this handshake. */

    uint8_t cid_in_use; /*!< This indicates whether the use of the CID extension
                         *   has been negotiated. Possible values are
                         *   #MBEDTLS_SSL_CID_ENABLED and
                         *   #MBEDTLS_SSL_CID_DISABLED. */
    unsigned char peer_cid[ MBEDTLS_SSL_CID_OUT_LEN_MAX ]; /*! The peer's CID */
    uint8_t peer_cid_len;                                  /*!< The length of
                                                            *   \c peer_cid.  */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    struct
    {
        size_t total_bytes_buffered; /*!< Cumulative size of heap allocated
                                      *   buffers used for message buffering. */

        uint8_t seen_ccs;               /*!< Indicates if a CCS message has
                                         *   been seen in the current flight. */

        struct mbedtls_ssl_hs_buffer
        {
            unsigned is_valid      : 1;
            unsigned is_fragmented : 1;
            unsigned is_complete   : 1;
            unsigned char *data;
            size_t data_len;
        } hs[MBEDTLS_SSL_MAX_BUFFERED_HS];

        struct
        {
            unsigned char *data;
            size_t len;
            unsigned epoch;
        } future_record;

    } buffering;

    uint16_t mtu;                       /*!<  Handshake mtu, used to fragment outgoing messages */
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    /*
     * Checksum contexts
     */
#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
    mbedtls_md5_context fin_md5;
    mbedtls_sha1_context fin_sha1;
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) || defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_hash_operation_t fin_sha256_psa;
#else
    mbedtls_sha256_context fin_sha256;
#endif
#endif
#if defined(MBEDTLS_SHA512_C)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_hash_operation_t fin_sha384_psa;
#else
    mbedtls_sha512_context fin_sha512;
#endif
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 || MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    void (*update_checksum)(mbedtls_ssl_context*, const unsigned char*, size_t);
    int (*calc_verify)(mbedtls_ssl_context*, unsigned char*, int);
    int(*calc_finished)(mbedtls_ssl_context*, unsigned char*, int);
#else
    void (*update_checksum)(mbedtls_ssl_context *, const unsigned char *, size_t);
    void (*calc_verify)(const mbedtls_ssl_context *, unsigned char *, size_t *);
    void (*calc_finished)(mbedtls_ssl_context *, unsigned char *, int);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

    mbedtls_ssl_tls_prf_cb *tls_prf;

   /* Buffer holding the digest up to, and including,
     * the Finished message sent by the server.
     */
    unsigned char server_finished_digest[MBEDTLS_MD_MAX_SIZE];

    /*
     * State-local variables used during the processing
     * of a specific handshake state.
     */
    union
    {
        /* Outgoing Finished message */
        struct
        {
            uint8_t preparation_done;

            /* Buffer holding digest of the handshake up to
             * but excluding the outgoing finished message. */
            unsigned char digest[MBEDTLS_MD_MAX_SIZE];
            size_t digest_len;
            mbedtls_ssl_key_set* traffic_keys;
        } finished_out;

        /* Incoming Finished message */
        struct
        {
            /* Buffer holding digest of the handshake up to but
             * excluding the peer's incoming finished message. */
            unsigned char digest[MBEDTLS_MD_MAX_SIZE];
            size_t digest_len;
        } finished_in;

#if defined(MBEDTLS_SSL_CLI_C)

        /* Client, incoming ServerKeyExchange */
        struct
        {
            uint8_t preparation_done;
        } srv_key_exchange;

        /* Client, incoming ServerHello */
        struct
        {
#if defined(MBEDTLS_SSL_RENEGOTIATION)
            int renego_info_seen;
#else
            int dummy;
#endif
        } srv_hello_in;

        /* Client, outgoing ClientKeyExchange */
        struct
        {
            uint8_t preparation_done;
        } cli_key_exch_out;

        /* Client, outgoing Certificate Verify */
        struct
        {
            uint8_t preparation_done;
        } crt_vrfy_out;

        /* Client, outgoing ClientHello */
        struct
        {
            uint8_t preparation_done;
        }  cli_hello_out;

#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)

        /* Server, outgoing ClientKeyExchange */
        struct
        {
            uint8_t preparation_done;
        } cli_key_exch_in;

#endif /* MBEDTLS_SSL_SRV_C */

        /* Incoming CertificateVerify */
        struct
        {
            unsigned char verify_buffer[ 64 + 33 + 1 + MBEDTLS_MD_MAX_SIZE ];
            size_t verify_buffer_len;
        } certificate_verify_in;

        /* Outgoing CertificateVerify */
        struct
        {
            unsigned char handshake_hash[ MBEDTLS_MD_MAX_SIZE ];
            size_t handshake_hash_len;
        } certificate_verify_out;

    } state_local;

    /* End of state-local variables. */


    mbedtls_ssl_ciphersuite_t const *ciphersuite_info;

    unsigned char randbytes[64];        /*!<  random bytes            */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#if defined(MBEDTLS_ECDSA_C)
    unsigned char certificate_request_context_len;
    unsigned char* certificate_request_context;
#endif

#if defined(MBEDTLS_ECDH_C)
    /* This is the actual key share list we sent.
     * The list configured by the application may
     * get modified via the server provided hint
     * using the HRR message.
     */
    mbedtls_ecp_group_id* key_shares_curve_list; /*!< curves to send as key shares */
#endif /* MBEDTLS_ECDH_C */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    // pointer to the pre_shared_key extension
    unsigned char* ptr_to_psk_ext;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

    unsigned char exporter_secret[MBEDTLS_MD_MAX_SIZE];
    unsigned char early_secret[MBEDTLS_MD_MAX_SIZE];
    unsigned char handshake_secret[MBEDTLS_MD_MAX_SIZE];
    unsigned char client_handshake_traffic_secret[MBEDTLS_MD_MAX_SIZE];
    unsigned char server_handshake_traffic_secret[MBEDTLS_MD_MAX_SIZE];
    unsigned char master_secret[MBEDTLS_MD_MAX_SIZE];
    unsigned char client_traffic_secret[MBEDTLS_MD_MAX_SIZE];
    unsigned char server_traffic_secret[MBEDTLS_MD_MAX_SIZE];
    unsigned char client_finished_key[MBEDTLS_MD_MAX_SIZE];
    unsigned char server_finished_key[MBEDTLS_MD_MAX_SIZE];

#if defined(MBEDTLS_ZERO_RTT)
    unsigned char binder_key[MBEDTLS_MD_MAX_SIZE];
    unsigned char client_early_traffic_secret[MBEDTLS_MD_MAX_SIZE];

    /*!< Early data indication:
    0  -- MBEDTLS_SSL_EARLY_DATA_DISABLED (for no early data), and
    1  -- MBEDTLS_SSL_EARLY_DATA_ENABLED (for use early data)
    */
    int early_data;
#endif /* MBEDTLS_ZERO_RTT */

#else
    size_t pmslen;                      /*!<  premaster length        */

    unsigned char premaster[MBEDTLS_PREMASTER_SIZE];
    /*!<  premaster secret        */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */


    int resume;                         /*!<  session resume indicator*/
    int max_major_ver;                  /*!< max. major version client*/
    int max_minor_ver;                  /*!< max. minor version client*/
    int cli_exts;                       /*!< client extension presence*/
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    int extensions_present;             /*!< which extension were present; the */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_SSL_TLS13_CTLS)
    uint8_t ctls; /* value of 1 indicates we are using ctls */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL && MBEDTLS_SSL_TLS13_CTLS */
#if (defined(MBEDTLS_SSL_SESSION_TICKETS) || (defined(MBEDTLS_SSL_NEW_SESSION_TICKET) && defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)))
    int new_session_ticket;             /*!< use NewSessionTicket?    */
#endif /* MBEDTLS_SSL_SESSION_TICKETS || ( MBEDTLS_SSL_NEW_SESSION_TICKET && MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL ) */
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    int extended_ms;                    /*!< use Extended Master Secret? */
#endif

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    unsigned int async_in_progress : 1; /*!< an asynchronous operation is in progress */
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    /** Asynchronous operation context. This field is meant for use by the
     * asynchronous operation callbacks (mbedtls_ssl_config::f_async_sign_start,
     * mbedtls_ssl_config::f_async_decrypt_start,
     * mbedtls_ssl_config::f_async_resume, mbedtls_ssl_config::f_async_cancel).
     * The library does not use it internally. */
    void *user_async_ctx;
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */
};

typedef struct mbedtls_ssl_hs_buffer mbedtls_ssl_hs_buffer;

/*
 * Representation of decryption/encryption transformations on records
 *
 * There are the following general types of record transformations:
 * - Stream transformations (TLS versions <= 1.2 only)
 *   Transformation adding a MAC and applying a stream-cipher
 *   to the authenticated message.
 * - CBC block cipher transformations ([D]TLS versions <= 1.2 only)
 *   In addition to the distinction of the order of encryption and
 *   authentication, there's a fundamental difference between the
 *   handling in SSL3 & TLS 1.0 and TLS 1.1 and TLS 1.2: For SSL3
 *   and TLS 1.0, the final IV after processing a record is used
 *   as the IV for the next record. No explicit IV is contained
 *   in an encrypted record. The IV for the first record is extracted
 *   at key extraction time. In contrast, for TLS 1.1 and 1.2, no
 *   IV is generated at key extraction time, but every encrypted
 *   record is explicitly prefixed by the IV with which it was encrypted.
 * - AEAD transformations ([D]TLS versions >= 1.2 only)
 *   These come in two fundamentally different versions, the first one
 *   used in TLS 1.2, excluding ChaChaPoly ciphersuites, and the second
 *   one used for ChaChaPoly ciphersuites in TLS 1.2 as well as for TLS 1.3.
 *   In the first transformation, the IV to be used for a record is obtained
 *   as the concatenation of an explicit, static 4-byte IV and the 8-byte
 *   record sequence number, and explicitly prepending this sequence number
 *   to the encrypted record. In contrast, in the second transformation
 *   the IV is obtained by XOR'ing a static IV obtained at key extraction
 *   time with the 8-byte record sequence number, without prepending the
 *   latter to the encrypted record.
 *
 * Additionally, DTLS 1.2 + CID as well as TLS 1.3 use an inner plaintext
 * which allows to add flexible length padding and to hide a record's true
 * content type.
 *
 * In addition to type and version, the following parameters are relevant:
 * - The symmetric cipher algorithm to be used.
 * - The (static) encryption/decryption keys for the cipher.
 * - For stream/CBC, the type of message digest to be used.
 * - For stream/CBC, (static) encryption/decryption keys for the digest.
 * - For AEAD transformations, the size (potentially 0) of an explicit,
 *   random initialization vector placed in encrypted records.
 * - For some transformations (currently AEAD and CBC in SSL3 and TLS 1.0)
 *   an implicit IV. It may be static (e.g. AEAD) or dynamic (e.g. CBC)
 *   and (if present) is combined with the explicit IV in a transformation-
 *   dependent way (e.g. appending in TLS 1.2 and XOR'ing in TLS 1.3).
 * - For stream/CBC, a flag determining the order of encryption and MAC.
 * - The details of the transformation depend on the SSL/TLS version.
 * - The length of the authentication tag.
 *
 * Note: Except for CBC in SSL3 and TLS 1.0, these parameters are
 *       constant across multiple encryption/decryption operations.
 *       For CBC, the implicit IV needs to be updated after each
 *       operation.
 *
 * The struct below refines this abstract view as follows:
 * - The cipher underlying the transformation is managed in
 *   cipher contexts cipher_ctx_{enc/dec}, which must have the
 *   same cipher type. The mode of these cipher contexts determines
 *   the type of the transformation in the sense above: e.g., if
 *   the type is MBEDTLS_CIPHER_AES_256_CBC resp. MBEDTLS_CIPHER_AES_192_GCM
 *   then the transformation has type CBC resp. AEAD.
 * - The cipher keys are never stored explicitly but
 *   are maintained within cipher_ctx_{enc/dec}.
 * - For stream/CBC transformations, the message digest contexts
 *   used for the MAC's are stored in md_ctx_{enc/dec}. These contexts
 *   are unused for AEAD transformations.
 * - For stream/CBC transformations and versions > SSL3, the
 *   MAC keys are not stored explicitly but maintained within
 *   md_ctx_{enc/dec}.
 * - For stream/CBC transformations and version SSL3, the MAC
 *   keys are stored explicitly in mac_enc, mac_dec and have
 *   a fixed size of 20 bytes. These fields are unused for
 *   AEAD transformations or transformations >= TLS 1.0.
 * - For transformations using an implicit IV maintained within
 *   the transformation context, its contents are stored within
 *   iv_{enc/dec}.
 * - The value of ivlen indicates the length of the IV.
 *   This is redundant in case of stream/CBC transformations
 *   which always use 0 resp. the cipher's block length as the
 *   IV length, but is needed for AEAD ciphers and may be
 *   different from the underlying cipher's block length
 *   in this case.
 * - The field fixed_ivlen is nonzero for AEAD transformations only
 *   and indicates the length of the static part of the IV which is
 *   constant throughout the communication, and which is stored in
 *   the first fixed_ivlen bytes of the iv_{enc/dec} arrays.
 *   Note: For CBC in SSL3 and TLS 1.0, the fields iv_{enc/dec}
 *   still store IV's for continued use across multiple transformations,
 *   so it is not true that fixed_ivlen == 0 means that iv_{enc/dec} are
 *   not being used!
 * - minor_ver denotes the SSL/TLS version
 * - For stream/CBC transformations, maclen denotes the length of the
 *   authentication tag, while taglen is unused and 0.
 * - For AEAD transformations, taglen denotes the length of the
 *   authentication tag, while maclen is unused and 0.
 * - For CBC transformations, encrypt_then_mac determines the
 *   order of encryption and authentication. This field is unused
 *   in other transformations.
 *
 */
struct mbedtls_ssl_transform
{
    /*
     * Session specific crypto layer
     */
    size_t minlen;                      /*!<  min. ciphertext length  */
    size_t ivlen;                       /*!<  IV length               */
    size_t fixed_ivlen;                 /*!<  Fixed part of IV (AEAD) */
    size_t maclen;                      /*!<  MAC(CBC) len            */
    size_t taglen;                      /*!<  TAG(AEAD) len           */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    /*!<  Chosen cipersuite_info  */
    unsigned int keylen;                /*!<  symmetric key length (bytes)  */

    mbedtls_ssl_key_set traffic_keys;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    mbedtls_ssl_key_set traffic_keys_previous;
#endif /* MBEDTL_SSL_PROTO_DTLS */

    unsigned char sequence_number_dec[12]; /* sequence number for incoming (decrypting) traffic */
    unsigned char sequence_number_enc[12]; /* sequence number for outgoing (encrypting) traffic */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

    unsigned char iv_enc[ MBEDTLS_MAX_IV_LENGTH ];           /*!<  IV (encryption)         */
    unsigned char iv_dec[ MBEDTLS_MAX_IV_LENGTH ];           /*!<  IV (decryption)         */
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)

#if defined(MBEDTLS_SSL_PROTO_SSL3)
    /* Needed only for SSL v3.0 secret */
    unsigned char mac_enc[20];          /*!<  SSL v3.0 secret (enc)   */
    unsigned char mac_dec[20];          /*!<  SSL v3.0 secret (dec)   */
#endif /* MBEDTLS_SSL_PROTO_SSL3 */

    mbedtls_md_context_t md_ctx_enc;            /*!<  MAC (encryption)        */
    mbedtls_md_context_t md_ctx_dec;            /*!<  MAC (decryption)        */

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    int encrypt_then_mac;       /*!< flag for EtM activation                */
#endif

#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */

    mbedtls_cipher_context_t cipher_ctx_enc;    /*!<  encryption context      */
    mbedtls_cipher_context_t cipher_ctx_dec;    /*!<  decryption context      */
    int minor_ver;

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    uint8_t in_cid_len;
    uint8_t out_cid_len;
    unsigned char in_cid [ MBEDTLS_SSL_CID_OUT_LEN_MAX ];
    unsigned char out_cid[ MBEDTLS_SSL_CID_OUT_LEN_MAX ];
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    /*
     * Session specific compression layer
     */
#if defined(MBEDTLS_ZLIB_SUPPORT)
    z_stream ctx_deflate;               /*!<  compression context     */
    z_stream ctx_inflate;               /*!<  decompression context   */
#endif

#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    /* We need the Hello random bytes in order to re-derive keys from the
     * Master Secret and other session info, see ssl_populate_transform() */
    unsigned char randbytes[64]; /*!< ServerHello.random+ClientHello.random */
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */
};

/*
 * Return 1 if the transform uses an AEAD cipher, 0 otherwise.
 * Equivalently, return 0 if a separate MAC is used, 1 otherwise.
 */
static inline int mbedtls_ssl_transform_uses_aead(
        const mbedtls_ssl_transform *transform )
{
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    return( transform->maclen == 0 && transform->taglen != 0 );
#else
    (void) transform;
    return( 1 );
#endif
}

/*
 * Internal representation of record frames
 *
 * Instances come in two flavors:
 * (1) Encrypted
 *     These always have data_offset = 0
 * (2) Unencrypted
 *     These have data_offset set to the amount of
 *     pre-expansion during record protection. Concretely,
 *     this is the length of the fixed part of the explicit IV
 *     used for encryption, or 0 if no explicit IV is used
 *     (e.g. for CBC in TLS 1.0, or stream ciphers).
 *
 * The reason for the data_offset in the unencrypted case
 * is to allow for in-place conversion of an unencrypted to
 * an encrypted record. If the offset wasn't included, the
 * encrypted content would need to be shifted afterwards to
 * make space for the fixed IV.
 *
 */
#if MBEDTLS_SSL_CID_OUT_LEN_MAX > MBEDTLS_SSL_CID_IN_LEN_MAX
#define MBEDTLS_SSL_CID_LEN_MAX MBEDTLS_SSL_CID_OUT_LEN_MAX
#else
#define MBEDTLS_SSL_CID_LEN_MAX MBEDTLS_SSL_CID_IN_LEN_MAX
#endif

typedef struct
{
    uint8_t ctr[8];         /* In TLS:  The implicit record sequence number.
                             * In DTLS: The 2-byte epoch followed by
                             *          the 6-byte sequence number.
                             * This is stored as a raw big endian byte array
                             * as opposed to a uint64_t because we rarely
                             * need to perform arithmetic on this, but do
                             * need it as a Byte array for the purpose of
                             * MAC computations.                             */
    uint8_t type;           /* The record content type.                      */
    uint8_t ver[2];         /* SSL/TLS version as present on the wire.
                             * Convert to internal presentation of versions
                             * using mbedtls_ssl_read_version() and
                             * mbedtls_ssl_write_version().
                             * Keep wire-format for MAC computations.        */

    unsigned char *buf;     /* Memory buffer enclosing the record content    */
    size_t buf_len;         /* Buffer length                                 */
    size_t data_offset;     /* Offset of record content                      */
    size_t data_len;        /* Length of record content                      */

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    uint8_t cid_len;        /* Length of the CID (0 if not present)          */
    unsigned char cid[ MBEDTLS_SSL_CID_LEN_MAX ]; /* The CID                 */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
} mbedtls_record;

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/*
 * List of certificate + private key pairs
 */
struct mbedtls_ssl_key_cert
{
    mbedtls_x509_crt *cert;                 /*!< cert                       */
    mbedtls_pk_context *key;                /*!< private key                */
    mbedtls_ssl_key_cert *next;             /*!< next key/cert pair         */
};
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
/*
 * List of handshake messages kept around for resending
 */
struct mbedtls_ssl_flight_item
{
    unsigned char *p;       /*!< message, including handshake headers   */
    size_t len;             /*!< length of p                            */
    unsigned char type;     /*!< type of the message: handshake or CCS  */
    mbedtls_ssl_flight_item *next;  /*!< next handshake message(s)              */
};
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

/* Find an entry in a signature-hash set matching a given hash algorithm. */
mbedtls_md_type_t mbedtls_ssl_sig_hash_set_find( mbedtls_ssl_sig_hash_set_t *set,
                                                 mbedtls_pk_type_t sig_alg );
/* Add a signature-hash-pair to a signature-hash set */
void mbedtls_ssl_sig_hash_set_add( mbedtls_ssl_sig_hash_set_t *set,
                                   mbedtls_pk_type_t sig_alg,
                                   mbedtls_md_type_t md_alg );
/* Allow exactly one hash algorithm for each signature. */
void mbedtls_ssl_sig_hash_set_const_hash( mbedtls_ssl_sig_hash_set_t *set,
                                          mbedtls_md_type_t md_alg );

/* Setup an empty signature-hash set */
static inline void mbedtls_ssl_sig_hash_set_init( mbedtls_ssl_sig_hash_set_t *set )
{
    mbedtls_ssl_sig_hash_set_const_hash( set, MBEDTLS_MD_NONE );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_2) &&
          MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/**
 * \brief           Free referenced items in an SSL transform context and clear
 *                  memory
 *
 * \param transform SSL transform context
 */
void mbedtls_ssl_transform_free( mbedtls_ssl_transform *transform );

/**
 * \brief           Free referenced items in an SSL handshake context and clear
 *                  memory
 *
 * \param ssl       SSL context
 */

void mbedtls_ssl_handshake_free( mbedtls_ssl_context *ssl );

int mbedtls_ssl_handshake_client_step( mbedtls_ssl_context *ssl );
int mbedtls_ssl_handshake_server_step( mbedtls_ssl_context *ssl );
void mbedtls_ssl_handshake_wrapup( mbedtls_ssl_context *ssl );

int mbedtls_ssl_handle_pending_alert( mbedtls_ssl_context *ssl );

int mbedtls_ssl_send_fatal_handshake_failure( mbedtls_ssl_context *ssl );

void mbedtls_ssl_reset_checksum( mbedtls_ssl_context *ssl );
int mbedtls_ssl_derive_keys( mbedtls_ssl_context *ssl );

int mbedtls_ssl_handle_message_type( mbedtls_ssl_context *ssl );
int mbedtls_ssl_prepare_handshake_record( mbedtls_ssl_context *ssl );
void mbedtls_ssl_update_handshake_status( mbedtls_ssl_context *ssl );

/**
 * \brief       Update record layer
 *
 *              This function roughly separates the implementation
 *              of the logic of (D)TLS from the implementation
 *              of the secure transport.
 *
 * \param  ssl              The SSL context to use.
 * \param  update_hs_digest This indicates if the handshake digest
 *                          should be automatically updated in case
 *                          a handshake message is found.
 *
 * \return      0 or non-zero error code.
 *
 * \note        A clarification on what is called 'record layer' here
 *              is in order, as many sensible definitions are possible:
 *
 *              The record layer takes as input an untrusted underlying
 *              transport (stream or datagram) and transforms it into
 *              a serially multiplexed, secure transport, which
 *              conceptually provides the following:
 *
 *              (1) Three datagram based, content-agnostic transports
 *                  for handshake, alert and CCS messages.
 *              (2) One stream- or datagram-based transport
 *                  for application data.
 *              (3) Functionality for changing the underlying transform
 *                  securing the contents.
 *
 *              The interface to this functionality is given as follows:
 *
 *              a Updating
 *                [Currently implemented by mbedtls_ssl_read_record]
 *
 *                Check if and on which of the four 'ports' data is pending:
 *                Nothing, a controlling datagram of type (1), or application
 *                data (2). In any case data is present, internal buffers
 *                provide access to the data for the user to process it.
 *                Consumption of type (1) datagrams is done automatically
 *                on the next update, invalidating that the internal buffers
 *                for previous datagrams, while consumption of application
 *                data (2) is user-controlled.
 *
 *              b Reading of application data
 *                [Currently manual adaption of ssl->in_offt pointer]
 *
 *                As mentioned in the last paragraph, consumption of data
 *                is different from the automatic consumption of control
 *                datagrams (1) because application data is treated as a stream.
 *
 *              c Tracking availability of application data
 *                [Currently manually through decreasing ssl->in_msglen]
 *
 *                For efficiency and to retain datagram semantics for
 *                application data in case of DTLS, the record layer
 *                provides functionality for checking how much application
 *                data is still available in the internal buffer.
 *
 *              d Changing the transformation securing the communication.
 *
 *              Given an opaque implementation of the record layer in the
 *              above sense, it should be possible to implement the logic
 *              of (D)TLS on top of it without the need to know anything
 *              about the record layer's internals. This is done e.g.
 *              in all the handshake handling functions, and in the
 *              application data reading function mbedtls_ssl_read.
 *
 * \note        The above tries to give a conceptual picture of the
 *              record layer, but the current implementation deviates
 *              from it in some places. For example, our implementation of
 *              the update functionality through mbedtls_ssl_read_record
 *              discards datagrams depending on the current state, which
 *              wouldn't fall under the record layer's responsibility
 *              following the above definition.
 *
 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

int mbedtls_ssl_read_record(mbedtls_ssl_context* ssl);
int mbedtls_ssl_fetch_input(mbedtls_ssl_context* ssl, size_t nb_want);

int mbedtls_ssl_write_record(mbedtls_ssl_context* ssl);
int mbedtls_ssl_flush_output(mbedtls_ssl_context* ssl);


int mbedtls_ssl_handshake_client_step(mbedtls_ssl_context* ssl);
int mbedtls_ssl_handshake_server_step(mbedtls_ssl_context* ssl);
void mbedtls_ssl_handshake_wrapup(mbedtls_ssl_context* ssl);

int mbedtls_ssl_send_fatal_handshake_failure(mbedtls_ssl_context* ssl);

#else
int mbedtls_ssl_read_record( mbedtls_ssl_context *ssl,
                             unsigned update_hs_digest );
int mbedtls_ssl_fetch_input( mbedtls_ssl_context *ssl, size_t nb_want );

int mbedtls_ssl_write_handshake_msg( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_record( mbedtls_ssl_context *ssl, uint8_t force_flush );
int mbedtls_ssl_flush_output( mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */


#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
int mbedtls_ssl_read_certificate_process(mbedtls_ssl_context* ssl);
int mbedtls_ssl_write_certificate_process(mbedtls_ssl_context* ssl);
#else
int mbedtls_ssl_parse_certificate( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_certificate( mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
int mbedtls_ssl_write_change_cipher_spec_process( mbedtls_ssl_context* ssl );
#else
int mbedtls_ssl_parse_change_cipher_spec( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_change_cipher_spec( mbedtls_ssl_context *ssl );
#endif  /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL && MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
int mbedtls_ssl_finished_in_process(mbedtls_ssl_context* ssl);
int mbedtls_ssl_finished_out_process(mbedtls_ssl_context* ssl);
#else
int mbedtls_ssl_parse_finished( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_finished( mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
int mbedtls_ssl_new_session_ticket_process(mbedtls_ssl_context* ssl);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */


#if defined(MBEDTLS_SSL_TLS13_CTLS)
static enum varint_length_enum set_varint_length(uint32_t input, uint32_t* output);
static uint8_t get_varint_length(const uint8_t input);
static uint32_t get_varint_value(const uint32_t input);
#endif /* MBEDTLS_SSL_TLS13_CTLS */


int mbedtls_ssl_key_derivation(mbedtls_ssl_context* ssl, mbedtls_ssl_key_set* traffic_keys);


#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
int mbedtls_ssl_read_certificate_verify_process(mbedtls_ssl_context* ssl);
int mbedtls_ssl_certificate_verify_process(mbedtls_ssl_context* ssl);

int mbedtls_ssl_tls1_3_derive_master_secret(mbedtls_ssl_context* ssl);
int mbedtls_set_traffic_key(mbedtls_ssl_context* ssl, mbedtls_ssl_key_set* traffic_keys, mbedtls_ssl_transform* transform, int mode);
int mbedtls_ssl_generate_application_traffic_keys(mbedtls_ssl_context* ssl, mbedtls_ssl_key_set* traffic_keys);
int mbedtls_ssl_generate_resumption_master_secret(mbedtls_ssl_context* ssl);
int mbedtls_ssl_write_encrypted_extension(mbedtls_ssl_context* ssl);
int mbedtls_ssl_derive_traffic_keys(mbedtls_ssl_context* ssl, mbedtls_ssl_key_set* traffic_keys);
int mbedtls_increment_sequence_number(unsigned char* sequenceNumber, unsigned char* nonce, size_t ivlen);

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
int mbedtls_ssl_write_change_cipher_spec(mbedtls_ssl_context* ssl);
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int mbedtls_ssl_write_pre_shared_key_ext(mbedtls_ssl_context* ssl, unsigned char* buf, unsigned char* end, size_t* olen, int dummy_run);
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
int mbedtls_ssl_write_signature_algorithms_ext(mbedtls_ssl_context* ssl, unsigned char* buf, unsigned char* end, size_t* olen);
int mbedtls_ssl_parse_signature_algorithms_ext(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len);
int mbedtls_ssl_check_signature_scheme(const mbedtls_ssl_context* ssl, int signature_scheme);
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_ZERO_RTT)
int mbedtls_ssl_early_data_key_derivation(mbedtls_ssl_context* ssl, mbedtls_ssl_key_set* traffic_keys);
int mbedtls_ssl_write_early_data_ext(mbedtls_ssl_context* ssl, unsigned char* buf, size_t buflen, size_t* olen);
#endif /* MBEDTLS_ZERO_RTT */
#if (defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C))
int mbedtls_ssl_parse_supported_groups_ext(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len);
#endif /* MBEDTLS_ECDH_C ||  MBEDTLS_ECDSA_C */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int mbedtls_ssl_create_binder(mbedtls_ssl_context* ssl, unsigned char* psk, size_t psk_len, const mbedtls_md_info_t* md, const mbedtls_ssl_ciphersuite_t* suite_info, unsigned char* buffer, size_t blen, unsigned char* result);
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
int mbedtls_ssl_parse_new_session_ticket_server(mbedtls_ssl_context* ssl, unsigned char* buf, size_t len, mbedtls_ssl_ticket* ticket);
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int mbedtls_ssl_parse_client_psk_identity_ext(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len);
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
#define MBEDTLS_SSL_ACK_RECORDS_SENT 0
#define MBEDTLS_SSL_ACK_RECORDS_RECEIVED 1
int mbedtls_ssl_parse_ack(mbedtls_ssl_context* ssl);
int mbedtls_ssl_write_ack(mbedtls_ssl_context* ssl);
void mbedtls_ack_clear_all(mbedtls_ssl_context* ssl, int mode);
int mbedtls_ack_add_record(mbedtls_ssl_context* ssl, uint8_t record, int mode);
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */


void mbedtls_ssl_optimize_checksum( mbedtls_ssl_context *ssl,
                            const mbedtls_ssl_ciphersuite_t *ciphersuite_info );

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int mbedtls_ssl_psk_derive_premaster( mbedtls_ssl_context *ssl, mbedtls_key_exchange_type_t key_ex );

/**
 * Get the first properly defined PSK by order of precedence:
 * 1. handshake PSK set by \c mbedtls_ssl_set_hs_psk() in the PSK callback
 * 2. static PSK configured by \c mbedtls_ssl_conf_psk()
 * Update the pair (PSK, PSK length) passed to the function if they're not null.
 * Return whether any PSK was found
 */
static inline int mbedtls_ssl_get_psk( const mbedtls_ssl_context *ssl,
    const unsigned char **psk, size_t *psk_len )
{
    if( ssl->handshake->psk != NULL && ssl->handshake->psk_len > 0 )
    {
        if( psk != NULL && psk_len != NULL )
        {
            *psk = ssl->handshake->psk;
            *psk_len = ssl->handshake->psk_len;
        }
    }

    else if( ssl->conf->psk != NULL && ssl->conf->psk_len > 0 &&
             ssl->conf->psk_identity != NULL && ssl->conf->psk_identity_len > 0)
    {
        if( psk != NULL && psk_len != NULL )
        {
            *psk = ssl->conf->psk;
            *psk_len = ssl->conf->psk_len;
        }
    }

    else
    {
        if( psk != NULL && psk_len != NULL )
        {
            *psk = NULL;
            *psk_len = 0;
        }
        return( MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED );
    }

    return( 0 );
}

#if defined(MBEDTLS_USE_PSA_CRYPTO)
/**
 * Get the first defined opaque PSK by order of precedence:
 * 1. handshake PSK set by \c mbedtls_ssl_set_hs_psk_opaque() in the PSK
 *    callback
 * 2. static PSK configured by \c mbedtls_ssl_conf_psk_opaque()
 * Return an opaque PSK
 */
static inline psa_key_id_t mbedtls_ssl_get_opaque_psk(
    const mbedtls_ssl_context *ssl )
{
    if( ! mbedtls_svc_key_id_is_null( ssl->handshake->psk_opaque ) )
        return( ssl->handshake->psk_opaque );

    if( ! mbedtls_svc_key_id_is_null( ssl->conf->psk_opaque ) )
        return( ssl->conf->psk_opaque );

    return( MBEDTLS_SVC_KEY_ID_INIT );
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_PK_C)
unsigned char mbedtls_ssl_sig_from_pk( mbedtls_pk_context *pk );
unsigned char mbedtls_ssl_sig_from_pk_alg( mbedtls_pk_type_t type );
mbedtls_pk_type_t mbedtls_ssl_pk_alg_from_sig( unsigned char sig );
#endif

mbedtls_md_type_t mbedtls_ssl_md_alg_from_hash( unsigned char hash );
unsigned char mbedtls_ssl_hash_from_md_alg( int md );
int mbedtls_ssl_set_calc_verify_md( mbedtls_ssl_context *ssl, int md );

#if defined(MBEDTLS_ECP_C)
int mbedtls_ssl_check_curve( const mbedtls_ssl_context *ssl, mbedtls_ecp_group_id grp_id );
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
int mbedtls_ssl_check_sig_hash( const mbedtls_ssl_context *ssl,
                                mbedtls_md_type_t md );
#endif

#if defined(MBEDTLS_SSL_DTLS_SRTP)
static inline mbedtls_ssl_srtp_profile mbedtls_ssl_check_srtp_profile_value
                                                    ( const uint16_t srtp_profile_value )
{
    switch( srtp_profile_value )
    {
        case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80:
        case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32:
        case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80:
        case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32:
            return srtp_profile_value;
        default: break;
    }
    return( MBEDTLS_TLS_SRTP_UNSET );
}
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static inline mbedtls_pk_context *mbedtls_ssl_own_key( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_key_cert *key_cert;

    if( ssl->handshake != NULL && ssl->handshake->key_cert != NULL )
        key_cert = ssl->handshake->key_cert;
    else
        key_cert = ssl->conf->key_cert;

    return( key_cert == NULL ? NULL : key_cert->key );
}

static inline mbedtls_x509_crt *mbedtls_ssl_own_cert( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_key_cert *key_cert;

    if( ssl->handshake != NULL && ssl->handshake->key_cert != NULL )
        key_cert = ssl->handshake->key_cert;
    else
        key_cert = ssl->conf->key_cert;

    return( key_cert == NULL ? NULL : key_cert->cert );
}

/*
 * Check usage of a certificate wrt extensions:
 * keyUsage, extendedKeyUsage (later), and nSCertType (later).
 *
 * Warning: cert_endpoint is the endpoint of the cert (ie, of our peer when we
 * check a cert we received from them)!
 *
 * Return 0 if everything is OK, -1 if not.
 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
int mbedtls_ssl_check_cert_usage(const mbedtls_x509_crt* cert,
    const mbedtls_key_exchange_type_t key_exchange,
    int cert_endpoint,
    uint32_t* flags);
#else
int mbedtls_ssl_check_cert_usage( const mbedtls_x509_crt *cert,
                          const mbedtls_ssl_ciphersuite_t *ciphersuite,
                          int cert_endpoint,
                          uint32_t *flags );
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#endif /* MBEDTLS_X509_CRT_PARSE_C */

void mbedtls_ssl_write_version( int major, int minor, int transport,
                        unsigned char ver[2] );
void mbedtls_ssl_read_version( int *major, int *minor, int transport,
                       const unsigned char ver[2] );


#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
static inline size_t mbedtls_ssl_hdr_len(const mbedtls_ssl_context* ssl, const int direction, mbedtls_ssl_transform* transform)
{
#if !defined(MBEDTLS_CID)
    ((void) direction);
#endif /* MBEDTLS_CID */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {

        int len;

        /* We are dealing with a plaintext DTLS 1.3 packet if transform is NULL */
        if (transform == NULL)  return(13);

        /* If the DTLS 1.3 packet is encrypted then we need to deterine the header size.
         * For the moment we assumed a 16-bit sequence number and that the length field
         * is included in the payload.
         */
        len = 1 /* unified header */ + 2 /* sequence number */ + 2 /* length */;

        /* Check whether it includes a CID */
#if defined(MBEDTLS_CID)
        if (direction == MBEDTLS_SSL_DIRECTION_OUT)
            len += ssl->out_cid_len;
        else
            len += ssl->in_cid_len;
#endif /* MBEDTLS_CID */
        return (len);
    }
    else
#else
    {
        ((void)transform);
        ((void)ssl);
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    return(5); /* TLS 1.3 header */
}
#else
static inline size_t mbedtls_ssl_hdr_len(const mbedtls_ssl_context* ssl)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return(13);
    }
#else
    ((void)ssl);
#endif
    return(5);
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

static inline size_t mbedtls_ssl_in_hdr_len( const mbedtls_ssl_context *ssl )
{
#if !defined(MBEDTLS_SSL_PROTO_DTLS)
    ((void) ssl);
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        return( 13 );
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        return( 5 );
    }
}

static inline size_t mbedtls_ssl_out_hdr_len( const mbedtls_ssl_context *ssl )
{
    return( (size_t) ( ssl->out_iv - ssl->out_hdr ) );
}

static inline size_t mbedtls_ssl_hs_hdr_len( const mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        return( 12 );
#else
    ((void) ssl);
#endif
    return( 4 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
void mbedtls_ssl_send_flight_completed( mbedtls_ssl_context *ssl );
void mbedtls_ssl_recv_flight_completed( mbedtls_ssl_context *ssl );
int mbedtls_ssl_resend( mbedtls_ssl_context *ssl );
int mbedtls_ssl_flight_transmit( mbedtls_ssl_context *ssl );
#endif


#if defined(MBEDTLS_CID)
int mbedtls_ssl_parse_cid_ext(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len);
void mbedtls_ssl_write_cid_ext(mbedtls_ssl_context* ssl, unsigned char* buf, size_t* olen);
#endif /* MBEDTLS_CID */

/* Visible for testing purposes only */
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
int mbedtls_ssl_dtls_replay_check( mbedtls_ssl_context const *ssl );
void mbedtls_ssl_dtls_replay_update( mbedtls_ssl_context *ssl );
#endif

static inline void mbedtls_ssl_handshake_set_state(mbedtls_ssl_context* ssl,
    int state)
{
    ssl->state = state;

    /* Note:
     * This only works as long as all state-local struct members
     * of mbedtls_ssl_hanshake_params::state_local can be initialized
     * through zeroization.
     * Exceptions must be manually checked for here.
     */
    if (state != MBEDTLS_SSL_HANDSHAKE_WRAPUP &&
        state != MBEDTLS_SSL_HANDSHAKE_OVER &&
        state != MBEDTLS_SSL_FLUSH_BUFFERS)
    {
        mbedtls_platform_zeroize(&ssl->handshake->state_local, sizeof(ssl->handshake->state_local));
    }
}

int mbedtls_ssl_session_copy( mbedtls_ssl_session *dst,
                              const mbedtls_ssl_session *src );

/* constant-time buffer comparison */
static inline int mbedtls_ssl_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    volatile unsigned char diff = 0;

    for( i = 0; i < n; i++ )
    {
        /* Read volatile data in order before computing diff.
         * This avoids IAR compiler warning:
         * 'the order of volatile accesses is undefined ..' */
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }

    return( diff );
}

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
int mbedtls_ssl_get_key_exchange_md_ssl_tls( mbedtls_ssl_context *ssl,
                                        unsigned char *output,
                                        unsigned char *data, size_t data_len );
#endif /* MBEDTLS_SSL_PROTO_SSL3 || MBEDTLS_SSL_PROTO_TLS1 || \
          MBEDTLS_SSL_PROTO_TLS1_1 */

#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
/* The hash buffer must have at least MBEDTLS_MD_MAX_SIZE bytes of length. */
int mbedtls_ssl_get_key_exchange_md_tls1_2( mbedtls_ssl_context *ssl,
                                            unsigned char *hash, size_t *hashlen,
                                            unsigned char *data, size_t data_len,
                                            mbedtls_md_type_t md_alg );
#endif /* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 || \
          MBEDTLS_SSL_PROTO_TLS1_2 */

#ifdef __cplusplus
}
#endif

void mbedtls_ssl_transform_init( mbedtls_ssl_transform *transform );
int mbedtls_ssl_encrypt_buf( mbedtls_ssl_context *ssl,
                             mbedtls_ssl_transform *transform,
                             mbedtls_record *rec,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng );
int mbedtls_ssl_decrypt_buf( mbedtls_ssl_context const *ssl,
                             mbedtls_ssl_transform *transform,
                             mbedtls_record *rec );

/* Length of the "epoch" field in the record header */
static inline size_t mbedtls_ssl_ep_len( const mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        return( 2 );
#else
    ((void) ssl);
#endif
    return( 0 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
int mbedtls_ssl_resend_hello_request( mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

void mbedtls_ssl_set_timer( mbedtls_ssl_context *ssl, uint32_t millisecs );

int mbedtls_ssl_check_timer( mbedtls_ssl_context *ssl );

void mbedtls_ssl_reset_in_out_pointers( mbedtls_ssl_context *ssl );
void mbedtls_ssl_update_out_pointers( mbedtls_ssl_context *ssl,
                              mbedtls_ssl_transform *transform );
void mbedtls_ssl_update_in_pointers( mbedtls_ssl_context *ssl );

int mbedtls_ssl_session_reset_int( mbedtls_ssl_context *ssl, int partial );

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
void mbedtls_ssl_dtls_replay_reset( mbedtls_ssl_context *ssl );
#endif

void mbedtls_ssl_handshake_wrapup_free_hs_transform( mbedtls_ssl_context *ssl );

#if defined(MBEDTLS_SSL_RENEGOTIATION)
int mbedtls_ssl_start_renegotiation( mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_SSL_RENEGOTIATION */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
size_t mbedtls_ssl_get_current_mtu( const mbedtls_ssl_context *ssl );
void mbedtls_ssl_buffering_free( mbedtls_ssl_context *ssl );
void mbedtls_ssl_flight_free( mbedtls_ssl_flight_item *flight );

int mbedtls_ssl_double_retransmit_timeout( mbedtls_ssl_context *ssl );
void mbedtls_ssl_reset_retransmit_timeout( mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#define MBEDTLS_SSL_TLS1_3_LABEL_LIST                                   \
    const unsigned char finished    [ sizeof("finished")     - 1 ];     \
    const unsigned char resumption  [ sizeof("resumption")   - 1 ];     \
    const unsigned char traffic_upd [ sizeof("traffic upd")  - 1 ];     \
    const unsigned char export      [ sizeof("exporter")     - 1 ];     \
    const unsigned char key         [ sizeof("key")          - 1 ];     \
    const unsigned char iv          [ sizeof("iv")           - 1 ];     \
    const unsigned char sn          [ sizeof("sn")           - 1 ];     \
    const unsigned char c_hs_traffic[ sizeof("c hs traffic") - 1 ];     \
    const unsigned char c_ap_traffic[ sizeof("c ap traffic") - 1 ];     \
    const unsigned char c_e_traffic [ sizeof("c e traffic")  - 1 ];     \
    const unsigned char s_hs_traffic[ sizeof("s hs traffic") - 1 ];     \
    const unsigned char s_ap_traffic[ sizeof("s ap traffic") - 1 ];     \
    const unsigned char s_e_traffic [ sizeof("s e traffic")  - 1 ];     \
    const unsigned char exp_master  [ sizeof("exp master")   - 1 ];     \
    const unsigned char res_master  [ sizeof("res master")   - 1 ];     \
    const unsigned char ext_binder  [ sizeof("ext binder")   - 1 ];     \
    const unsigned char res_binder  [ sizeof("res binder")   - 1 ];     \
    const unsigned char derived     [ sizeof("derived")      - 1 ];     \

union mbedtls_ssl_tls1_3_labels_union
{
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
struct mbedtls_ssl_tls1_3_labels_struct
{
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
extern const struct mbedtls_ssl_tls1_3_labels_struct mbedtls_ssl_tls1_3_labels;

#define MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( LABEL )  \
    mbedtls_ssl_tls1_3_labels.LABEL,              \
    sizeof(mbedtls_ssl_tls1_3_labels.LABEL)

#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN  \
    sizeof( union mbedtls_ssl_tls1_3_labels_union )

/* The maximum length of HKDF contexts used in the TLS 1.3 standad.
 * Since contexts are always hashes of message transcripts, this can
 * be approximated from above by the maximum hash size. */
#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN  \
    MBEDTLS_MD_MAX_SIZE

/* Maximum desired length for expanded key material generated
 * by HKDF-Expand-Label. */
#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN 255

/**
 * \brief           This function is part of the TLS 1.3 key schedule.
 *                  It extracts key and IV for the actual client/server traffic
 *                  from the client/server traffic secrets.
 *
 * From RFC 8446:
 *
 * <tt>
 *   [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
 *   [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)*
 * </tt>
 *
 * \param hash_alg      The identifier for the hash algorithm to be used
 *                      for the HKDF-based expansion of the secret.
 * \param client_secret The client traffic secret.
 *                      This must be a readable buffer of size \p slen Bytes
 * \param server_secret The server traffic secret.
 *                      This must be a readable buffer of size \p slen Bytes
 * \param slen          Length of the secrets \p client_secret and
 *                      \p server_secret in Bytes.
 * \param key_len       The desired length of the key to be extracted in Bytes.
 * \param iv_len        The desired length of the IV to be extracted in Bytes.
 * \param keys          The address of the structure holding the generated
 *                      keys and IVs.
 *
 * \returns             \c 0 on success.
 * \returns             A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_secret,
                     const unsigned char *server_secret,
                     size_t slen, size_t key_len, size_t iv_len,
                     mbedtls_ssl_key_set *keys );

/**
 * \brief           The \c HKDF-Expand-Label function from
 *                  the TLS 1.3 standard RFC 8446.
 *
 * <tt>
 *                  HKDF-Expand-Label( Secret, Label, Context, Length ) =
 *                       HKDF-Expand( Secret, HkdfLabel, Length )
 * </tt>
 *
 * \param hash_alg  The identifier for the hash algorithm to use.
 * \param secret    The \c Secret argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p slen Bytes.
 * \param slen      The length of \p secret in Bytes.
 * \param label     The \c Label argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p llen Bytes.
 * \param llen      The length of \p label in Bytes.
 * \param ctx       The \c Context argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p clen Bytes.
 * \param clen      The length of \p context in Bytes.
 * \param buf       The destination buffer to hold the expanded secret.
 *                  This must be a writable buffe of length \p blen Bytes.
 * \param blen      The desired size of the expanded secret in Bytes.
 *
 * \returns         \c 0 on success.
 * \return          A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t slen,
                     const unsigned char *label, size_t llen,
                     const unsigned char *ctx, size_t clen,
                     unsigned char *buf, size_t blen );

/**
 * \brief The \c Derive-Secret function from the TLS 1.3 standard RFC 8446.
 *
 * <tt>
 *   Derive-Secret( Secret, Label, Messages ) =
 *      HKDF-Expand-Label( Secret, Label,
 *                         Hash( Messages ),
 *                         Hash.Length ) )
 * </tt>
 *
 * Note: In this implementation of the function we assume that
 * the parameter message contains the already hashed value and
 * the Derive-Secret function does not need to hash it again.
 *
 * \param hash_alg The identifier for the hash function used for the
 *                 applications of HKDF.
 * \param secret   The \c Secret argument to the \c Derive-Secret function.
 *                 This must be a readable buffer of length \p slen Bytes.
 * \param slen     The length of \p secret in Bytes.
 * \param label    The \c Label argument to the \c Derive-Secret function.
 *                 This must be a readable buffer of length \p llen Bytes.
 * \param llen     The length of \p label in Bytes.
 * \param hash     The hash of the \c Messages argument to the \c Derive-Secret
 *                 function. This must be a readable buffer of length \p mlen
 *                 hlen Bytes.
 * \param hlen     The length of \p hash.
 * \param dstbuf   The target buffer to write the output of \c Derive-Secret to.
 *                 This must be a writable buffer of size \p buflen Bytes.
 * \param buflen   The length of \p dstbuf in Bytes.
 *
 * \returns        \c 0 on success.
 * \returns        A negative error code on failure.
 */

#define MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED 0
#define MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED   1

int mbedtls_ssl_tls1_3_derive_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret, size_t slen,
                   const unsigned char *label, size_t llen,
                   const unsigned char *ctx, size_t clen,
                   int context_already_hashed,
                   unsigned char *dstbuf, size_t buflen );

/**
 * \brief Compute the next secret in the TLS 1.3 key schedule
 *
 * The TLS 1.3 key schedule proceeds as follows to compute
 * the three main secrets during the handshake: The early
 * secret for early data, the handshake secret for all
 * other encrypted handshake messages, and the master
 * secret for all application traffic.
 *
 * <tt>
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
 * </tt>
 *
 * Each of the three secrets in turn is the basis for further
 * key derivations, such as the derivation of traffic keys and IVs;
 * see e.g. mbedtls_ssl_tls1_3_make_traffic_keys().
 *
 * This function implements one step in this evolution of secrets:
 *
 * <tt>
 *                old_secret
 *                    |
 *                    v
 *     Derive-Secret( ., "derived", "" )
 *                    |
 *                    v
 *     input -> HKDF-Extract = new_secret
 * </tt>
 *
 * \param hash_alg    The identifier for the hash function used for the
 *                    applications of HKDF.
 * \param secret_old  The address of the buffer holding the old secret
 *                    on function entry. If not \c NULL, this must be a
 *                    readable buffer whose size matches the output size
 *                    of the hash function represented by \p hash_alg.
 *                    If \c NULL, an all \c 0 array will be used instead.
 * \param input       The address of the buffer holding the additional
 *                    input for the key derivation (e.g., the PSK or the
 *                    ephemeral (EC)DH secret). If not \c NULL, this must be
 *                    a readable buffer whose size \p input_len Bytes.
 *                    If \c NULL, an all \c 0 array will be used instead.
 * \param input_len   The length of \p input in Bytes.
 * \param secret_new  The address of the buffer holding the new secret
 *                    on function exit. This must be a writable buffer
 *                    whose size matches the output size of the hash
 *                    function represented by \p hash_alg.
 *                    This may be the same as \p secret_old.
 *
 * \returns           \c 0 on success.
 * \returns           A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_evolve_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret_old,
                   const unsigned char *input, size_t input_len,
                   unsigned char *secret_new );
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) */

#endif /* ssl_internal.h */
