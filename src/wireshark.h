// SPDX-License-Identifier: MIT
// Copied from the Wireshark project.

#ifndef TLSEXTRACTOR_WIRESHARK_H
#define TLSEXTRACTOR_WIRESHARK_H

#define HAVE_LIBGCRYPT_AEAD

#include "pint.h"

#define DISSECTOR_ASSERT assert
#define _U_ __attribute__((unused))

#include <glib.h>
#include <gcrypt.h>
#include <assert.h>

typedef struct _value_string {
    guint32 value;
    const gchar *strptr;
} value_string;

typedef struct _value_string_ext value_string_ext;

typedef const value_string *(*_value_string_match2_t)(const guint32, value_string_ext *);

struct _value_string_ext {
    _value_string_match2_t _vs_match2;
    guint32 _vs_first_value; /* first value of the value_string array       */
    guint _vs_num_entries; /* number of entries in the value_string array */
    /*  (excluding final {0, NULL})                */
    const value_string *_vs_p;           /* the value string array address              */
    const gchar *_vs_name;        /* vse "Name" (for error messages)             */
};

#ifdef HAVE_LIBGNUTLS
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>
#endif /* HAVE_LIBGNUTLS */

/* TODO inline this now that Libgcrypt is mandatory? */
#define SSL_CIPHER_CTX gcry_cipher_hd_t
#define SSL_DECRYPT_DEBUG


/* other defines */
typedef enum {
    SSL_ID_CHG_CIPHER_SPEC = 0x14,
    SSL_ID_ALERT = 0x15,
    SSL_ID_HANDSHAKE = 0x16,
    SSL_ID_APP_DATA = 0x17,
    SSL_ID_HEARTBEAT = 0x18,
    SSL_ID_TLS12_CID = 0x19
} ContentType;

typedef enum {
    SSL_HND_HELLO_REQUEST = 0,
    SSL_HND_CLIENT_HELLO = 1,
    SSL_HND_SERVER_HELLO = 2,
    SSL_HND_HELLO_VERIFY_REQUEST = 3,
    SSL_HND_NEWSESSION_TICKET = 4,
    SSL_HND_END_OF_EARLY_DATA = 5,
    SSL_HND_HELLO_RETRY_REQUEST = 6,
    SSL_HND_ENCRYPTED_EXTENSIONS = 8,
    SSL_HND_CERTIFICATE = 11,
    SSL_HND_SERVER_KEY_EXCHG = 12,
    SSL_HND_CERT_REQUEST = 13,
    SSL_HND_SVR_HELLO_DONE = 14,
    SSL_HND_CERT_VERIFY = 15,
    SSL_HND_CLIENT_KEY_EXCHG = 16,
    SSL_HND_FINISHED = 20,
    SSL_HND_CERT_URL = 21,
    SSL_HND_CERT_STATUS = 22,
    SSL_HND_SUPPLEMENTAL_DATA = 23,
    SSL_HND_KEY_UPDATE = 24,
    SSL_HND_COMPRESSED_CERTIFICATE = 25,
    /* Encrypted Extensions was NextProtocol in draft-agl-tls-nextprotoneg-03
     * and changed in draft 04. Not to be confused with TLS 1.3 EE. */
    SSL_HND_ENCRYPTED_EXTS = 67
} HandshakeType;

#define SSL2_HND_ERROR                 0x00
#define SSL2_HND_CLIENT_HELLO          0x01
#define SSL2_HND_CLIENT_MASTER_KEY     0x02
#define SSL2_HND_CLIENT_FINISHED       0x03
#define SSL2_HND_SERVER_HELLO          0x04
#define SSL2_HND_SERVER_VERIFY         0x05
#define SSL2_HND_SERVER_FINISHED       0x06
#define SSL2_HND_REQUEST_CERTIFICATE   0x07
#define SSL2_HND_CLIENT_CERTIFICATE    0x08

#define SSL_HND_HELLO_EXT_SERVER_NAME                   0
#define SSL_HND_HELLO_EXT_MAX_FRAGMENT_LENGTH           1
#define SSL_HND_HELLO_EXT_CLIENT_CERTIFICATE_URL        2
#define SSL_HND_HELLO_EXT_TRUSTED_CA_KEYS               3
#define SSL_HND_HELLO_EXT_TRUNCATED_HMAC                4
#define SSL_HND_HELLO_EXT_STATUS_REQUEST                5
#define SSL_HND_HELLO_EXT_USER_MAPPING                  6
#define SSL_HND_HELLO_EXT_CLIENT_AUTHZ                  7
#define SSL_HND_HELLO_EXT_SERVER_AUTHZ                  8
#define SSL_HND_HELLO_EXT_CERT_TYPE                     9
#define SSL_HND_HELLO_EXT_SUPPORTED_GROUPS              10 /* renamed from "elliptic_curves" (RFC 7919 / TLS 1.3) */
#define SSL_HND_HELLO_EXT_EC_POINT_FORMATS              11
#define SSL_HND_HELLO_EXT_SRP                           12
#define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS          13
#define SSL_HND_HELLO_EXT_USE_SRTP                      14
#define SSL_HND_HELLO_EXT_HEARTBEAT                     15
#define SSL_HND_HELLO_EXT_ALPN                          16
#define SSL_HND_HELLO_EXT_STATUS_REQUEST_V2             17
#define SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP  18
#define SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE              19
#define SSL_HND_HELLO_EXT_SERVER_CERT_TYPE              20
#define SSL_HND_HELLO_EXT_PADDING                       21
#define SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC              22
#define SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET        23
#define SSL_HND_HELLO_EXT_TOKEN_BINDING                 24
#define SSL_HND_HELLO_EXT_CACHED_INFO                   25
#define SSL_HND_HELLO_EXT_COMPRESS_CERTIFICATE          27
#define SSL_HND_HELLO_EXT_RECORD_SIZE_LIMIT             28
/* 26-33  Unassigned*/
#define SSL_HND_HELLO_EXT_DELEGATED_CREDENTIALS         34 /* draft-ietf-tls-subcerts-10.txt */
#define SSL_HND_HELLO_EXT_SESSION_TICKET_TLS            35
/* RFC 8446 (TLS 1.3) */
#define SSL_HND_HELLO_EXT_KEY_SHARE_OLD                 40 /* draft-ietf-tls-tls13-22 (removed in -23) */
#define SSL_HND_HELLO_EXT_PRE_SHARED_KEY                41
#define SSL_HND_HELLO_EXT_EARLY_DATA                    42
#define SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS            43
#define SSL_HND_HELLO_EXT_COOKIE                        44
#define SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES        45
#define SSL_HND_HELLO_EXT_TICKET_EARLY_DATA_INFO        46 /* draft-ietf-tls-tls13-18 (removed in -19) */
#define SSL_HND_HELLO_EXT_CERTIFICATE_AUTHORITIES       47
#define SSL_HND_HELLO_EXT_OID_FILTERS                   48
#define SSL_HND_HELLO_EXT_POST_HANDSHAKE_AUTH           49
#define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS_CERT     50
#define SSL_HND_HELLO_EXT_KEY_SHARE                     51
#define SSL_HND_HELLO_EXT_CONNECTION_ID                 53
#define SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS_V1  57 /* draft-ietf-quic-tls-33 */
#define SSL_HND_HELLO_EXT_GREASE_0A0A                   2570
#define SSL_HND_HELLO_EXT_GREASE_1A1A                   6682
#define SSL_HND_HELLO_EXT_GREASE_2A2A                   10794
#define SSL_HND_HELLO_EXT_NPN                           13172 /* 0x3374 */
#define SSL_HND_HELLO_EXT_GREASE_3A3A                   14906
#define SSL_HND_HELLO_EXT_ALPS                          17513 /* draft-vvv-tls-alps-01, temporary value used in BoringSSL implementation */
#define SSL_HND_HELLO_EXT_GREASE_4A4A                   19018
#define SSL_HND_HELLO_EXT_GREASE_5A5A                   23130
#define SSL_HND_HELLO_EXT_GREASE_6A6A                   27242
#define SSL_HND_HELLO_EXT_CHANNEL_ID_OLD                30031 /* 0x754f */
#define SSL_HND_HELLO_EXT_CHANNEL_ID                    30032 /* 0x7550 */
#define SSL_HND_HELLO_EXT_GREASE_7A7A                   31354
#define SSL_HND_HELLO_EXT_GREASE_8A8A                   35466
#define SSL_HND_HELLO_EXT_GREASE_9A9A                   39578
#define SSL_HND_HELLO_EXT_GREASE_AAAA                   43690
#define SSL_HND_HELLO_EXT_GREASE_BABA                   47802
#define SSL_HND_HELLO_EXT_GREASE_CACA                   51914
#define SSL_HND_HELLO_EXT_GREASE_DADA                   56026
#define SSL_HND_HELLO_EXT_GREASE_EAEA                   60138
#define SSL_HND_HELLO_EXT_GREASE_FAFA                   64250
#define SSL_HND_HELLO_EXT_RENEGOTIATION_INFO            65281 /* 0xFF01 */
#define SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS     65445 /* 0xffa5 draft-ietf-quic-tls-13 */
#define SSL_HND_HELLO_EXT_ENCRYPTED_SERVER_NAME         65486 /* 0xffce draft-ietf-tls-esni-01 */

#define SSL_HND_CERT_URL_TYPE_INDIVIDUAL_CERT       1
#define SSL_HND_CERT_URL_TYPE_PKIPATH               2
#define SSL_HND_CERT_STATUS_TYPE_OCSP        1
#define SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI  2
#define SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY     2

/* https://github.com/quicwg/base-drafts/wiki/Temporary-IANA-Registry#quic-transport-parameters */
#define SSL_HND_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID  0x00
#define SSL_HND_QUIC_TP_MAX_IDLE_TIMEOUT                    0x01
#define SSL_HND_QUIC_TP_STATELESS_RESET_TOKEN               0x02
#define SSL_HND_QUIC_TP_MAX_UDP_PAYLOAD_SIZE                0x03
#define SSL_HND_QUIC_TP_INITIAL_MAX_DATA                    0x04
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  0x05
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI         0x07
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAMS_BIDI            0x08
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAMS_UNI             0x09
#define SSL_HND_QUIC_TP_ACK_DELAY_EXPONENT                  0x0a
#define SSL_HND_QUIC_TP_MAX_ACK_DELAY                       0x0b
#define SSL_HND_QUIC_TP_DISABLE_ACTIVE_MIGRATION            0x0c
#define SSL_HND_QUIC_TP_PREFERRED_ADDRESS                   0x0d
#define SSL_HND_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT          0x0e
#define SSL_HND_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID        0x0f
#define SSL_HND_QUIC_TP_RETRY_SOURCE_CONNECTION_ID          0x10
#define SSL_HND_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE             0x20 /* https://tools.ietf.org/html/draft-pauly-quic-datagram-05 */
#define SSL_HND_QUIC_TP_LOSS_BITS                           0x1057 /* https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-lossbits-03 */
#define SSL_HND_QUIC_TP_GREASE_QUIC_BIT                     0x2ab2 /* https://tools.ietf.org/html/draft-thomson-quic-bit-grease-00 */
#define SSL_HND_QUIC_TP_ENABLE_TIME_STAMP                   0x7157 /* https://tools.ietf.org/html/draft-huitema-quic-ts-02 */
#define SSL_HND_QUIC_TP_ENABLE_TIME_STAMP_V2                0x7158 /* https://tools.ietf.org/html/draft-huitema-quic-ts-03 */
#define SSL_HND_QUIC_TP_VERSION_NEGOTIATION                 0x73DB /* https://tools.ietf.org/html/draft-ietf-quic-version-negotiation-03 */
#define SSL_HND_QUIC_TP_MIN_ACK_DELAY                       0xde1a /* https://tools.ietf.org/html/draft-iyengar-quic-delayed-ack-00 */
/* https://quiche.googlesource.com/quiche/+/refs/heads/master/quic/core/crypto/transport_parameters.cc */
#define SSL_HND_QUIC_TP_GOOGLE_USER_AGENT                   0x3129
#define SSL_HND_QUIC_TP_GOOGLE_KEY_UPDATE_NOT_YET_SUPPORTED 0x312B
#define SSL_HND_QUIC_TP_GOOGLE_QUIC_VERSION                 0x4752
#define SSL_HND_QUIC_TP_GOOGLE_INITIAL_RTT                  0x3127
#define SSL_HND_QUIC_TP_GOOGLE_SUPPORT_HANDSHAKE_DONE       0x312A
#define SSL_HND_QUIC_TP_GOOGLE_QUIC_PARAMS                  0x4751
#define SSL_HND_QUIC_TP_GOOGLE_CONNECTION_OPTIONS           0x3128
/* https://github.com/facebookincubator/mvfst/blob/master/quic/QuicConstants.h */
#define SSL_HND_QUIC_TP_FACEBOOK_PARTIAL_RELIABILITY        0xFF00
/*
 * Lookup tables
 */
extern const value_string ssl_version_short_names[];
extern const value_string ssl_20_msg_types[];
extern value_string_ext ssl_20_cipher_suites_ext;
extern const value_string ssl_20_certificate_type[];
extern const value_string ssl_31_content_type[];
extern const value_string ssl_versions[];
extern const value_string ssl_31_change_cipher_spec[];
extern const value_string ssl_31_alert_level[];
extern const value_string ssl_31_alert_description[];
extern const value_string ssl_31_handshake_type[];
extern const value_string tls_heartbeat_type[];
extern const value_string tls_heartbeat_mode[];
extern const value_string ssl_31_compression_method[];
extern const value_string ssl_31_key_exchange_algorithm[];
extern const value_string ssl_31_signature_algorithm[];
extern const value_string ssl_31_client_certificate_type[];
extern const value_string ssl_31_public_value_encoding[];
extern value_string_ext ssl_31_ciphersuite_ext;
extern const value_string tls_hello_extension_types[];
extern const value_string tls_hash_algorithm[];
extern const value_string tls_signature_algorithm[];
extern const value_string tls13_signature_algorithm[];
extern const value_string tls_certificate_type[];
extern const value_string tls_cert_chain_type[];
extern const value_string tls_cert_status_type[];
extern const value_string ssl_extension_curves[];
extern const value_string ssl_extension_ec_point_formats[];
extern const value_string ssl_curve_types[];
extern const value_string tls_hello_ext_server_name_type_vs[];
extern const value_string tls_hello_ext_max_fragment_length[];
extern const value_string tls_hello_ext_psk_ke_mode[];
extern const value_string tls13_key_update_request[];
extern const value_string compress_certificate_algorithm_vals[];
extern const value_string quic_transport_parameter_id[];
// TODO: extern const range_string quic_version_vals[];
// TODO: extern const val64_string quic_enable_time_stamp_v2_vals[];

/* XXX Should we use GByteArray instead? */
typedef struct _StringInfo {
    guchar *data;      /* Backing storage which may be larger than data_len */
    guint data_len;  /* Length of the meaningful part of data */
} StringInfo;

#define SSL_WRITE_KEY           1

#define SSL_VER_UNKNOWN         0
#define SSLV2_VERSION           0x0002 /* not in record layer, SSL_CLIENT_SERVER from
                                          http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html */
#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define GMTLSV1_VERSION        0x101
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT0_OPENSSL_VERSION 0x100
#define DTLSV1DOT2_VERSION     0xfefd

/* Returns the TLS 1.3 draft version or 0 if not applicable. */
static inline guint8 extract_tls13_draft_version(guint32 version) {
    if ((version & 0xff00) == 0x7f00) {
        return (guint8) version;
    }
    return 0;
}


#define SSL_CLIENT_RANDOM       (1<<0)
#define SSL_SERVER_RANDOM       (1<<1)
#define SSL_CIPHER              (1<<2)
#define SSL_HAVE_SESSION_KEY    (1<<3)
#define SSL_VERSION             (1<<4)
#define SSL_MASTER_SECRET       (1<<5)
#define SSL_PRE_MASTER_SECRET   (1<<6)
#define SSL_CLIENT_EXTENDED_MASTER_SECRET (1<<7)
#define SSL_SERVER_EXTENDED_MASTER_SECRET (1<<8)
#define SSL_NEW_SESSION_TICKET  (1<<10)
#define SSL_ENCRYPT_THEN_MAC    (1<<11)
#define SSL_SEEN_0RTT_APPDATA   (1<<12)
#define SSL_QUIC_RECORD_LAYER   (1<<13) /* For QUIC (draft >= -13) */

#define SSL_EXTENDED_MASTER_SECRET_MASK (SSL_CLIENT_EXTENDED_MASTER_SECRET|SSL_SERVER_EXTENDED_MASTER_SECRET)

/* SSL Cipher Suite modes */
typedef enum {
    MODE_STREAM,    /* GenericStreamCipher */
    MODE_CBC,       /* GenericBlockCipher */
    MODE_GCM,       /* GenericAEADCipher */
    MODE_CCM,       /* AEAD_AES_{128,256}_CCM with 16 byte auth tag */
    MODE_CCM_8,     /* AEAD_AES_{128,256}_CCM with 8 byte auth tag */
    MODE_POLY1305,  /* AEAD_CHACHA20_POLY1305 with 16 byte auth tag (RFC 7905) */
} ssl_cipher_mode_t;

/* Explicit and implicit nonce length (RFC 5116 - Section 3.2.1) */
#define IMPLICIT_NONCE_LEN  4
#define EXPLICIT_NONCE_LEN  8
#define TLS13_AEAD_NONCE_LENGTH     12

/* TLS 1.3 Record type for selecting the appropriate secret. */
typedef enum {
    TLS_SECRET_0RTT_APP,
    TLS_SECRET_HANDSHAKE,
    TLS_SECRET_APP,
} TLSRecordType;

#define SSL_DEBUG_USE_STDERR "-"

#define SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES 16

/* Record fragment lengths MUST NOT exceed 2^14 (= 0x4000) */
#define TLS_MAX_RECORD_LENGTH 0x4000

typedef struct _SslCipherSuite {
    gint number;
    gint kex;
    gint enc;
    gint dig;
    ssl_cipher_mode_t mode;
} SslCipherSuite;

typedef struct _SslFlow {
    guint32 byte_seq;
    guint16 flags;
    // TODO: wmem_tree_t *multisegment_pdus;
} SslFlow;

struct _SslDecompress {
    gint compression;
#ifdef HAVE_ZLIB
    z_stream istream;
#endif
};

typedef struct _SslDecompress SslDecompress;

typedef struct _SslDecoder {
    const SslCipherSuite *cipher_suite;
    gint compression;
    guchar _mac_key_or_write_iv[48];
    StringInfo mac_key; /* for block and stream ciphers */
    StringInfo write_iv; /* for AEAD ciphers (at least GCM, CCM) */
    SSL_CIPHER_CTX evp;
    SslDecompress *decomp;
    guint64 seq;    /**< Implicit (TLS) or explicit (DTLS) record sequence number. */
    guint16 epoch;
    SslFlow *flow;
    StringInfo app_traffic_secret;  /**< TLS 1.3 application traffic secret (if applicable), wmem file scope. */
} SslDecoder;

/*
 * TLS 1.3 Cipher context. Simpler than SslDecoder since no compression is
 * required and all keys are calculated internally.
 */
typedef struct {
    gcry_cipher_hd_t hd;
    guint8 iv[TLS13_AEAD_NONCE_LENGTH];
} tls13_cipher;

#define KEX_DHE_DSS     0x10
#define KEX_DHE_PSK     0x11
#define KEX_DHE_RSA     0x12
#define KEX_DH_ANON     0x13
#define KEX_DH_DSS      0x14
#define KEX_DH_RSA      0x15
#define KEX_ECDHE_ECDSA 0x16
#define KEX_ECDHE_PSK   0x17
#define KEX_ECDHE_RSA   0x18
#define KEX_ECDH_ANON   0x19
#define KEX_ECDH_ECDSA  0x1a
#define KEX_ECDH_RSA    0x1b
#define KEX_KRB5        0x1c
#define KEX_PSK         0x1d
#define KEX_RSA         0x1e
#define KEX_RSA_PSK     0x1f
#define KEX_SRP_SHA     0x20
#define KEX_SRP_SHA_DSS 0x21
#define KEX_SRP_SHA_RSA 0x22
#define KEX_IS_DH(n)    ((n) >= KEX_DHE_DSS && (n) <= KEX_ECDH_RSA)
#define KEX_TLS13       0x23
#define KEX_ECJPAKE     0x24

#define KEX_ECDHE_SM2   0x25
#define KEX_ECC_SM2     0x26
#define KEX_IBSDH_SM9   0x27
#define KEX_IBC_SM9     0x28

/* Order is significant, must match "ciphers" array in packet-tls-utils.c */

#define ENC_START       0x30
#define ENC_DES         0x30
#define ENC_3DES        0x31
#define ENC_RC4         0x32
#define ENC_RC2         0x33
#define ENC_IDEA        0x34
#define ENC_AES         0x35
#define ENC_AES256      0x36
#define ENC_CAMELLIA128 0x37
#define ENC_CAMELLIA256 0x38
#define ENC_SEED        0x39
#define ENC_CHACHA20    0x3A
#define ENC_NULL        0x3B
#define ENC_SM1         0x3C
#define ENC_SM4         0x3D


#define DIG_MD5         0x40
#define DIG_SHA         0x41
#define DIG_SHA256      0x42
#define DIG_SHA384      0x43
#define DIG_NA          0x44 /* Not Applicable */
#define DIG_SM3         0x45

typedef struct {
    const gchar *name;
    guint len;
} SslDigestAlgo;

typedef struct _SslRecordInfo {
    guchar *plain_data;     /**< Decrypted data. */
    guint data_len;       /**< Length of decrypted data. */
    gint id;             /**< Identifies the exact record within a frame
                                 (there can be multiple records in a frame). */
    ContentType type;       /**< Content type of the decrypted record data. */
    SslFlow *flow;          /**< Flow where this record fragment is a part of.
                                 Can be NULL if this record type may not be fragmented. */
    guint32 seq;            /**< Data offset within the flow. */
    struct _SslRecordInfo *next;
} SslRecordInfo;

/**
 * Stored information about a part of a reassembled handshake message. A single
 * handshake record is uniquely identified by (record_id, reassembly_id).
 */
typedef struct _TlsHsFragment {
    guint record_id;      /**< Identifies the exact record within a frame
                                 (there can be multiple records in a frame). */
    guint reassembly_id;  /**< Identifies the reassembly that this fragment is part of. */
    guint32 offset;         /**< Offset within a reassembly. */
    guint8 type;           /**< Handshake type (first byte of the buffer). */
    int is_last: 1;    /**< Whether this fragment completes the message. */
    struct _TlsHsFragment *next;
} TlsHsFragment;

typedef struct {
    SslRecordInfo *records; /**< Decrypted records within this frame. */
    TlsHsFragment *hs_fragments;    /**< Handshake records that are part of a reassembly. */
    guint32 srcport;        /**< Used for Decode As */
    guint32 destport;
} SslPacketInfo;

typedef struct _SslSession {
    gint cipher;
    gint compression;
    guint16 version;
    guchar tls13_draft_version;
    gint8 client_cert_type;
    gint8 server_cert_type;
    guint32 client_ccs_frame;
    guint32 server_ccs_frame;

    /* The address/proto/port of the server as determined from heuristics
     * (e.g. ClientHello) or set externally (via ssl_set_master_secret()). */
    //TODO: address srv_addr;
    //TODO: port_type srv_ptype;
    guint srv_port;

    /* The Application layer protocol if known (for STARTTLS support) */
    //dissector_handle_t   app_handle;
    const char *alpn_name;
    guint32 last_nontls_frame;
    gboolean is_session_resumed;

    /* First pass only: track an in-progress handshake reassembly (>0) */
    guint32 client_hs_reassembly_id;
    guint32 server_hs_reassembly_id;

    /* Connection ID extension

    struct {
        opaque cid<0..2^8-1>;
    } ConnectionId;
    */
#define DTLS_MAX_CID_LENGTH 256

    guint8 *client_cid;
    guint8 *server_cid;
    guint8 client_cid_len;
    guint8 server_cid_len;
} SslSession;

/* RFC 5246, section 8.1 says that the master secret is always 48 bytes */
#define SSL_MASTER_SECRET_LENGTH        48

struct cert_key_id; /* defined in epan/secrets.h */

/* This holds state information for a SSL conversation */
typedef struct _SslDecryptSession {
    guchar _master_secret[SSL_MASTER_SECRET_LENGTH];
    guchar _session_id[256];
    guchar _client_random[32];
    guchar _server_random[32];
    StringInfo session_id;
    StringInfo session_ticket;
    StringInfo server_random;
    StringInfo client_random;
    StringInfo master_secret;
    StringInfo handshake_data;
    /* the data store for this StringInfo must be allocated explicitly with a capture lifetime scope */
    StringInfo pre_master_secret;
    guchar _server_data_for_iv[24];
    StringInfo server_data_for_iv;
    guchar _client_data_for_iv[24];
    StringInfo client_data_for_iv;

    gint state;
    const SslCipherSuite *cipher_suite;
    SslDecoder *server;
    SslDecoder *client;
    SslDecoder server_new;
    SslDecoder client_new;
#if defined(HAVE_LIBGNUTLS)
    struct cert_key_id *cert_key_id;   /**< SHA-1 Key ID of public key in certificate. */
#endif
    StringInfo psk;
    StringInfo app_data_segment;
    SslSession session;
    gboolean has_early_data;

} SslDecryptSession;

/* User Access Table */
typedef struct _ssldecrypt_assoc_t {
    char *ipaddr;
    char *port;
    char *protocol;
    char *keyfile;
    char *password;
} ssldecrypt_assoc_t;

typedef struct ssl_common_options {
    const gchar *psk;
    const gchar *keylog_filename;
} ssl_common_options_t;


#define MAX_BLOCK_SIZE 16
#define MAX_KEY_SIZE 32

#include "wireshark.h"

static FILE *ssl_debug_file = NULL;

void
ssl_debug_printf(const gchar *fmt, ...);

void
ssl_print_data(const gchar *name, const guchar *data, size_t len);

void
ssl_print_string(const gchar *name, const StringInfo *data);

gint
ssl_data_alloc(StringInfo *str, size_t len);

void
ssl_data_set(StringInfo *str, const guchar *data, guint len);

static gint
ssl_data_realloc(StringInfo *str, guint len);

static gint
ssl_data_copy(StringInfo *dst, StringInfo *src);


/* libgcrypt wrappers for HMAC/message digest operations {{{ */
/* hmac abstraction layer */
#define SSL_HMAC gcry_md_hd_t

static inline gint
ssl_hmac_init(SSL_HMAC *md, gint algo);

static inline gint
ssl_hmac_setkey(SSL_HMAC *md, const void *key, gint len);

static inline gint
ssl_hmac_reset(SSL_HMAC *md);

static inline void
ssl_hmac_update(SSL_HMAC *md, const void *data, gint len);

static inline void
ssl_hmac_final(SSL_HMAC *md, guchar *data, guint *datalen);

static inline void
ssl_hmac_cleanup(SSL_HMAC *md);

/* message digest abstraction layer*/
#define SSL_MD gcry_md_hd_t

static inline gint
ssl_md_init(SSL_MD *md, gint algo);

static inline void
ssl_md_update(SSL_MD *md, guchar *data, gint len);

static inline void
ssl_md_final(SSL_MD *md, guchar *data, guint *datalen);

static inline void
ssl_md_cleanup(SSL_MD *md);

static inline void
ssl_md_reset(SSL_MD *md);

/* md5 /sha abstraction layer */
#define SSL_SHA_CTX gcry_md_hd_t
#define SSL_MD5_CTX gcry_md_hd_t

static inline void
ssl_sha_init(SSL_SHA_CTX *md);

static inline void
ssl_sha_update(SSL_SHA_CTX *md, guchar *data, gint len);

static inline void
ssl_sha_final(guchar *buf, SSL_SHA_CTX *md);

static inline void
ssl_sha_reset(SSL_SHA_CTX *md);

static inline void
ssl_sha_cleanup(SSL_SHA_CTX *md);

static inline gint
ssl_md5_init(SSL_MD5_CTX *md);

static inline void
ssl_md5_update(SSL_MD5_CTX *md, guchar *data, gint len);

static inline void
ssl_md5_final(guchar *buf, SSL_MD5_CTX *md);

static inline void
ssl_md5_reset(SSL_MD5_CTX *md);

static inline void
ssl_md5_cleanup(SSL_MD5_CTX *md);
/* libgcrypt wrappers for HMAC/message digest operations }}} */

/* libgcrypt wrappers for Cipher state manipulation {{{ */
gint
ssl_cipher_setiv(SSL_CIPHER_CTX *cipher, guchar *iv, gint iv_len);

/* stream cipher abstraction layer*/
static gint
ssl_cipher_init(gcry_cipher_hd_t *cipher, gint algo, guchar *sk,
                guchar *iv, gint mode);

static inline gint
ssl_cipher_decrypt(gcry_cipher_hd_t *cipher, guchar *out, gint outl,
                   const guchar *in, gint inl);

static inline gint
ssl_get_digest_by_name(const gchar *name);

static inline gint
ssl_get_cipher_by_name(const gchar *name);

static inline void
ssl_cipher_cleanup(gcry_cipher_hd_t *cipher);
/* }}} */

/* Digests, Ciphers and Cipher Suites registry {{{ */
static const SslDigestAlgo digests[] = {
        {"MD5",            16},
        {"SHA1",           20},
        {"SHA256",         32},
        {"SHA384",         48},
        {"Not Applicable", 0},
};

#define DIGEST_MAX_SIZE 48

/* get index digest index */
static const SslDigestAlgo *
ssl_cipher_suite_dig(const SslCipherSuite *cs) {
    return &digests[cs->dig - DIG_MD5];
}

static const gchar *ciphers[] = {
        "DES",
        "3DES",
        "ARCFOUR", /* libgcrypt does not support rc4, but this should be 100% compatible*/
        "RFC2268_128", /* libgcrypt name for RC2 with a 128-bit key */
        "IDEA",
        "AES",
        "AES256",
        "CAMELLIA128",
        "CAMELLIA256",
        "SEED",
        "CHACHA20", /* since Libgcrypt 1.7.0 */
        "*UNKNOWN*"
};

static const SslCipherSuite cipher_suites[] = {
        {0x0001, KEX_RSA,         ENC_NULL,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_MD5 */
        {0x0002, KEX_RSA,         ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA */
        {0x0003, KEX_RSA,         ENC_RC4,         DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
        {0x0004, KEX_RSA,         ENC_RC4,         DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_MD5 */
        {0x0005, KEX_RSA,         ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_SHA */
        {0x0006, KEX_RSA,         ENC_RC2,         DIG_MD5,    MODE_CBC},   /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
        {0x0007, KEX_RSA,         ENC_IDEA,        DIG_SHA,    MODE_CBC},   /* TLS_RSA_WITH_IDEA_CBC_SHA */
        {0x0008, KEX_RSA,         ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
        {0x0009, KEX_RSA,         ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_RSA_WITH_DES_CBC_SHA */
        {0x000A, KEX_RSA,         ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
        {0x000B, KEX_DH_DSS,      ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
        {0x000C, KEX_DH_DSS,      ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DH_DSS_WITH_DES_CBC_SHA */
        {0x000D, KEX_DH_DSS,      ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
        {0x000E, KEX_DH_RSA,      ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
        {0x000F, KEX_DH_RSA,      ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DH_RSA_WITH_DES_CBC_SHA */
        {0x0010, KEX_DH_RSA,      ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */
        {0x0011, KEX_DHE_DSS,     ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
        {0x0012, KEX_DHE_DSS,     ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
        {0x0013, KEX_DHE_DSS,     ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
        {0x0014, KEX_DHE_RSA,     ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
        {0x0015, KEX_DHE_RSA,     ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
        {0x0016, KEX_DHE_RSA,     ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
        {0x0017, KEX_DH_ANON,     ENC_RC4,         DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
        {0x0018, KEX_DH_ANON,     ENC_RC4,         DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_WITH_RC4_128_MD5 */
        {0x0019, KEX_DH_ANON,     ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
        {0x001A, KEX_DH_ANON,     ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DH_anon_WITH_DES_CBC_SHA */
        {0x001B, KEX_DH_ANON,     ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
        {0x002C, KEX_PSK,         ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA */
        {0x002D, KEX_DHE_PSK,     ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA */
        {0x002E, KEX_RSA_PSK,     ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA */
        {0x002F, KEX_RSA,         ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_RSA_WITH_AES_128_CBC_SHA */
        {0x0030, KEX_DH_DSS,      ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
        {0x0031, KEX_DH_RSA,      ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
        {0x0032, KEX_DHE_DSS,     ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
        {0x0033, KEX_DHE_RSA,     ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
        {0x0034, KEX_DH_ANON,     ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
        {0x0035, KEX_RSA,         ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_RSA_WITH_AES_256_CBC_SHA */
        {0x0036, KEX_DH_DSS,      ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
        {0x0037, KEX_DH_RSA,      ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
        {0x0038, KEX_DHE_DSS,     ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
        {0x0039, KEX_DHE_RSA,     ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
        {0x003A, KEX_DH_ANON,     ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
        {0x003B, KEX_RSA,         ENC_NULL,        DIG_SHA256, MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA256 */
        {0x003C, KEX_RSA,         ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
        {0x003D, KEX_RSA,         ENC_AES256,      DIG_SHA256, MODE_CBC},   /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
        {0x003E, KEX_DH_DSS,      ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA256 */
        {0x003F, KEX_DH_RSA,      ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA256 */
        {0x0040, KEX_DHE_DSS,     ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 */
        {0x0041, KEX_RSA,         ENC_CAMELLIA128, DIG_SHA,    MODE_CBC},   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
        {0x0042, KEX_DH_DSS,      ENC_CAMELLIA128, DIG_SHA,    MODE_CBC},   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
        {0x0043, KEX_DH_RSA,      ENC_CAMELLIA128, DIG_SHA,    MODE_CBC},   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
        {0x0044, KEX_DHE_DSS,     ENC_CAMELLIA128, DIG_SHA,    MODE_CBC},   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
        {0x0045, KEX_DHE_RSA,     ENC_CAMELLIA128, DIG_SHA,    MODE_CBC},   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
        {0x0046, KEX_DH_ANON,     ENC_CAMELLIA128, DIG_SHA,    MODE_CBC},   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
        {0x0060, KEX_RSA,         ENC_RC4,         DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
        {0x0061, KEX_RSA,         ENC_RC2,         DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
        {0x0062, KEX_RSA,         ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
        {0x0063, KEX_DHE_DSS,     ENC_DES,         DIG_SHA,    MODE_CBC},   /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
        {0x0064, KEX_RSA,         ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
        {0x0065, KEX_DHE_DSS,     ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
        {0x0066, KEX_DHE_DSS,     ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_WITH_RC4_128_SHA */
        {0x0067, KEX_DHE_RSA,     ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
        {0x0068, KEX_DH_DSS,      ENC_AES256,      DIG_SHA256, MODE_CBC},   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA256 */
        {0x0069, KEX_DH_RSA,      ENC_AES256,      DIG_SHA256, MODE_CBC},   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA256 */
        {0x006A, KEX_DHE_DSS,     ENC_AES256,      DIG_SHA256, MODE_CBC},   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 */
        {0x006B, KEX_DHE_RSA,     ENC_AES256,      DIG_SHA256, MODE_CBC},   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
        {0x006C, KEX_DH_ANON,     ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
        {0x006D, KEX_DH_ANON,     ENC_AES256,      DIG_SHA256, MODE_CBC},   /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
        {0x0084, KEX_RSA,         ENC_CAMELLIA256, DIG_SHA,    MODE_CBC},   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
        {0x0085, KEX_DH_DSS,      ENC_CAMELLIA256, DIG_SHA,    MODE_CBC},   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
        {0x0086, KEX_DH_RSA,      ENC_CAMELLIA256, DIG_SHA,    MODE_CBC},   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
        {0x0087, KEX_DHE_DSS,     ENC_CAMELLIA256, DIG_SHA,    MODE_CBC},   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
        {0x0088, KEX_DHE_RSA,     ENC_CAMELLIA256, DIG_SHA,    MODE_CBC},   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
        {0x0089, KEX_DH_ANON,     ENC_CAMELLIA256, DIG_SHA,    MODE_CBC},   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
        {0x008A, KEX_PSK,         ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_RC4_128_SHA */
        {0x008B, KEX_PSK,         ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_PSK_WITH_3DES_EDE_CBC_SHA */
        {0x008C, KEX_PSK,         ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_PSK_WITH_AES_128_CBC_SHA */
        {0x008D, KEX_PSK,         ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_PSK_WITH_AES_256_CBC_SHA */
        {0x008E, KEX_DHE_PSK,     ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_RC4_128_SHA */
        {0x008F, KEX_DHE_PSK,     ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA */
        {0x0090, KEX_DHE_PSK,     ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA */
        {0x0091, KEX_DHE_PSK,     ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA */
        {0x0092, KEX_RSA_PSK,     ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_RC4_128_SHA */
        {0x0093, KEX_RSA_PSK,     ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
        {0x0094, KEX_RSA_PSK,     ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
        {0x0095, KEX_RSA_PSK,     ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
        {0x0096, KEX_RSA,         ENC_SEED,        DIG_SHA,    MODE_CBC},   /* TLS_RSA_WITH_SEED_CBC_SHA */
        {0x0097, KEX_DH_DSS,      ENC_SEED,        DIG_SHA,    MODE_CBC},   /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
        {0x0098, KEX_DH_RSA,      ENC_SEED,        DIG_SHA,    MODE_CBC},   /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
        {0x0099, KEX_DHE_DSS,     ENC_SEED,        DIG_SHA,    MODE_CBC},   /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
        {0x009A, KEX_DHE_RSA,     ENC_SEED,        DIG_SHA,    MODE_CBC},   /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */
        {0x009B, KEX_DH_ANON,     ENC_SEED,        DIG_SHA,    MODE_CBC},   /* TLS_DH_anon_WITH_SEED_CBC_SHA */
        {0x009C, KEX_RSA,         ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
        {0x009D, KEX_RSA,         ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
        {0x009E, KEX_DHE_RSA,     ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 */
        {0x009F, KEX_DHE_RSA,     ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
        {0x00A0, KEX_DH_RSA,      ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_DH_RSA_WITH_AES_128_GCM_SHA256 */
        {0x00A1, KEX_DH_RSA,      ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_DH_RSA_WITH_AES_256_GCM_SHA384 */
        {0x00A2, KEX_DHE_DSS,     ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 */
        {0x00A3, KEX_DHE_DSS,     ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 */
        {0x00A4, KEX_DH_DSS,      ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_DH_DSS_WITH_AES_128_GCM_SHA256 */
        {0x00A5, KEX_DH_DSS,      ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_DH_DSS_WITH_AES_256_GCM_SHA384 */
        {0x00A6, KEX_DH_ANON,     ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
        {0x00A7, KEX_DH_ANON,     ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
        {0x00A8, KEX_PSK,         ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
        {0x00A9, KEX_PSK,         ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
        {0x00AA, KEX_DHE_PSK,     ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 */
        {0x00AB, KEX_DHE_PSK,     ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 */
        {0x00AC, KEX_RSA_PSK,     ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
        {0x00AD, KEX_RSA_PSK,     ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
        {0x00AE, KEX_PSK,         ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_PSK_WITH_AES_128_CBC_SHA256 */
        {0x00AF, KEX_PSK,         ENC_AES256,      DIG_SHA384, MODE_CBC},   /* TLS_PSK_WITH_AES_256_CBC_SHA384 */
        {0x00B0, KEX_PSK,         ENC_NULL,        DIG_SHA256, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA256 */
        {0x00B1, KEX_PSK,         ENC_NULL,        DIG_SHA384, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA384 */
        {0x00B2, KEX_DHE_PSK,     ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
        {0x00B3, KEX_DHE_PSK,     ENC_AES256,      DIG_SHA384, MODE_CBC},   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
        {0x00B4, KEX_DHE_PSK,     ENC_NULL,        DIG_SHA256, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA256 */
        {0x00B5, KEX_DHE_PSK,     ENC_NULL,        DIG_SHA384, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA384 */
        {0x00B6, KEX_RSA_PSK,     ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
        {0x00B7, KEX_RSA_PSK,     ENC_AES256,      DIG_SHA384, MODE_CBC},   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
        {0x00B8, KEX_RSA_PSK,     ENC_NULL,        DIG_SHA256, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA256 */
        {0x00B9, KEX_RSA_PSK,     ENC_NULL,        DIG_SHA384, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA384 */
        {0x00BA, KEX_RSA,         ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
        {0x00BB, KEX_DH_DSS,      ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
        {0x00BC, KEX_DH_RSA,      ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
        {0x00BD, KEX_DHE_DSS,     ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
        {0x00BE, KEX_DHE_RSA,     ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
        {0x00BF, KEX_DH_ANON,     ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 */
        {0x00C0, KEX_RSA,         ENC_CAMELLIA256, DIG_SHA256, MODE_CBC},   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
        {0x00C1, KEX_DH_DSS,      ENC_CAMELLIA256, DIG_SHA256, MODE_CBC},   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
        {0x00C2, KEX_DH_RSA,      ENC_CAMELLIA256, DIG_SHA256, MODE_CBC},   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
        {0x00C3, KEX_DHE_DSS,     ENC_CAMELLIA256, DIG_SHA256, MODE_CBC},   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
        {0x00C4, KEX_DHE_RSA,     ENC_CAMELLIA256, DIG_SHA256, MODE_CBC},   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
        {0x00C5, KEX_DH_ANON,     ENC_CAMELLIA256, DIG_SHA256, MODE_CBC},   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 */

        /* NOTE: TLS 1.3 cipher suites are incompatible with TLS 1.2. */
        {0x1301, KEX_TLS13,       ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_AES_128_GCM_SHA256 */
        {0x1302, KEX_TLS13,       ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_AES_256_GCM_SHA384 */
        {0x1303, KEX_TLS13,       ENC_CHACHA20,    DIG_SHA256, MODE_POLY1305}, /* TLS_CHACHA20_POLY1305_SHA256 */
        {0x1304, KEX_TLS13,       ENC_AES,         DIG_SHA256, MODE_CCM},   /* TLS_AES_128_CCM_SHA256 */
        {0x1305, KEX_TLS13,       ENC_AES,         DIG_SHA256, MODE_CCM_8},   /* TLS_AES_128_CCM_8_SHA256 */

        {0xC001, KEX_ECDH_ECDSA,  ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
        {0xC002, KEX_ECDH_ECDSA,  ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
        {0xC003, KEX_ECDH_ECDSA,  ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
        {0xC004, KEX_ECDH_ECDSA,  ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
        {0xC005, KEX_ECDH_ECDSA,  ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
        {0xC006, KEX_ECDHE_ECDSA, ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
        {0xC007, KEX_ECDHE_ECDSA, ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
        {0xC008, KEX_ECDHE_ECDSA, ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
        {0xC009, KEX_ECDHE_ECDSA, ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
        {0xC00A, KEX_ECDHE_ECDSA, ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
        {0xC00B, KEX_ECDH_RSA,    ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_NULL_SHA */
        {0xC00C, KEX_ECDH_RSA,    ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
        {0xC00D, KEX_ECDH_RSA,    ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
        {0xC00E, KEX_ECDH_RSA,    ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
        {0xC00F, KEX_ECDH_RSA,    ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
        {0xC0FF, KEX_ECJPAKE,     ENC_AES,         DIG_NA,     MODE_CCM_8},   /* TLS_ECJPAKE_WITH_AES_128_CCM_8 */
        {0xC010, KEX_ECDHE_RSA,   ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_NULL_SHA */
        {0xC011, KEX_ECDHE_RSA,   ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
        {0xC012, KEX_ECDHE_RSA,   ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
        {0xC013, KEX_ECDHE_RSA,   ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
        {0xC014, KEX_ECDHE_RSA,   ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
        {0xC015, KEX_ECDH_ANON,   ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_NULL_SHA */
        {0xC016, KEX_ECDH_ANON,   ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_RC4_128_SHA */
        {0xC017, KEX_ECDH_ANON,   ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
        {0xC018, KEX_ECDH_ANON,   ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
        {0xC019, KEX_ECDH_ANON,   ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
        {0xC01A, KEX_SRP_SHA,     ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA */
        {0xC01B, KEX_SRP_SHA_RSA, ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA */
        {0xC01C, KEX_SRP_SHA_DSS, ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA */
        {0xC01D, KEX_SRP_SHA,     ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_SRP_SHA_WITH_AES_128_CBC_SHA */
        {0xC01E, KEX_SRP_SHA_RSA, ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA */
        {0xC01F, KEX_SRP_SHA_DSS, ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA */
        {0xC020, KEX_SRP_SHA,     ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_SRP_SHA_WITH_AES_256_CBC_SHA */
        {0xC021, KEX_SRP_SHA_RSA, ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA */
        {0xC022, KEX_SRP_SHA_DSS, ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA */
        {0xC023, KEX_ECDHE_ECDSA, ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
        {0xC024, KEX_ECDHE_ECDSA, ENC_AES256,      DIG_SHA384, MODE_CBC},   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
        {0xC025, KEX_ECDH_ECDSA,  ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
        {0xC026, KEX_ECDH_ECDSA,  ENC_AES256,      DIG_SHA384, MODE_CBC},   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
        {0xC027, KEX_ECDHE_RSA,   ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
        {0xC028, KEX_ECDHE_RSA,   ENC_AES256,      DIG_SHA384, MODE_CBC},   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
        {0xC029, KEX_ECDH_RSA,    ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
        {0xC02A, KEX_ECDH_RSA,    ENC_AES256,      DIG_SHA384, MODE_CBC},   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
        {0xC02B, KEX_ECDHE_ECDSA, ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
        {0xC02C, KEX_ECDHE_ECDSA, ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
        {0xC02D, KEX_ECDH_ECDSA,  ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
        {0xC02E, KEX_ECDH_ECDSA,  ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
        {0xC02F, KEX_ECDHE_RSA,   ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
        {0xC030, KEX_ECDHE_RSA,   ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
        {0xC031, KEX_ECDH_RSA,    ENC_AES,         DIG_SHA256, MODE_GCM},   /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
        {0xC032, KEX_ECDH_RSA,    ENC_AES256,      DIG_SHA384, MODE_GCM},   /* TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */
        {0xC033, KEX_ECDHE_PSK,   ENC_RC4,         DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_RC4_128_SHA */
        {0xC034, KEX_ECDHE_PSK,   ENC_3DES,        DIG_SHA,    MODE_CBC},   /* TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA */
        {0xC035, KEX_ECDHE_PSK,   ENC_AES,         DIG_SHA,    MODE_CBC},   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA */
        {0xC036, KEX_ECDHE_PSK,   ENC_AES256,      DIG_SHA,    MODE_CBC},   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA */
        {0xC037, KEX_ECDHE_PSK,   ENC_AES,         DIG_SHA256, MODE_CBC},   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
        {0xC038, KEX_ECDHE_PSK,   ENC_AES256,      DIG_SHA384, MODE_CBC},   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
        {0xC039, KEX_ECDHE_PSK,   ENC_NULL,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA */
        {0xC03A, KEX_ECDHE_PSK,   ENC_NULL,        DIG_SHA256, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
        {0xC03B, KEX_ECDHE_PSK,   ENC_NULL,        DIG_SHA384, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA384 */
        {0xC072, KEX_ECDHE_ECDSA, ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
        {0xC073, KEX_ECDHE_ECDSA, ENC_CAMELLIA256, DIG_SHA384, MODE_CBC},   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
        {0xC074, KEX_ECDH_ECDSA,  ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
        {0xC075, KEX_ECDH_ECDSA,  ENC_CAMELLIA256, DIG_SHA384, MODE_CBC},   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
        {0xC076, KEX_ECDHE_RSA,   ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
        {0xC077, KEX_ECDHE_RSA,   ENC_CAMELLIA256, DIG_SHA384, MODE_CBC},   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
        {0xC078, KEX_ECDH_RSA,    ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
        {0xC079, KEX_ECDH_RSA,    ENC_CAMELLIA256, DIG_SHA384, MODE_CBC},   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
        {0xC07A, KEX_RSA,         ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC07B, KEX_RSA,         ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC07C, KEX_DHE_RSA,     ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC07D, KEX_DHE_RSA,     ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC07E, KEX_DH_RSA,      ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC07F, KEX_DH_RSA,      ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC080, KEX_DHE_DSS,     ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC081, KEX_DHE_DSS,     ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC082, KEX_DH_DSS,      ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC083, KEX_DH_DSS,      ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC084, KEX_DH_ANON,     ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC085, KEX_DH_ANON,     ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC086, KEX_ECDHE_ECDSA, ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC087, KEX_ECDHE_ECDSA, ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC088, KEX_ECDH_ECDSA,  ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC089, KEX_ECDH_ECDSA,  ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC08A, KEX_ECDHE_RSA,   ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC08B, KEX_ECDHE_RSA,   ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC08C, KEX_ECDH_RSA,    ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC08D, KEX_ECDH_RSA,    ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC08E, KEX_PSK,         ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC08F, KEX_PSK,         ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC090, KEX_DHE_PSK,     ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC091, KEX_DHE_PSK,     ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC092, KEX_RSA_PSK,     ENC_CAMELLIA128, DIG_SHA256, MODE_GCM},   /* TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
        {0xC093, KEX_RSA_PSK,     ENC_CAMELLIA256, DIG_SHA384, MODE_GCM},   /* TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
        {0xC094, KEX_PSK,         ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
        {0xC095, KEX_PSK,         ENC_CAMELLIA256, DIG_SHA384, MODE_CBC},   /* TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
        {0xC096, KEX_DHE_PSK,     ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
        {0xC097, KEX_DHE_PSK,     ENC_CAMELLIA256, DIG_SHA384, MODE_CBC},   /* TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
        {0xC098, KEX_RSA_PSK,     ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
        {0xC099, KEX_RSA_PSK,     ENC_CAMELLIA256, DIG_SHA384, MODE_CBC},   /* TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
        {0xC09A, KEX_ECDHE_PSK,   ENC_CAMELLIA128, DIG_SHA256, MODE_CBC},   /* TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
        {0xC09B, KEX_ECDHE_PSK,   ENC_CAMELLIA256, DIG_SHA384, MODE_CBC},   /* TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
        {0xC09C, KEX_RSA,         ENC_AES,         DIG_NA,     MODE_CCM},   /* TLS_RSA_WITH_AES_128_CCM */
        {0xC09D, KEX_RSA,         ENC_AES256,      DIG_NA,     MODE_CCM},   /* TLS_RSA_WITH_AES_256_CCM */
        {0xC09E, KEX_DHE_RSA,     ENC_AES,         DIG_NA,     MODE_CCM},   /* TLS_DHE_RSA_WITH_AES_128_CCM */
        {0xC09F, KEX_DHE_RSA,     ENC_AES256,      DIG_NA,     MODE_CCM},   /* TLS_DHE_RSA_WITH_AES_256_CCM */
        {0xC0A0, KEX_RSA,         ENC_AES,         DIG_NA,     MODE_CCM_8},   /* TLS_RSA_WITH_AES_128_CCM_8 */
        {0xC0A1, KEX_RSA,         ENC_AES256,      DIG_NA,     MODE_CCM_8},   /* TLS_RSA_WITH_AES_256_CCM_8 */
        {0xC0A2, KEX_DHE_RSA,     ENC_AES,         DIG_NA,     MODE_CCM_8},   /* TLS_DHE_RSA_WITH_AES_128_CCM_8 */
        {0xC0A3, KEX_DHE_RSA,     ENC_AES256,      DIG_NA,     MODE_CCM_8},   /* TLS_DHE_RSA_WITH_AES_256_CCM_8 */
        {0xC0A4, KEX_PSK,         ENC_AES,         DIG_NA,     MODE_CCM},   /* TLS_PSK_WITH_AES_128_CCM */
        {0xC0A5, KEX_PSK,         ENC_AES256,      DIG_NA,     MODE_CCM},   /* TLS_PSK_WITH_AES_256_CCM */
        {0xC0A6, KEX_DHE_PSK,     ENC_AES,         DIG_NA,     MODE_CCM},   /* TLS_DHE_PSK_WITH_AES_128_CCM */
        {0xC0A7, KEX_DHE_PSK,     ENC_AES256,      DIG_NA,     MODE_CCM},   /* TLS_DHE_PSK_WITH_AES_256_CCM */
        {0xC0A8, KEX_PSK,         ENC_AES,         DIG_NA,     MODE_CCM_8},   /* TLS_PSK_WITH_AES_128_CCM_8 */
        {0xC0A9, KEX_PSK,         ENC_AES256,      DIG_NA,     MODE_CCM_8},   /* TLS_PSK_WITH_AES_256_CCM_8 */
        {0xC0AA, KEX_DHE_PSK,     ENC_AES,         DIG_NA,     MODE_CCM_8},   /* TLS_PSK_DHE_WITH_AES_128_CCM_8 */
        {0xC0AB, KEX_DHE_PSK,     ENC_AES256,      DIG_NA,     MODE_CCM_8},   /* TLS_PSK_DHE_WITH_AES_256_CCM_8 */
        {0xC0AC, KEX_ECDHE_ECDSA, ENC_AES,         DIG_NA,     MODE_CCM},   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
        {0xC0AD, KEX_ECDHE_ECDSA, ENC_AES256,      DIG_NA,     MODE_CCM},   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
        {0xC0AE, KEX_ECDHE_ECDSA, ENC_AES,         DIG_NA,     MODE_CCM_8},   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
        {0xC0AF, KEX_ECDHE_ECDSA, ENC_AES256,      DIG_NA,     MODE_CCM_8},   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
        {0xCCA8, KEX_ECDHE_RSA,   ENC_CHACHA20,    DIG_SHA256, MODE_POLY1305}, /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
        {0xCCA9, KEX_ECDHE_ECDSA, ENC_CHACHA20,    DIG_SHA256, MODE_POLY1305}, /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
        {0xCCAA, KEX_DHE_RSA,     ENC_CHACHA20,    DIG_SHA256, MODE_POLY1305}, /* TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
        {0xCCAB, KEX_PSK,         ENC_CHACHA20,    DIG_SHA256, MODE_POLY1305}, /* TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 */
        {0xCCAC, KEX_ECDHE_PSK,   ENC_CHACHA20,    DIG_SHA256, MODE_POLY1305}, /* TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
        {0xCCAD, KEX_DHE_PSK,     ENC_CHACHA20,    DIG_SHA256, MODE_POLY1305}, /* TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
        {0xCCAE, KEX_RSA_PSK,     ENC_CHACHA20,    DIG_SHA256, MODE_POLY1305}, /* TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 */
        /* GM */
        {0xe001, KEX_ECDHE_SM2,   ENC_SM1,         DIG_SM3,    MODE_CBC},        /* ECDHE_SM1_SM3 */
        {0xe003, KEX_ECC_SM2,     ENC_SM1,         DIG_SM3,    MODE_CBC},        /* ECC_SM1_SM3 */
        {0xe005, KEX_IBSDH_SM9,   ENC_SM1,         DIG_SM3,    MODE_CBC},        /* IBSDH_SM1_SM3 */
        {0xe007, KEX_IBC_SM9,     ENC_SM1,         DIG_SM3,    MODE_CBC},        /* IBC_SM1_SM3 */
        {0xe009, KEX_RSA,         ENC_SM1,         DIG_SM3,    MODE_CBC},        /* RSA_SM1_SM3 */
        {0xe00a, KEX_RSA,         ENC_SM1,         DIG_SHA,    MODE_CBC},        /* RSA_SM1_SHA1 */
        {0xe011, KEX_ECDHE_SM2,   ENC_SM4,         DIG_SM3,    MODE_CBC},        /* ECDHE_SM4_SM3 */
        {0xe013, KEX_ECC_SM2,     ENC_SM4,         DIG_SM3,    MODE_CBC},        /* ECC_SM4_SM3 */
        {0xe015, KEX_IBSDH_SM9,   ENC_SM4,         DIG_SM3,    MODE_CBC},        /* IBSDH_SM4_SM3 */
        {0xe017, KEX_IBC_SM9,     ENC_SM4,         DIG_SM3,    MODE_CBC},        /* IBC_SM4_SM3 */
        {0xe019, KEX_RSA,         ENC_SM4,         DIG_SM3,    MODE_CBC},        /* RSA_SM4_SM3 */
        {0xe01a, KEX_RSA,         ENC_SM4,         DIG_SHA,    MODE_CBC},        /* RSA_SM4_SHA1 */
        {-1, 0, 0, 0,                                          MODE_STREAM}
};

#define MAX_BLOCK_SIZE 16
#define MAX_KEY_SIZE 32

const SslCipherSuite *
ssl_find_cipher(int num);

int
ssl_get_cipher_algo(const SslCipherSuite *cipher_suite);

guint
ssl_get_cipher_blocksize(const SslCipherSuite *cipher_suite);

static guint
ssl_get_cipher_export_keymat_size(int cipher_suite_num);

/* Digests, Ciphers and Cipher Suites registry }}} */


/* HMAC and the Pseudorandom function {{{ */
static void
tls_hash(StringInfo *secret, StringInfo *seed, gint md,
         StringInfo *out, guint out_len);

static gint tls_handshake_hash(SslDecryptSession *ssl, StringInfo *out);

static gint tls12_handshake_hash(SslDecryptSession *ssl, gint md, StringInfo *out);

static gboolean
tls_prf(StringInfo *secret, const gchar *usage,
        StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len);

static gboolean
tls12_prf(gint md, StringInfo *secret, const gchar *usage,
          StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len);

static void
ssl3_generate_export_iv(StringInfo *r1, StringInfo *r2,
                        StringInfo *out, guint out_len);

static gboolean
ssl3_prf(StringInfo *secret, const gchar *usage,
         StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len);

/* out_len is the wanted output length for the pseudorandom function.
 * Ensure that ssl->cipher_suite is set. */
static gboolean
prf(SslDecryptSession *ssl, StringInfo *secret, const gchar *usage,
    StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len);

int ssl_init_decoder(SslDecoder *dec, const SslCipherSuite *cipher_suite, gint cipher_algo,
                     gint compression, guint8 *mk, guint8 *sk, guint8 *iv, guint iv_length);

int
ssl_generate_keyring_material(SslDecryptSession *ssl_session);

static gint
tls_check_mac(SslDecoder *decoder, gint ct, gint ver, guint8 *data,
              guint32 datalen, guint8 *mac);

static int
ssl3_check_mac(SslDecoder *decoder, int ct, guint8 *data,
               guint32 datalen, guint8 *mac);

static gint
dtls_check_mac(SslDecoder *decoder, gint ct, int ver, guint8 *data,
               guint32 datalen, guint8 *mac);

/* Decryption integrity check }}} */

static gboolean
tls_decrypt_aead_record(SslDecryptSession *ssl, SslDecoder *decoder,
#ifdef HAVE_LIBGCRYPT_AEAD
                        guint8 ct, guint16 record_version,
#else
        guint8 ct _U_, guint16 record_version _U_,
#endif
                        gboolean ignore_mac_failed
#ifndef HAVE_LIBGCRYPT_AEAD
        _U_
#endif
        ,
                        const guchar *in, guint16 inl,
#ifdef HAVE_LIBGCRYPT_AEAD
                        const guchar *cid, guint8 cidl,
#else
        const guchar *cid _U_, guint8 cidl _U_,
#endif
                        StringInfo *out_str, guint *outl);

#ifdef HAVE_ZLIB
static int
ssl_decompress_record(SslDecompress* decomp, const guchar* in, guint inl, StringInfo* out_str, guint* outl)
{
    gint err;

    switch (decomp->compression) {
        case 1:  /* DEFLATE */
            err = Z_OK;
            if (out_str->data_len < 16384) {  /* maximal plain length */
                ssl_data_realloc(out_str, 16384);
            }
#ifdef z_const
            decomp->istream.next_in = in;
#else
DIAG_OFF(cast-qual)
            decomp->istream.next_in = (Bytef *)in;
DIAG_ON(cast-qual)
#endif
            decomp->istream.avail_in = inl;
            decomp->istream.next_out = out_str->data;
            decomp->istream.avail_out = out_str->data_len;
            if (inl > 0)
                err = inflate(&decomp->istream, Z_SYNC_FLUSH);
            if (err != Z_OK) {
                ssl_debug_printf("ssl_decompress_record: inflate() failed - %d\n", err);
                return -1;
            }
            *outl = out_str->data_len - decomp->istream.avail_out;
            break;
        default:
            ssl_debug_printf("ssl_decompress_record: unsupported compression method %d\n", decomp->compression);
            return -1;
    }
    return 0;
}
#else

int
ssl_decompress_record(SslDecompress *decomp _U_, const guchar *in _U_, guint inl _U_, StringInfo *out_str _U_,
                      guint *outl _U_);

#endif
/* Record Decompression (after decryption) }}} */


/* Record decryption glue based on security parameters {{{ */
/* Assume that we are called only for a non-NULL decoder which also means that
 * we have a non-NULL decoder->cipher_suite. */
gint
ssl_decrypt_record(SslDecryptSession *ssl, SslDecoder *decoder, guint8 ct, guint16 record_version,
                   gboolean ignore_mac_failed,
                   const guchar *in, guint16 inl, const guchar *cid, guint8 cidl,
                   StringInfo *comp_str, StringInfo *out_str, guint *outl);

#endif //TLSEXTRACTOR_WIRESHARK_H
