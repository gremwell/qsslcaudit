
#include "tlshello.h"

#include <QtEndian>
#include <QDebug>

// this we need only for TlsClientHello type
#include "ssltest.h"

// taken from packet-tls.c, wireshark source code

#define SSL_ID_HANDSHAKE               0x16
#define SSL_ID_APP_DATA                0x17

#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304

#define SSL2_HND_CLIENT_HELLO          0x01

#define SSL_HND_HELLO_REQUEST          0
#define SSL_HND_CLIENT_HELLO           1
#define SSL_HND_SERVER_HELLO           2
#define SSL_HND_HELLO_VERIFY_REQUEST   3
#define SSL_HND_NEWSESSION_TICKET      4
#define SSL_HND_END_OF_EARLY_DATA      5
#define SSL_HND_HELLO_RETRY_REQUEST    6
#define SSL_HND_ENCRYPTED_EXTENSIONS   8
#define SSL_HND_CERTIFICATE            11
#define SSL_HND_SERVER_KEY_EXCHG       12
#define SSL_HND_CERT_REQUEST           13
#define SSL_HND_SVR_HELLO_DONE         14
#define SSL_HND_CERT_VERIFY            15
#define SSL_HND_CLIENT_KEY_EXCHG       16
#define SSL_HND_FINISHED               20
#define SSL_HND_CERT_URL               21
#define SSL_HND_CERT_STATUS            22
#define SSL_HND_SUPPLEMENTAL_DATA      23
#define SSL_HND_KEY_UPDATE             24
#define SSL_HND_COMPRESSED_CERTIFICATE 25
/* Encrypted Extensions was NextProtocol in draft-agl-tls-nextprotoneg-03
 * and changed in draft 04. Not to be confused with TLS 1.3 EE. */
#define SSL_HND_ENCRYPTED_EXTS         67

#define TLS_MAX_RECORD_LENGTH 0x4000

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
/* 26-34  Unassigned*/
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
#define SSL_HND_HELLO_EXT_GREASE_0A0A                   2570
#define SSL_HND_HELLO_EXT_GREASE_1A1A                   6682
#define SSL_HND_HELLO_EXT_GREASE_2A2A                   10794
#define SSL_HND_HELLO_EXT_NPN                           13172 /* 0x3374 */
#define SSL_HND_HELLO_EXT_GREASE_3A3A                   14906
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

#define SSL_HND_CERT_STATUS_TYPE_OCSP        1
#define SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI  2

typedef struct _value_string {
    quint32 value;
    const char *strptr;
} value_string;

static const value_string ssl_20_cipher_suites[] = {
    { 0x000000, "TLS_NULL_WITH_NULL_NULL" },
    { 0x000001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x000002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x000003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x000004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x000005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x000006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x000007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x000008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x00000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x00000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x000010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x000013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x000016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x000018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x000019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x00001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x00001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA" },
    { 0x00001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
#if 0
    { 0x00001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
#endif
    /* RFC 2712 */
    { 0x00001E, "TLS_KRB5_WITH_DES_CBC_SHA" },
    { 0x00001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
    { 0x000020, "TLS_KRB5_WITH_RC4_128_SHA" },
    { 0x000021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
    { 0x000022, "TLS_KRB5_WITH_DES_CBC_MD5" },
    { 0x000023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
    { 0x000024, "TLS_KRB5_WITH_RC4_128_MD5" },
    { 0x000025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
    { 0x000026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
    { 0x000027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
    { 0x000028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
    { 0x000029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
    { 0x00002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x00002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
    /* RFC 4785 */
    { 0x00002C, "TLS_PSK_WITH_NULL_SHA" },
    { 0x00002D, "TLS_DHE_PSK_WITH_NULL_SHA" },
    { 0x00002E, "TLS_RSA_PSK_WITH_NULL_SHA" },
    /* RFC 5246 */
    { 0x00002f, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x000035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x00003B, "TLS_RSA_WITH_NULL_SHA256" },
    { 0x00003C, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00003D, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x00003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x000040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x000041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000047, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x000048, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x000049, "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA" },
    { 0x00004A, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00004B, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00004C, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x000060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x000061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    { 0x000062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    { 0x000067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x000068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x000069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x00006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
    { 0x00006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
    /* 0x00,0x6E-83 Unassigned  */
    { 0x000084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* RFC 4279 */
    { 0x00008A, "TLS_PSK_WITH_RC4_128_SHA" },
    { 0x00008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x00008C, "TLS_PSK_WITH_AES_128_CBC_SHA" },
    { 0x00008D, "TLS_PSK_WITH_AES_256_CBC_SHA" },
    { 0x00008E, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
    { 0x00008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x000090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x000091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x000092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
    { 0x000093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x000094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
    { 0x000095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
    /* RFC 4162 */
    { 0x000096, "TLS_RSA_WITH_SEED_CBC_SHA" },
    { 0x000097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
    { 0x000098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
    { 0x000099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
    { 0x00009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
    { 0x00009B, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
    /* RFC 5288 */
    { 0x00009C, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00009D, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x0000A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x0000A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x0000A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x0000A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x0000A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x0000A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x0000A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
    { 0x0000A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
    /* RFC 5487 */
    { 0x0000A8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000A9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AE, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000AF, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B0, "TLS_PSK_WITH_NULL_SHA256" },
    { 0x0000B1, "TLS_PSK_WITH_NULL_SHA384" },
    { 0x0000B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
    { 0x0000B5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
    { 0x0000B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
    { 0x0000B9, "TLS_RSA_PSK_WITH_NULL_SHA384" },
    /* From RFC 5932 */
    { 0x0000BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
    /* 0x00,0xC6-FE Unassigned  */
    { 0x0000FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
    /* 0x01-BF,* Unassigned  */
    /* From RFC 4492 */
    { 0x00c001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x00c002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x00c003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00c005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x00c006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
    { 0x00c007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
    { 0x00c008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00c00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x00c00b, "TLS_ECDH_RSA_WITH_NULL_SHA" },
    { 0x00c00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
    { 0x00c00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00c00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00c010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
    { 0x00c011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
    { 0x00c012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00c014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00c015, "TLS_ECDH_anon_WITH_NULL_SHA" },
    { 0x00c016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
    { 0x00c017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
    { 0x00c019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
    /* RFC 5054 */
    { 0x00C01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
    { 0x00C01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00C01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
    { 0x00C020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
    { 0x00C021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00C022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
    /* RFC 5589 */
    { 0x00C023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
    /* RFC 5489 */
    { 0x00C033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
    { 0x00C034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x00C036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x00C037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00C038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00C039, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
    { 0x00C03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
    { 0x00C03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },
    /* 0xC0,0x3C-FF Unassigned
            0xC1-FD,* Unassigned
            0xFE,0x00-FD Unassigned
            0xFE,0xFE-FF Reserved to avoid conflicts with widely deployed implementations [Pasi_Eronen]
            0xFF,0x00-FF Reserved for Private Use [RFC5246]
            */

    /* old numbers used in the beginning
     * http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
    { 0x00CC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },

    /* http://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305 */
    { 0x00CCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },

    /* http://tools.ietf.org/html/draft-josefsson-salsa20-tls */
    { 0x00E410, "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E411, "TLS_RSA_WITH_SALSA20_SHA1" },
    { 0x00E412, "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E413, "TLS_ECDHE_RSA_WITH_SALSA20_SHA1" },
    { 0x00E414, "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E415, "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1" },
    { 0x00E416, "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E417, "TLS_PSK_WITH_SALSA20_SHA1" },
    { 0x00E418, "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E419, "TLS_ECDHE_PSK_WITH_SALSA20_SHA1" },
    { 0x00E41A, "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E41B, "TLS_RSA_PSK_WITH_SALSA20_SHA1" },
    { 0x00E41C, "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E41D, "TLS_DHE_PSK_WITH_SALSA20_SHA1" },
    { 0x00E41E, "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E41F, "TLS_DHE_RSA_WITH_SALSA20_SHA1" },

    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0x00fefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0x00feff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* note that ciphersuites of {0x00????} are TLS cipher suites in
     * a sslv2 client hello message; the ???? above is the two-byte
     * tls cipher suite id
     */

    { 0x010080, "SSL2_RC4_128_WITH_MD5" },
    { 0x020080, "SSL2_RC4_128_EXPORT40_WITH_MD5" },
    { 0x030080, "SSL2_RC2_128_CBC_WITH_MD5" },
    { 0x040080, "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5" },
    { 0x050080, "SSL2_IDEA_128_CBC_WITH_MD5" },
    { 0x060040, "SSL2_DES_64_CBC_WITH_MD5" },
    { 0x0700c0, "SSL2_DES_192_EDE3_CBC_WITH_MD5" },
    { 0x080080, "SSL2_RC4_64_WITH_MD5" },

    { 0x00, nullptr }
};

QString cipherStringFromId(unsigned int id)
{
    for (unsigned int i = 0; i < sizeof(ssl_20_cipher_suites)/sizeof(ssl_20_cipher_suites[0]); i++) {
        if (ssl_20_cipher_suites[i].value == id)
            return QString(ssl_20_cipher_suites[i].strptr);
    }
    return QString("");
}

bool isUnknownCipher(unsigned int id)
{
    for (unsigned int i = 0; i < sizeof(ssl_20_cipher_suites)/sizeof(ssl_20_cipher_suites[0]); i++) {
        if (ssl_20_cipher_suites[i].value == id)
            return false;
    }
    return true;
}

/*
 * Supported Groups (formerly named "EC Named Curve").
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 */
static const value_string ssl_extension_curves[] = {
    {  1, "sect163k1" },
    {  2, "sect163r1" },
    {  3, "sect163r2" },
    {  4, "sect193r1" },
    {  5, "sect193r2" },
    {  6, "sect233k1" },
    {  7, "sect233r1" },
    {  8, "sect239k1" },
    {  9, "sect283k1" },
    { 10, "sect283r1" },
    { 11, "sect409k1" },
    { 12, "sect409r1" },
    { 13, "sect571k1" },
    { 14, "sect571r1" },
    { 15, "secp160k1" },
    { 16, "secp160r1" },
    { 17, "secp160r2" },
    { 18, "secp192k1" },
    { 19, "secp192r1" },
    { 20, "secp224k1" },
    { 21, "secp224r1" },
    { 22, "secp256k1" },
    { 23, "secp256r1" },
    { 24, "secp384r1" },
    { 25, "secp521r1" },
    { 26, "brainpoolP256r1" }, /* RFC 7027 */
    { 27, "brainpoolP384r1" }, /* RFC 7027 */
    { 28, "brainpoolP512r1" }, /* RFC 7027 */
    { 29, "x25519" }, /* RFC 8446 / RFC 8422 */
    { 30, "x448" }, /* RFC 8446 / RFC 8422 */
    { 256, "ffdhe2048" }, /* RFC 7919 */
    { 257, "ffdhe3072" }, /* RFC 7919 */
    { 258, "ffdhe4096" }, /* RFC 7919 */
    { 259, "ffdhe6144" }, /* RFC 7919 */
    { 260, "ffdhe8192" }, /* RFC 7919 */
    { 2570, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 6682, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 10794, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 14906, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 19018, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 23130, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 27242, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 31354, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 35466, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 39578, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 43690, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 47802, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 51914, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 56026, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 60138, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 64250, "Reserved (GREASE)" }, /* draft-ietf-tls-grease */
    { 0xFF01, "arbitrary_explicit_prime_curves" },
    { 0xFF02, "arbitrary_explicit_char2_curves" },
    { 0x00, nullptr }
};

QString extensionCurveStringFromId(unsigned int id)
{
    for (unsigned int i = 0; i < sizeof(ssl_extension_curves)/sizeof(ssl_extension_curves[0]); i++) {
        if (ssl_extension_curves[i].value == id)
            return QString(ssl_extension_curves[i].strptr);
    }
    return QString("");
}

bool isUnknownExtensionCurve(unsigned int id)
{
    for (unsigned int i = 0; i < sizeof(ssl_extension_curves)/sizeof(ssl_extension_curves[0]); i++) {
        if (ssl_extension_curves[i].value == id) {
            if (QString(ssl_extension_curves[i].strptr).contains("GREASE", Qt::CaseInsensitive)) {
                return true;
            } else {
                return false;
            }
        }
    }
    return true;
}

static quint8 getUint8(const QByteArray &packet, int offset)
{
    if (offset < packet.size())
        return static_cast<quint8>(packet.at(offset));
    return 0;
}

static quint16 getUint16(const QByteArray &packet, int offset)
{
    if (offset + 1 < packet.size())
        return qFromBigEndian<quint16>((uchar *)packet.mid(offset, 2).data());
    return 0;
}

static quint32 getUint32(const QByteArray &packet, int offset)
{
    if (offset + 3 < packet.size())
        return qFromBigEndian<quint32>((uchar *)packet.mid(offset, 4).data());
    return 0;
}

bool is_sslv2_clienthello(const QByteArray &packet)
{
    /*
     * Detect SSL 2.0 compatible Client Hello as used in SSLv3 and TLS.
     *
     * https://tools.ietf.org/html/rfc5246#appendix-E.2
     *  uint8 V2CipherSpec[3];
     *  struct {
     *      uint16 msg_length;          // 0: highest bit must be 1
     *      uint8 msg_type;             // 2: 1 for Client Hello
     *      Version version;            // 3: equal to ClientHello.client_version
     *      uint16 cipher_spec_length;  // 5: cannot be 0, must be multiple of 3
     *      uint16 session_id_length;   // 7: zero or 16 (in TLS 1.0)
     *      uint16 challenge_length;    // 9: must be 32
     *      // length so far: 2 + 1 + 2 + 2 + 2 + 2 = 11
     *      V2CipherSpec cipher_specs[V2ClientHello.cipher_spec_length];    // len: min 3
     *      opaque session_id[V2ClientHello.session_id_length];             // len: zero or 16
     *      opaque challenge[V2ClientHello.challenge_length;                // len: 32
     *      // min. length: 11 + 3 + (0 or 16) + 32 = 46 or 62
     *  } V2ClientHello;
     */
    if (packet.size() < 39) {
        return false;
    }

    /* Assume that message length is less than 256 (at most 64 cipherspecs). */
    if (getUint8(packet, 0) != 0x80) {
        return false;
    }

    /* msg_type must be 1 for Client Hello */
    if (getUint8(packet, 2) != 1) {
        return false;
    }

    /* cipher spec length must be a non-zero multiple of 3 */
    quint16 cipher_spec_length = getUint16(packet, 5);
    if (cipher_spec_length == 0 || cipher_spec_length % 3 != 0) {
        return false;
    }

    /* session ID length must be 0 or 16 in TLS 1.0 */
    quint16 session_id_length = getUint16(packet, 7);
    if (session_id_length != 0 && session_id_length != 16) {
        return false;
    }

    /* Challenge Length must be between 16 and 32 */
    quint16 challenge_length = getUint16(packet, 9);
    if ((challenge_length < 16) || (challenge_length > 32)) {
        return false;
    }

    return true;
}

bool is_sslv3_or_tls(const QByteArray &packet)
{
    quint8 content_type;
    quint16 protocol_version, record_length;

    /*
     * Heuristics should match a non-empty TLS record:
     * ContentType (1), ProtocolVersion (2), Length (2), fragment (...)
     */
    if (packet.size() < 6) {
        return false;
    }

    content_type = getUint8(packet, 0);
    protocol_version = getUint16(packet, 1);
    record_length = getUint16(packet, 3);

    /* These are the common types. */
    if (content_type != SSL_ID_HANDSHAKE && content_type != SSL_ID_APP_DATA) {
        return false;
    }

    /*
     * Match SSLv3, TLS 1.0/1.1/1.2 (TLS 1.3 uses same value as TLS 1.0). Most
     * likely you'll see 0x300 (SSLv3) or 0x301 (TLS 1.1) for interoperability
     * reasons. Per RFC 5246 we should accept any 0x3xx value, but this is just
     * a heuristic that catches common/likely cases.
     */
    if (protocol_version != SSLV3_VERSION &&
        protocol_version != TLSV1_VERSION &&
        protocol_version != TLSV1DOT1_VERSION &&
        protocol_version != TLSV1DOT2_VERSION) {
        return false;
    }

    /* Check for sane length, see also ssl_check_record_length in packet-tls-utils.c */
    if (record_length == 0 || record_length >= TLS_MAX_RECORD_LENGTH + 2048) {
        return false;
    }

    return true;
}

bool is_sslv3_or_tls_hello(const QByteArray &packet)
{
    quint8 msg_type = getUint8(packet, 5);

    if (msg_type == SSL_HND_CLIENT_HELLO)
        return true;

    return false;
}

void dissect_ssl2_hnd_client_hello(const QByteArray &packet, TlsClientHelloInfo *tlsHelloInfo)
{
    /* struct {
     *    uint8 msg_type;
     *     Version version;
     *     uint16 cipher_spec_length;
     *     uint16 session_id_length;
     *     uint16 challenge_length;
     *     V2CipherSpec cipher_specs[V2ClientHello.cipher_spec_length];
     *     opaque session_id[V2ClientHello.session_id_length];
     *     Random challenge;
     * } V2ClientHello;
     *
     * Note: when we get here, offset's already pointing at Version
     *
     */
    quint16 cipher_spec_length;
    quint16 session_id_length;
    quint16 challenge_length;
    int offset = 3;

    tlsHelloInfo->version = getUint16(packet, offset);

    offset += 2;

    cipher_spec_length = getUint16(packet, offset);

    offset += 2;

    session_id_length = getUint16(packet, offset);

    offset += 2;

    challenge_length = getUint16(packet, offset);

    offset += 2;

    /* iterate through the cipher specs, showing them */
    while (cipher_spec_length > 0) {
        quint32 cipher_spec = 0;
        char cipher_spec_buf[3];

        cipher_spec_buf[0] = packet.at(offset + 2);
        cipher_spec_buf[1] = packet.at(offset + 1);
        cipher_spec_buf[2] = packet.at(offset + 0);
        memcpy(&cipher_spec, cipher_spec_buf, 3);

        tlsHelloInfo->ciphers << cipher_spec;

        offset += 3;        /* length of one cipher spec */
        cipher_spec_length -= 3;
    }

    /* if there's a session id, show it */
    if (session_id_length > 0) {
        tlsHelloInfo->session_id = packet.mid(offset, session_id_length);

        offset += session_id_length;
    }

    /* if there's a challenge, show it */
    if (challenge_length > 0) {
        tlsHelloInfo->challenge = packet.mid(offset, challenge_length);
    }
}

static int ssl_dissect_hnd_hello_common(const QByteArray &packet, int offset, TlsClientHelloInfo *ret)
{
    quint8 sessid_length;
    //quint8 draft_version = session->tls13_draft_version;

    //ti_rnd = proto_tree_add_item(tree, hf->hf.hs_random, tvb, offset, 32, ENC_NA);

    if (true/*session->version != TLSV1DOT3_VERSION*/) { /* No time on first bytes random with TLS 1.3 */
        ret->random_time = getUint32(packet, offset);
        offset += 4;

        /* show the random bytes */
        ret->random = packet.mid(offset, 28);
        offset += 28;
    } else {
        offset += 32;
    }

    /* No Session ID with TLS 1.3 on Server Hello before draft -22 */
    if (true/*from_server == 0 || !(session->version == TLSV1DOT3_VERSION && draft_version > 0 && draft_version < 22)*/) {
        /* show the session id (length followed by actual Session ID) */
        sessid_length = getUint8(packet, offset);
        offset++;

        if (sessid_length > 0) {
            ret->session_id = packet.mid(offset, sessid_length);
            offset += sessid_length;
        }
    }

    return offset;
}

static int ssl_dissect_hnd_hello_ext_status_request(const QByteArray &packet, int offset, TlsClientHelloInfo *ret)
{
    /* TLS 1.2/1.3 status_request Client Hello Extension.
     * TLS 1.2 status_request_v2 CertificateStatusRequestItemV2 type.
     * https://tools.ietf.org/html/rfc6066#section-8 (status_request)
     * https://tools.ietf.org/html/rfc6961#section-2.2 (status_request_v2)
     *  struct {
     *      CertificateStatusType status_type;
     *      uint16 request_length;  // for status_request_v2
     *      select (status_type) {
     *          case ocsp: OCSPStatusRequest;
     *          case ocsp_multi: OCSPStatusRequest;
     *      } request;
     *  } CertificateStatusRequest; // CertificateStatusRequestItemV2
     *
     *  enum { ocsp(1), ocsp_multi(2), (255) } CertificateStatusType;
     *  struct {
     *      ResponderID responder_id_list<0..2^16-1>;
     *      Extensions  request_extensions;
     *  } OCSPStatusRequest;
     *  opaque ResponderID<1..2^16-1>;
     *  opaque Extensions<0..2^16-1>;
     */
    quint8    cert_status_type;

    cert_status_type = getUint8(packet, offset);
    offset++;

    switch (cert_status_type) {
    case SSL_HND_CERT_STATUS_TYPE_OCSP:
    case SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI:
        {
            quint32 responder_id_list_len;
            quint32 request_extensions_len;

            /* ResponderID responder_id_list<0..2^16-1> */
            responder_id_list_len = getUint16(packet, offset);
            offset += 2;
            if (responder_id_list_len != 0) {
                ret->hnd_hello.cert_status_type_ocsp_responder_id_list = packet.mid(offset, static_cast<int>(responder_id_list_len));
            }
            offset += responder_id_list_len;

            /* opaque Extensions<0..2^16-1> */
            request_extensions_len = getUint16(packet, offset);
            offset += 2;
            if (request_extensions_len != 0) {
                if (responder_id_list_len != 0) {
                    ret->hnd_hello.cert_status_type_ocsp_responder_id_list = packet.mid(offset, static_cast<int>(request_extensions_len));
                }
            }
            offset += request_extensions_len;
            break;
        }
    }

    return offset;
}

static int ssl_dissect_hnd_hello_ext_status_request_v2(const QByteArray &packet, int offset, TlsClientHelloInfo *ret)
{
    /* https://tools.ietf.org/html/rfc6961#section-2.2
     *  struct {
     *    CertificateStatusRequestItemV2 certificate_status_req_list<1..2^16-1>;
     *  } CertificateStatusRequestListV2;
     */
    quint32 req_list_length, next_offset;

    /* CertificateStatusRequestItemV2 certificate_status_req_list<1..2^16-1> */
    req_list_length = getUint16(packet, offset);
    offset += 2;
    next_offset = static_cast<quint32>(offset) + req_list_length;

    while (static_cast<quint32>(offset) < next_offset) {
        offset = ssl_dissect_hnd_hello_ext_status_request(packet, offset, ret);
    }

    return offset;
}

static int ssl_dissect_hnd_hello_ext_supported_versions(const QByteArray &packet, int offset, TlsClientHelloInfo *ret)
{

   /* RFC 8446 Section 4.2.1
    * struct {
    *     ProtocolVersion versions<2..254>; // ClientHello
    * } SupportedVersions;
    * Note that ServerHello and HelloRetryRequest are handled by the caller.
    */
    quint32 versions_length;
    int next_offset;

    /* ProtocolVersion versions<2..254> */
    versions_length = getUint8(packet, offset);
    offset++;
    next_offset = offset + static_cast<int>(versions_length);

    quint16 version;

    while (offset + 2 <= next_offset) {
        version = getUint16(packet, offset);
        ret->hnd_hello.supported_versions << version;
        offset += 2;
    }
    if (offset != next_offset) {
        offset = next_offset;
    }

    /* XXX remove this when draft 19 support is dropped,
     * this is only required for early data decryption. */
//    if (max_draft_version) {
//        session->tls13_draft_version = max_draft_version;
//    }

    return offset;
}

static int ssl_dissect_hnd_hello_ext_ec_point_formats(const QByteArray &packet, int offset, TlsClientHelloInfo *ret)
{
    quint8 ecpf_length;

    ecpf_length = getUint8(packet, offset);
    offset += 1;

    /* make this a subtree */

    /* loop over all point formats */
    while (ecpf_length > 0) {
        ret->hnd_hello.ec_point_formats << getUint8(packet, offset);
        offset++;
        ecpf_length--;
    }

    return offset;
}

static int ssl_dissect_hnd_hello_ext_supported_groups(const QByteArray &packet, int offset, int offset_end, TlsClientHelloInfo *ret)
{
    /* RFC 8446 Section 4.2.7
     *  enum { ..., (0xFFFF) } NamedGroup;
     *  struct {
     *      NamedGroup named_group_list<2..2^16-1>
     *  } NamedGroupList;
     *
     * NOTE: "NamedCurve" (RFC 4492) is renamed to "NamedGroup" (RFC 7919) and
     * the extension itself from "elliptic_curves" to "supported_groups".
     */
    quint32 groups_length;
    int next_offset;

    /* NamedGroup named_group_list<2..2^16-1> */
    groups_length = getUint16(packet, offset);
    offset += 2;
    next_offset = offset + static_cast<int>(groups_length);

    /* make this a subtree */

    /* loop over all groups */
    while (offset + 2 <= offset_end) {
        ret->hnd_hello.supported_groups << getUint16(packet, offset);
        offset += 2;
    }
    if (offset != next_offset) {
        offset = next_offset;
    }

    return offset;
}

static int ssl_dissect_hnd_hello_ext_session_ticket(const QByteArray &packet, int offset, int offset_end, TlsClientHelloInfo *ret)
{
    int ext_len = offset_end - offset;
    ret->hnd_hello.session_ticket_data = packet.mid(offset, ext_len);
    return offset + ext_len;
}

static int ssl_dissect_hash_alg_list(const QByteArray &packet, int offset, TlsClientHelloInfo *ret)
{
    /* https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
     *  struct {
     *       HashAlgorithm hash;
     *       SignatureAlgorithm signature;
     *  } SignatureAndHashAlgorithm;
     *  SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
     */
    int sh_alg_length;
    int next_offset;

    /* SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2> */
    sh_alg_length = getUint16(packet, offset);
    offset += 2;
    next_offset = offset + sh_alg_length;

    while (offset + 2 <= next_offset) {
        quint8 hashalg, sigalg;

        hashalg = getUint8(packet, offset);
        sigalg = getUint8(packet, offset + 1);

        ret->hnd_hello.sig_hash_algs << QPair<quint8, quint8>(hashalg, sigalg);

        offset += 2;
    }

    if (offset != next_offset) {
        offset = next_offset;
    }

    return offset;
}

static int ssl_dissect_hnd_hello_ext_sig_hash_algs(const QByteArray &packet, int offset, TlsClientHelloInfo *ret)
{
    return ssl_dissect_hash_alg_list(packet, offset, ret);
}

static int ssl_dissect_hnd_hello_ext_npn(const QByteArray &packet, int offset, int offset_end, TlsClientHelloInfo *ret)
{
    /* https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04#page-3
     *   The "extension_data" field of a "next_protocol_negotiation" extension
     *   in a "ServerHello" contains an optional list of protocols advertised
     *   by the server.  Protocols are named by opaque, non-empty byte strings
     *   and the list of protocols is serialized as a concatenation of 8-bit,
     *   length prefixed byte strings.  Implementations MUST ensure that the
     *   empty string is not included and that no byte strings are truncated.
     */
    quint32 npn_length;

    /* List is optional, do not add tree if there are no entries. */
    if (offset == offset_end) {
        return offset;
    }

    while (offset < offset_end) {
        /* non-empty, 8-bit length prefixed strings means range 1..255 */
        npn_length = getUint8(packet, offset);
        offset++;

        ret->hnd_hello.npn << packet.mid(offset, static_cast<int>(npn_length));

        offset += npn_length;
    }

    return offset;
}

static int ssl_dissect_hnd_hello_ext_alpn(const QByteArray &packet, int offset, TlsClientHelloInfo *ret)
{

    /* https://tools.ietf.org/html/rfc7301#section-3.1
     *  opaque ProtocolName<1..2^8-1>;
     *  struct {
     *      ProtocolName protocol_name_list<2..2^16-1>
     *  } ProtocolNameList;
     */
    quint32 alpn_length, name_length;
    int next_offset;

    /* ProtocolName protocol_name_list<2..2^16-1> */
    alpn_length = getUint16(packet, offset);
    offset += 2;
    next_offset = offset + static_cast<int>(alpn_length);

    /* Parse list (note missing check for end of vector, ssl_add_vector below
     * ensures that data is always available.) */
    while (offset < next_offset) {
        /* opaque ProtocolName<1..2^8-1> */
        name_length = getUint8(packet, offset);
        offset++;

        ret->hnd_hello.alpn << packet.mid(offset, static_cast<int>(name_length));

        offset += name_length;
    }

    return offset;
}

static int ssl_dissect_hnd_hello_ext_server_name(const QByteArray &packet, int offset, int offset_end, TlsClientHelloInfo *ret)
{
    /* https://tools.ietf.org/html/rfc6066#section-3
     *
     *  struct {
     *      NameType name_type;
     *      select (name_type) {
     *          case host_name: HostName;
     *      } name;
     *  } ServerName;
     *
     *  enum {
     *      host_name(0), (255)
     *  } NameType;
     *
     *  opaque HostName<1..2^16-1>;
     *
     *  struct {
     *      ServerName server_name_list<1..2^16-1>
     *  } ServerNameList;
     */
    quint32 list_length, server_name_length;
    int next_offset;

    /* The server SHALL include "server_name" extension with empty data. */
    if (offset == offset_end) {
        return offset;
    }

    /* ServerName server_name_list<1..2^16-1> */
    list_length = getUint16(packet, offset);
    offset += 2;
    next_offset = offset + static_cast<int>(list_length);

    while (offset < next_offset) {
        quint8 server_name_type = getUint8(packet, offset);
        offset++;

        /* opaque HostName<1..2^16-1> */
        server_name_length = getUint16(packet, offset);
        offset += 2;

        QByteArray server_name(packet.mid(offset, static_cast<int>(server_name_length)));
        ret->hnd_hello.server_name << qMakePair(server_name_type, server_name);
        offset += server_name_length;
    }
    return offset;
}

static int ssl_dissect_hnd_extension(const QByteArray &packet, int offset, int hnd_type, TlsClientHelloInfo *ret)
{
    quint32 exts_len;
    quint16 ext_type;
    quint16 ext_len;
    int next_offset;
    bool is_tls13 = false; //session->version == TLSV1DOT3_VERSION;

    int offset_end;

    /* Extension extensions<0..2^16-2> (for TLS 1.3 HRR/CR min-length is 2) */
    exts_len = getUint16(packet, offset);
    offset += 2;
    offset_end = offset + static_cast<int>(exts_len);

    while (offset_end - offset >= 4) {
        ext_type = getUint16(packet, offset);
        ext_len  = getUint16(packet, offset + 2);

        offset += 2;

        /* opaque extension_data<0..2^16-1> */
        offset += 2;
        next_offset = offset + static_cast<int>(ext_len);

        switch (ext_type) {
        case SSL_HND_HELLO_EXT_SERVER_NAME:
            offset = ssl_dissect_hnd_hello_ext_server_name(packet, offset, next_offset, ret);
            break;
        case SSL_HND_HELLO_EXT_STATUS_REQUEST:
            if (hnd_type == SSL_HND_CLIENT_HELLO) {
                offset = ssl_dissect_hnd_hello_ext_status_request(packet, offset, ret);
            } else if (is_tls13/* && hnd_type == SSL_HND_CERTIFICATE*/) {
                //offset = tls_dissect_hnd_certificate_status(hf, tvb, pinfo, ext_tree, offset, next_offset);
            }
            break;
        case SSL_HND_HELLO_EXT_CERT_TYPE:
//            offset = ssl_dissect_hnd_hello_ext_cert_type(hf, tvb, ext_tree,
//                                                         offset, next_offset,
//                                                         hnd_type, ext_type,
//                                                         session);
            break;
        case SSL_HND_HELLO_EXT_SUPPORTED_GROUPS:
            offset = ssl_dissect_hnd_hello_ext_supported_groups(packet, offset, next_offset, ret);
            break;
        case SSL_HND_HELLO_EXT_EC_POINT_FORMATS:
            offset = ssl_dissect_hnd_hello_ext_ec_point_formats(packet, offset, ret);
            break;
        case SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS:
        case SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS_CERT: /* since TLS 1.3 draft -23 */
            offset = ssl_dissect_hnd_hello_ext_sig_hash_algs(packet, offset, ret);
            break;
        case SSL_HND_HELLO_EXT_USE_SRTP:
//            if (is_dtls) {
//                offset = dtls_dissect_hnd_hello_ext_use_srtp(tvb, ext_tree, offset, next_offset);
//            } else {
//                // XXX expert info: This extension MUST only be used with DTLS, and not with TLS.
//            }
            break;
        case SSL_HND_HELLO_EXT_HEARTBEAT:
            ret->hnd_hello.heartbeat_mode = 1;
            offset++;
            break;
        case SSL_HND_HELLO_EXT_ALPN:
            offset = ssl_dissect_hnd_hello_ext_alpn(packet, offset, ret);
            break;
        case SSL_HND_HELLO_EXT_STATUS_REQUEST_V2:
            if (hnd_type == SSL_HND_CLIENT_HELLO)
                offset = ssl_dissect_hnd_hello_ext_status_request_v2(packet, offset, ret);
            break;
        case SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
            // TLS 1.3 note: SCT only appears in EE in draft -16 and before.
//            if (hnd_type == SSL_HND_SERVER_HELLO || hnd_type == SSL_HND_ENCRYPTED_EXTENSIONS || hnd_type == SSL_HND_CERTIFICATE)
//                offset = tls_dissect_sct_list(hf, tvb, pinfo, ext_tree, offset, next_offset, session->version);
            break;
        case SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE:
        case SSL_HND_HELLO_EXT_SERVER_CERT_TYPE:
//            offset = ssl_dissect_hnd_hello_ext_cert_type(hf, tvb, ext_tree,
//                                                         offset, next_offset,
//                                                         hnd_type, ext_type,
//                                                         session);
            break;
        case SSL_HND_HELLO_EXT_PADDING:
            ret->hnd_hello.padding = ext_len;
            offset += ext_len;
            break;
        case SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC:
            ret->hnd_hello.encrypt_then_mac = 1;
            break;
        case SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET:
            ret->hnd_hello.extended_master_secret = 1;
            break;
        case SSL_HND_HELLO_EXT_COMPRESS_CERTIFICATE:
//            offset = ssl_dissect_hnd_hello_ext_compress_certificate(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_RECORD_SIZE_LIMIT:
            ret->hnd_hello.record_size_limit = getUint16(packet, offset);
            offset += 2;
            break;
        case SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS:
//            offset = ssl_dissect_hnd_hello_ext_quic_transport_parameters(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_SESSION_TICKET_TLS:
            offset = ssl_dissect_hnd_hello_ext_session_ticket(packet, offset, next_offset, ret);
            break;
        case SSL_HND_HELLO_EXT_KEY_SHARE_OLD: /* used before TLS 1.3 draft -23 */
        case SSL_HND_HELLO_EXT_KEY_SHARE:
//            offset = ssl_dissect_hnd_hello_ext_key_share(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type);
            break;
        case SSL_HND_HELLO_EXT_PRE_SHARED_KEY:
//            offset = ssl_dissect_hnd_hello_ext_pre_shared_key(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type);
            break;
        case SSL_HND_HELLO_EXT_EARLY_DATA:
        case SSL_HND_HELLO_EXT_TICKET_EARLY_DATA_INFO:
//            offset = ssl_dissect_hnd_hello_ext_early_data(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS:
            switch (hnd_type) {
            case SSL_HND_CLIENT_HELLO:
                offset = ssl_dissect_hnd_hello_ext_supported_versions(packet, offset, ret);
                break;
            case SSL_HND_SERVER_HELLO:
            case SSL_HND_HELLO_RETRY_REQUEST:
                ret->hnd_hello.supported_version = getUint16(packet, offset);
                offset += 2;
                break;
            }
            break;
        case SSL_HND_HELLO_EXT_COOKIE:
//            offset = ssl_dissect_hnd_hello_ext_cookie(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES:
//            offset = ssl_dissect_hnd_hello_ext_psk_key_exchange_modes(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_CERTIFICATE_AUTHORITIES:
//            offset = ssl_dissect_hnd_hello_ext_certificate_authorities(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_OID_FILTERS:
//            offset = ssl_dissect_hnd_hello_ext_oid_filters(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_POST_HANDSHAKE_AUTH:
            break;
        case SSL_HND_HELLO_EXT_NPN:
            offset = ssl_dissect_hnd_hello_ext_npn(packet, offset, next_offset, ret);
            break;
        case SSL_HND_HELLO_EXT_RENEGOTIATION_INFO:
//            offset = ssl_dissect_hnd_hello_ext_reneg_info(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_ENCRYPTED_SERVER_NAME:
//            offset = ssl_dissect_hnd_hello_ext_esni(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        default:
            offset += ext_len;
            break;
        }

        if (offset != next_offset) {
            /* Dissection did not end at expected location, fix it. */
            offset = next_offset;
        }
    }

    /* Check if Extensions vector is correctly terminated. */
    if (offset != offset_end) {
        offset = offset_end;
    }

    return offset;
}

void ssl_dissect_hnd_cli_hello(const QByteArray &packet, TlsClientHelloInfo *tlsHelloInfo)
{
    /* struct {
     *     ProtocolVersion client_version;
     *     Random random;
     *     SessionID session_id;
     *     opaque cookie<0..32>;                   //new field for DTLS
     *     CipherSuite cipher_suites<2..2^16-1>;
     *     CompressionMethod compression_methods<1..2^8-1>;
     *     Extension client_hello_extension_list<0..2^16-1>;
     * } ClientHello;
     */
    quint32 cipher_suite_length;
    quint32 compression_methods_length;
    quint8 compression_method;
    int next_offset;

    int offset = 9;

    /* show the client version */
    tlsHelloInfo->version = getUint16(packet, offset);

    offset += 2;

    /* dissect fields that are also present in ClientHello */
    offset = ssl_dissect_hnd_hello_common(packet, offset, tlsHelloInfo);

    /* fields specific for DTLS (cookie_len, cookie) */
#if 0
    if (dtls_hfs != NULL) {
        guint32 cookie_length;
        /* opaque cookie<0..32> (for DTLS only) */
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &cookie_length,
                            dtls_hfs->hf_dtls_handshake_cookie_len, 0, 32)) {
            return;
        }
        offset++;
        if (cookie_length > 0) {
            proto_tree_add_item(tree, dtls_hfs->hf_dtls_handshake_cookie,
                                tvb, offset, cookie_length, ENC_NA);
            offset += cookie_length;
        }
    }
#endif

    /* CipherSuite cipher_suites<2..2^16-1> */
    cipher_suite_length = getUint16(packet, offset);

    offset += 2;
    next_offset = offset + static_cast<int>(cipher_suite_length);

    while (offset + 2 <= next_offset) {
        quint16 cipher_suite = getUint16(packet, offset);
        tlsHelloInfo->ciphers << cipher_suite;
        offset += 2;
    }

    if (offset != next_offset) {
        offset = next_offset;
    }

    /* CompressionMethod compression_methods<1..2^8-1> */
    compression_methods_length = getUint8(packet, offset);
    offset++;
    next_offset = offset + static_cast<int>(compression_methods_length);

    while (offset < next_offset) {
        compression_method = getUint8(packet, offset);
        tlsHelloInfo->comp_methods << compression_method;
        offset++;
    }

    /* SSL v3.0 has no extensions, so length field can indeed be missing. */
    if (tlsHelloInfo->version > SSLV3_VERSION) {
        ssl_dissect_hnd_extension(packet, offset, SSL_HND_CLIENT_HELLO, tlsHelloInfo);
    }
}
