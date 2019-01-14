
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


static quint8 getUint8(const QByteArray &packet, int offset)
{
    if (offset < packet.size())
        return static_cast<quint8>(packet.at(offset));
    return 0;
}

static quint16 getUint16(const QByteArray &packet, int offset)
{
    if (offset + 1 < packet.size())
        return qFromBigEndian<quint16>(packet.mid(offset, 2).constData());
    return 0;
}

static quint32 getUint32(const QByteArray &packet, int offset)
{
    if (offset + 3 < packet.size())
        return qFromBigEndian<quint32>(packet.mid(offset, 4).constData());
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
    if (packet.size() < 46) {
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
        tlsHelloInfo->session_id.resize(session_id_length);
        memcpy(tlsHelloInfo->session_id.data(), packet.mid(offset, session_id_length).constData(), session_id_length);

        offset += session_id_length;
    }

    /* if there's a challenge, show it */
    if (challenge_length > 0) {
        tlsHelloInfo->challenge.resize(challenge_length);
        memcpy(tlsHelloInfo->challenge.data(), packet.mid(offset, challenge_length).constData(), challenge_length);
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
        ret->random.resize(28);
        memcpy(ret->random.data(), packet.mid(offset, 28).constData(), 28);
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
            memcpy(ret->session_id.data(), packet.mid(offset, sessid_length).constData(), sessid_length);
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
                ret->hnd_hello.cert_status_type_ocsp_responder_id_list.resize(static_cast<int>(responder_id_list_len));
                memcpy(ret->hnd_hello.cert_status_type_ocsp_responder_id_list.data(),
                       packet.mid(offset, static_cast<int>(responder_id_list_len)),
                       responder_id_list_len);
            }
            offset += responder_id_list_len;

            /* opaque Extensions<0..2^16-1> */
            request_extensions_len = getUint16(packet, offset);
            offset += 2;
            if (request_extensions_len != 0) {
                if (responder_id_list_len != 0) {
                    ret->hnd_hello.cert_status_type_ocsp_responder_id_list.resize(static_cast<int>(responder_id_list_len));
                    memcpy(ret->hnd_hello.cert_status_type_ocsp_request_extensions.data(),
                           packet.mid(offset, static_cast<int>(request_extensions_len)),
                           request_extensions_len);
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
    ret->hnd_hello.session_ticket_data.resize(ext_len);
    memcpy(ret->hnd_hello.session_ticket_data.data(),
           packet.mid(offset, ext_len).constData(),
           static_cast<size_t>(ext_len));
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

        QByteArray npn;
        memcpy(npn.data(),
               packet.mid(offset, static_cast<int>(npn_length)).constData(),
               npn_length);
        ret->hnd_hello.npn << npn;

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

        QByteArray alpn_str;
        alpn_str.resize(static_cast<int>(name_length));
        memcpy(alpn_str.data(),
               packet.mid(offset, static_cast<int>(name_length)).constData(),
               name_length);
        ret->hnd_hello.alpn << alpn_str;

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

        QByteArray server_name;
        server_name.resize(static_cast<int>(server_name_length));
        memcpy(server_name.data(),
               packet.mid(offset, static_cast<int>(server_name_length)).constData(),
               server_name_length);

        ret->hnd_hello.server_name << QPair<quint8, QByteArray>(server_name_type, server_name);
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
