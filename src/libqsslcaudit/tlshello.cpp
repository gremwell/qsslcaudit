#include <QByteArray>
#include <QtEndian>

// taken from packet-tls.c, wireshark source code

#define SSL_ID_HANDSHAKE               0x16
#define SSL_ID_APP_DATA                0x17

#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304

#define SSL2_HND_CLIENT_HELLO          0x01
#define SSL_HND_CLIENT_HELLO           1

#define TLS_MAX_RECORD_LENGTH 0x4000

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
    if (static_cast<quint8>(packet.at(0)) != 0x80) {
        return false;
    }

    /* msg_type must be 1 for Client Hello */
    if (static_cast<quint8>(packet.at(2)) != 1) {
        return false;
    }

    /* cipher spec length must be a non-zero multiple of 3 */
    quint16 cipher_spec_length = qFromBigEndian<quint16>(packet.mid(5, 2).constData());
    if (cipher_spec_length == 0 || cipher_spec_length % 3 != 0) {
        return false;
    }

    /* session ID length must be 0 or 16 in TLS 1.0 */
    quint16 session_id_length = qFromBigEndian<quint16>(packet.mid(7, 2).constData());
    if (session_id_length != 0 && session_id_length != 16) {
        return false;
    }

    /* Challenge Length must be between 16 and 32 */
    quint16 challenge_length = qFromBigEndian<quint16>(packet.mid(9, 2).constData());
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

    content_type = static_cast<quint8>(packet.at(0));
    protocol_version = qFromBigEndian<quint16>(packet.mid(1, 2).constData());
    record_length = qFromBigEndian<quint16>(packet.mid(3, 2).constData());

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
    quint8 msg_type = static_cast<quint8>(packet.at(5));

    if (msg_type == SSL_HND_CLIENT_HELLO)
        return true;

    return false;
}
