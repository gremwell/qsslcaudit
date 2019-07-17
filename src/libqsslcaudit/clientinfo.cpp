#include "clientinfo.h"
#include "tlshello.h"
// only for dtlsErrorToString method
#include "sslserver.h"


bool TlsClientHelloExt::operator==(const TlsClientHelloExt &other) const
{
    // cleanup "supported_versions" and "supported_groups" from unknown values to fight from GREASE extension
    // see https://tools.ietf.org/html/draft-davidben-tls-grease-01
    if (supported_versions.size() != other.supported_versions.size())
        return false;
    for (int i = 1; i < supported_versions.size(); i++) {
        if (supported_versions.at(i) < 0x0A00)
            if (supported_versions.at(i) != other.supported_versions.at(i))
                return false;
    }

    if (supported_groups.size() != other.supported_groups.size())
        return false;
    for (int i = 0; i < supported_groups.size(); i++) {
        if (!isUnknownExtensionCurve(supported_groups.at(i)))
            if (supported_groups.at(i) != other.supported_groups.at(i))
                return false;
    }

    if ((server_name != other.server_name)
            || (heartbeat_mode != other.heartbeat_mode)
            || (supported_version != other.supported_version)
            || (encrypt_then_mac != other.encrypt_then_mac)
            || (ec_point_formats != other.ec_point_formats)
            || (sig_hash_algs != other.sig_hash_algs)
            || (npn != other.npn)
            || (alpn != other.alpn))
        return false;
    return true;
}

void TlsClientHelloExt::clear()
{
    server_name.clear();
    server_name.squeeze();
    heartbeat_mode = 0;
    padding = 0;
    record_size_limit = 0;
    supported_version = 0;
    encrypt_then_mac = 0;
    extended_master_secret = 0;
    cert_status_type_ocsp_responder_id_list.clear();
    cert_status_type_ocsp_responder_id_list.squeeze();
    cert_status_type_ocsp_request_extensions.clear();
    cert_status_type_ocsp_request_extensions.squeeze();
    supported_versions.clear();
    supported_versions.squeeze();
    ec_point_formats.clear();
    ec_point_formats.squeeze();
    supported_groups.clear();
    supported_groups.squeeze();
    session_ticket_data.clear();
    session_ticket_data.squeeze();
    sig_hash_algs.clear();
    sig_hash_algs.squeeze();
    npn.clear();
    npn.squeeze();
    alpn.clear();
    alpn.squeeze();
}

QString TlsClientHelloExt::printable() const
{
    QString ret;
    QTextStream out(&ret);

    if (heartbeat_mode)
        out << "heartbeat mode" << endl;

    if (server_name.size() > 0) {
        out << "SNI: ";
        for (int i = 0; i < server_name.size(); i++) {
            out << server_name.at(i).second;
            if (i != server_name.size() - 1)
                out << ", ";
        }
        out << endl;
    }

    if (alpn.size() > 0) {
        out << "ALPN: ";
        for (int i = 0; i < alpn.size(); i++) {
            out << QString::fromStdString(alpn.at(i).toStdString());
            if (i != alpn.size() - 1)
                out << ", ";
        }
        out << endl;
    }

    return ret;
}

void TlsClientHelloInfo::clear()
{
    version = 0;
    ciphers.clear();
    ciphers.squeeze();
    session_id.clear();
    session_id.squeeze();
    challenge.clear();
    challenge.squeeze();
    comp_methods.clear();
    comp_methods.squeeze();
    random_time = 0;
    random.clear();
    random.squeeze();
    cookie.clear();
    cookie.squeeze();
    hnd_hello.clear();
}

bool TlsClientHelloInfo::operator==(const TlsClientHelloInfo &other) const
{
    // cleanup "ciphers" from unknown values to fight from GREASE extension
    // see https://tools.ietf.org/html/draft-davidben-tls-grease-01
    if (ciphers.size() != other.ciphers.size())
        return false;
    for (int i = 0; i < ciphers.size(); i++) {
        if (!isUnknownCipher(ciphers.at(i)))
            if (ciphers.at(i) != other.ciphers.at(i))
                return false;
    }

    if ((version != other.version)
            || (comp_methods != other.comp_methods)
            || (hnd_hello != other.hnd_hello))
        return false;
    return true;
}

QString TlsClientHelloInfo::printable() const
{
    QString ret;
    QTextStream out(&ret);

    out << "protocol: ";
    switch (version) {
    case 0x300:
        out << "SSLv3";
        break;
    case 0x301:
        out << "TLSv1.0";
        break;
    case 0x302:
        out << "TLSv1.1";
        break;
    case 0x303:
        out << "TLSv1.2";
        break;
    case 0x304:
        out << "TLSv1.3";
        break;
    case 0xfeff:
        out << "DTLSv1.0";
        break;
    case 0x100:
        out << "DTLSv1.0";
        break;
    case 0xfefd:
        out << "DTLSv1.2";
        break;
    default:
        out << "SSLv2/unknown";
    }
    out << endl;

    out << "accepted ciphers: ";
    for (int i = 0; i < ciphers.size(); i++) {
        QString cipher = cipherStringFromId(ciphers.at(i));
        if (cipher.size() > 0) {
            out << cipher;
            if (i != ciphers.size() - 1)
                out << ":";
        }
    }
    out << endl;

    out << hnd_hello.printable();

    return ret;
}

void ClientInfo::clear()
{
    m_sourceHost = QString();
    m_hasHelloMessage = false;
    tlsHelloInfo.clear();

    m_sslErrors = QList<XSslError>();
    m_dtlsErrors = QList<XDtlsError>();
    m_sslErrorsStr = QStringList();
    m_socketErrors = QList<QAbstractSocket::SocketError>();
    m_sslConnectionEstablished = false;
    m_interceptedData = QByteArray();
    m_rawDataRecv = QByteArray();
    m_rawDataSent = QByteArray();
}

bool ClientInfo::isEqualTo(const ClientInfo *other) const
{
    if ((m_sourceHost != other->m_sourceHost)
            || (m_hasHelloMessage != other->m_hasHelloMessage)
            || (tlsHelloInfo != other->tlsHelloInfo)
            || (!m_hasHelloMessage && (m_rawDataRecv != other->m_rawDataRecv)))
        return false;
    return true;
}

bool ClientInfo::operator==(const ClientInfo &other) const
{
    if ((m_sourceHost != other.m_sourceHost)
            || (m_hasHelloMessage != other.m_hasHelloMessage)
            || (tlsHelloInfo != other.tlsHelloInfo)
            || (!m_hasHelloMessage && (m_rawDataRecv != other.m_rawDataRecv)))
        return false;
    return true;
}

QString ClientInfo::printable() const
{
    QString ret;
    QTextStream out(&ret);

    out << "source host: " << m_sourceHost << endl;

    out << "dtls?: " << m_dtlsMode << endl;
    if (m_dtlsMode) {
        out << "dtls errors: ";
        for (int i = 0; i < m_dtlsErrors.size(); i++)
            out << " " << SslServer::dtlsErrorToString(m_dtlsErrors.at(i));
        out << endl;
    }

    out << "ssl errors: " << m_sslErrorsStr.join(" ") << endl;

    out << "ssl conn established?: " << m_sslConnectionEstablished << endl;

    if (m_socketErrors.size() > 0) {
        out << "socket errors: ";
        for (int i = 0; i < m_socketErrors.size(); i++)
            out << " " << m_socketErrors.at(i);
        out << endl;
    }

    out << "intercepted data: " << m_interceptedData << endl;

    out << "received data, bytes: " << m_rawDataRecv.size() << endl;

    out << "transmitted data, bytes: " << m_rawDataSent.size() << endl;

    if (!m_hasHelloMessage) {
        out << "not a valid TLS/SSL client, "
            << m_rawDataRecv.size() << " byte(s) of raw data received, i.e.: "
            << m_rawDataRecv.left(32).simplified() << endl;
    }

    if (m_hasHelloMessage)
        out << tlsHelloInfo.printable();

    return ret;
}

static bool isHelloMessage(const QByteArray &packet, bool *isSsl2, bool dtlsMode)
{
    if (dtlsMode) {
        if (is_dtls(packet)) {
            return true;
        } else {
            return false;
        }
    }
    if (is_sslv3_or_tls(packet)) {
        if (is_sslv3_or_tls_hello(packet)) {
            *isSsl2 = false;
            return true;
        }
    } else if (is_sslv2_clienthello(packet)) {
        *isSsl2 = true;
        return true;
    }

    return false;
}

static int helloPosInBuffer(const QByteArray &buf, bool *isSsl2, bool dtlsMode)
{
    int size = buf.size();

    for (int i = 0; i < size; i++) {
        if (isHelloMessage(buf.right(size - i), isSsl2, dtlsMode))
            return i;
    }

    return -1;
}

void ClientInfo::parseRawData()
{
    int helloPos = -1;
    bool isSsl2 = false;

    // test for SSL/TLS HELLO message
    if ((m_rawDataRecv.size() > 0) && ((helloPos = helloPosInBuffer(m_rawDataRecv, &isSsl2, m_dtlsMode)) >= 0)) {
        m_hasHelloMessage = true;

        if (isSsl2) {
            dissect_ssl2_hnd_client_hello(m_rawDataRecv.right(m_rawDataRecv.size() - helloPos), &tlsHelloInfo);
        } else {
            ssl_dissect_hnd_cli_hello(m_rawDataRecv.right(m_rawDataRecv.size() - helloPos), &tlsHelloInfo, m_dtlsMode);
        }
    }
}

void ClientInfo::addRawDataRecv(const QByteArray &data) {
    m_rawDataRecv.append(data);
    // we do it each time (which is not THAT costly) to have
    // the corresponding ClientInfo members having always proper values
    parseRawData();
}

QDebug operator<<(QDebug dbg, const ClientInfo &clientInfo)
{
    QDebugStateSaver saver(dbg);
    dbg.nospace();

    dbg << "source host(" << clientInfo.sourceHost() << ")" << endl;
    dbg << "has hello message(" << clientInfo.hasHelloMessage() << ")" << endl;
    dbg << "tls version(" << clientInfo.tlsHelloInfo.version << ")" << endl;
    dbg << "tls ciphers(" << clientInfo.tlsHelloInfo.ciphers << ")" << endl;
    dbg << "tls session_id(" << clientInfo.tlsHelloInfo.session_id << ")" << endl;
    dbg << "tls challenge(" << clientInfo.tlsHelloInfo.challenge << ")" << endl;
    dbg << "tls comp_methods(" << clientInfo.tlsHelloInfo.comp_methods << ")" << endl;
    dbg << "tls random_time(" << clientInfo.tlsHelloInfo.random_time << ")" << endl;
    dbg << "tls random(" << clientInfo.tlsHelloInfo.random << ")" << endl;
    dbg << "tls cookie(" << clientInfo.tlsHelloInfo.cookie << ")" << endl;
    dbg << "tls hnd_hello_ext_heartbeat_mode(" << clientInfo.tlsHelloInfo.hnd_hello.heartbeat_mode << ")" << endl;
    dbg << "tls hnd_hello_ext_padding(" << clientInfo.tlsHelloInfo.hnd_hello.padding << ")" << endl;
    dbg << "tls hnd_hello_ext_record_size_limit(" << clientInfo.tlsHelloInfo.hnd_hello.record_size_limit << ")" << endl;
    dbg << "tls hnd_hello_ext_supported_version(" << clientInfo.tlsHelloInfo.hnd_hello.supported_version << ")" << endl;
    dbg << "tls hnd_hello_ext_cert_status_type_ocsp_responder_id_list(" << clientInfo.tlsHelloInfo.hnd_hello.cert_status_type_ocsp_responder_id_list << ")" << endl;
    dbg << "tls hnd_hello_ext_cert_status_type_ocsp_request_extensions(" << clientInfo.tlsHelloInfo.hnd_hello.cert_status_type_ocsp_request_extensions << ")" << endl;
    dbg << "tls hnd_hello_ext_supported_versions(" << clientInfo.tlsHelloInfo.hnd_hello.supported_versions << ")" << endl;
    dbg << "tls hnd_hello_ext_ec_point_formats(" << clientInfo.tlsHelloInfo.hnd_hello.ec_point_formats << ")" << endl;
    dbg << "tls hnd_hello_ext_supported_groups(" << clientInfo.tlsHelloInfo.hnd_hello.supported_groups << ")" << endl;
    dbg << "tls hnd_hello_ext_session_ticket_data(" << clientInfo.tlsHelloInfo.hnd_hello.session_ticket_data << ")" << endl;
    dbg << "tls hnd_hello_ext_sig_hash_algs(" << clientInfo.tlsHelloInfo.hnd_hello.sig_hash_algs << ")" << endl;
    dbg << "tls hnd_hello_ext_npn(" << clientInfo.tlsHelloInfo.hnd_hello.npn << ")" << endl;
    dbg << "tls hnd_hello_ext_alpn(" << clientInfo.tlsHelloInfo.hnd_hello.alpn << ")" << endl;
    dbg << "tls hnd_hello_ext_ext_encrypt_then_mac(" << clientInfo.tlsHelloInfo.hnd_hello.encrypt_then_mac << ")" << endl;
    dbg << "tls hnd_hello_ext_extended_master_secret(" << clientInfo.tlsHelloInfo.hnd_hello.extended_master_secret << ")" << endl;
    dbg << "tls hnd_hello_ext_server_name(" << clientInfo.tlsHelloInfo.hnd_hello.server_name << ")" << endl;

    return dbg;
}
