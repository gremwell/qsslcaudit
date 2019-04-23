#include "ssltest.h"
#include "debug.h"
#include "sslcertgen.h"
#include "ssltests.h"
#include "ciphers.h"
#include "tlshello.h"

#ifdef UNSAFE
#include <openssl-unsafe/ssl.h>
#else
#include <openssl/ssl.h>
#endif

SslTest::SslTest()
{
    clear();
}

SslTest::~SslTest()
{
}

SslTest *SslTest::createTest(int id)
{
    switch (id) {
    case 0:
        return new SslTest01();
    case 1:
        return new SslTest02();
    case 2:
        return new SslTest03();
    case 3:
        return new SslTest04();
    case 4:
        return new SslTest05();
    case 5:
        return new SslTest06();
    case 6:
        return new SslTest07();
    case 7:
        return new SslTest08();
    case 8:
        return new SslTest09();
    case 9:
        return new SslTest10();
    case 10:
        return new SslTest11();
    case 11:
        return new SslTest12();
    case 12:
        return new SslTest13();
    case 13:
        return new SslTest14();
    case 14:
        return new SslTest15();
    case 15:
        return new SslTest16();
    case 16:
        return new SslTest17();
    case 17:
        return new SslTest18();
    case 18:
        return new SslTest19();
    case 19:
        return new SslTest20();
    case 20:
        return new SslTest21();
    case 21:
        return new SslTest22();
    }
    return NULL;
}

const QString SslTest::resultToStatus(enum SslTest::SslTestResult result)
{
    QString ret;

    switch (result) {
    case SslTest::SSLTEST_RESULT_SUCCESS:
        ret = "PASSED";
        break;
    case SslTest::SSLTEST_RESULT_NOT_READY:
    case SslTest::SSLTEST_RESULT_UNDEFINED:
    case SslTest::SSLTEST_RESULT_INIT_FAILED:
        ret = "UNDEFINED";
        break;
    case SslTest::SSLTEST_RESULT_DATA_INTERCEPTED:
    case SslTest::SSLTEST_RESULT_CERT_ACCEPTED:
    case SslTest::SSLTEST_RESULT_PROTO_ACCEPTED:
    case SslTest::SSLTEST_RESULT_PROTO_ACCEPTED_WITH_ERR:
        ret = "FAILED";
        break;
    }

    return ret;
}

void SslTest::printReport()
{
    if (m_result < 0) {
        RED(m_report);
    } else {
        GREEN(m_report);
    }
}

void SslTest::clear()
{
    m_sslErrors = QList<XSslError>();
    m_sslErrorsStr = QStringList();
    m_socketErrors = QList<QAbstractSocket::SocketError>();
    m_sslConnectionEstablished = false;
    m_interceptedData = QByteArray();
    m_result = SSLTEST_RESULT_NOT_READY;
    m_rawDataRecv = QByteArray();
    m_rawDataSent = QByteArray();
    m_report = QString("test results undefined");
    m_clientInfo.clear();
}

bool SslTest::checkProtoSupport(XSsl::SslProtocol proto)
{
    bool isSsl2Supported = false;
    bool isSsl3Supported = true;
    bool isTls1Supported = true;
    bool isTls11Supported = true;

    // OpenSSL does not have API that returns supported protocols
    // internally it relies on compile-time defines, see ssl_check_allowed_versions()

    // to check for SSLv2 support the most reliable way is to check for protocol-specific define
#if defined(SSL2_MT_ERROR) && !defined(OPENSSL_NO_SSL2)
    isSsl2Supported = true;
#else
    isSsl2Supported = false;
#endif
    if ((proto == XSsl::SslV2) && !isSsl2Supported)
        return false;

    // the similar is for SSLv3 and others support but defines are a bit different
#if defined(OPENSSL_NO_SSL3_METHOD) || defined(OPENSSL_NO_SSL3)
    isSsl3Supported = false;
#endif
    if ((proto == XSsl::SslV3) && !isSsl3Supported)
        return false;

#if defined(OPENSSL_NO_TLS1_METHOD) || defined(OPENSSL_NO_TLS1)
    isTls1Supported = false;
#endif
    if ((proto == XSsl::TlsV1_0) && !isTls1Supported)
        return false;

#if defined(OPENSSL_NO_TLS1_1_METHOD) || defined(OPENSSL_NO_TLS1_1)
    isSsl3Supported = false;
#endif
    if ((proto == XSsl::TlsV1_1) && !isTls11Supported)
        return false;

    return true;
}

bool SslTest::checkForSocketErrors()
{
    // all errors should be here except those which we handle below in a particular test
    if (m_socketErrors.contains(QAbstractSocket::ConnectionRefusedError)
            || m_socketErrors.contains(QAbstractSocket::HostNotFoundError)
            || m_socketErrors.contains(QAbstractSocket::SocketAccessError)
            || m_socketErrors.contains(QAbstractSocket::SocketResourceError)
            || m_socketErrors.contains(QAbstractSocket::DatagramTooLargeError)
            || m_socketErrors.contains(QAbstractSocket::NetworkError)
            || m_socketErrors.contains(QAbstractSocket::AddressInUseError)
            || m_socketErrors.contains(QAbstractSocket::SocketAddressNotAvailableError)
            || m_socketErrors.contains(QAbstractSocket::UnsupportedSocketOperationError)
            || m_socketErrors.contains(QAbstractSocket::UnfinishedSocketOperationError)
            || m_socketErrors.contains(QAbstractSocket::OperationError)
            || m_socketErrors.contains(QAbstractSocket::TemporaryError)) {
        m_report = QString("socket/network error occuried");
        setResult(SSLTEST_RESULT_UNDEFINED);
        return true;
    }

    if (m_socketErrors.contains(QAbstractSocket::UnknownSocketError)) {
        m_report = QString("unknown socket error occuried");
        setResult(SSLTEST_RESULT_UNDEFINED);
        return true;
    }

    return false;
}

bool SslTest::isHelloMessage(const QByteArray &packet, bool *isSsl2)
{
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

int SslTest::helloPosInBuffer(const QByteArray &buf, bool *isSsl2)
{
    int size = buf.size();

    for (int i = 0; i < size; i++) {
        if (isHelloMessage(buf.right(size - i), isSsl2))
            return i;
    }

    return -1;
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

QString TlsClientInfo::printable() const
{
    QString ret;
    QTextStream out(&ret);

    out << "source host: " << sourceHost << endl;

    if (isBrokenSslClient) {
        out << "not a valid TLS/SSL client, "
            << rawDataRecv.size() << " byte(s) of raw data received: "
            << rawDataRecv.left(16) << endl;
    }

    if (hasHelloMessage)
        out << tlsHelloInfo.printable();

    return ret;
}

QDebug operator<<(QDebug dbg, const TlsClientInfo &clientInfo)
{
    QDebugStateSaver saver(dbg);
    dbg.nospace();

    dbg << "source host(" << clientInfo.sourceHost << ")" << endl;
    dbg << "has hello message(" << clientInfo.hasHelloMessage << ")" << endl;
    dbg << "is broken SSL client(" << clientInfo.isBrokenSslClient << ")" << endl;
    dbg << "tls version(" << clientInfo.tlsHelloInfo.version << ")" << endl;
    dbg << "tls ciphers(" << clientInfo.tlsHelloInfo.ciphers << ")" << endl;
    dbg << "tls session_id(" << clientInfo.tlsHelloInfo.session_id << ")" << endl;
    dbg << "tls challenge(" << clientInfo.tlsHelloInfo.challenge << ")" << endl;
    dbg << "tls comp_methods(" << clientInfo.tlsHelloInfo.comp_methods << ")" << endl;
    dbg << "tls random_time(" << clientInfo.tlsHelloInfo.random_time << ")" << endl;
    dbg << "tls random(" << clientInfo.tlsHelloInfo.random << ")" << endl;
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

bool SslTest::checkForNonSslClient()
{
#ifdef UNSAFE_QSSL
    int helloPos = -1;
    bool isSsl2 = false;

    // test for HELLO message in advance
    if ((m_rawDataRecv.size() > 0) && ((helloPos = helloPosInBuffer(m_rawDataRecv, &isSsl2)) >= 0)) {
        m_clientInfo.hasHelloMessage = true;

        if (isSsl2) {
            dissect_ssl2_hnd_client_hello(m_rawDataRecv.right(m_rawDataRecv.size() - helloPos), &m_clientInfo.tlsHelloInfo);
        } else {
            ssl_dissect_hnd_cli_hello(m_rawDataRecv.right(m_rawDataRecv.size() - helloPos), &m_clientInfo.tlsHelloInfo);
        }
    }

    // some conditions below are excessive, this is for purpose to make our decisions clear
    if ((m_rawDataRecv.size() == 0)
            && !m_sslConnectionEstablished
            && !m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)
            && m_socketErrors.contains(QAbstractSocket::SocketTimeoutError)) {
        m_report = QString("no data was transmitted before timeout expired");
        setResult(SSLTEST_RESULT_UNDEFINED);
        m_clientInfo.isBrokenSslClient = true;
        return true;
    }

    if ((m_rawDataRecv.size() == 0)
            && !m_sslConnectionEstablished
            && m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)
            && !m_socketErrors.contains(QAbstractSocket::SocketTimeoutError)) {
        m_report = QString("client closed the connection without transmitting any data");
        setResult(SSLTEST_RESULT_UNDEFINED);
        m_clientInfo.isBrokenSslClient = true;
        return true;
    }

    if ((m_rawDataRecv.size() > 0)
            && !m_sslConnectionEstablished
            && m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)
            && !m_socketErrors.contains(QAbstractSocket::SocketTimeoutError)
            && !m_clientInfo.hasHelloMessage) {
        m_report = QString("secure connection was not established, %1 bytes were received before client closed the connection")
                .arg(m_rawDataRecv.size());
        setResult(SSLTEST_RESULT_UNDEFINED);
        m_clientInfo.isBrokenSslClient = true;
        return true;
    }

    // this case is the same for broken SSL clients and perfectly valid ones
#if 0
    if ((m_rawDataRecv.size() > 0)
            && !m_sslConnectionEstablished
            && m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)
            && !m_socketErrors.contains(QAbstractSocket::SocketTimeoutError)
            && hasHelloMessage
            && (m_sslErrorsStr.size() == 1)
            && m_sslErrorsStr.contains("The remote host closed the connection")) {
        // client sent HELLO, but as SSL errors list is empty and encrypted connection
        // was not established, something went wrong in the middle of handshake
        // thus, consider client as non-SSL
        m_report = QString("secure connection was not properly established (however, the attempt was made), client closed the connection");
        setResult(SSLTEST_RESULT_UNDEFINED);
        m_clientInfo.isBrokenSslClient = true;
        return true;
    }
#endif

    if ((m_rawDataRecv.size() > 0)
            && !m_sslConnectionEstablished
            && !m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)
            && m_socketErrors.contains(QAbstractSocket::SocketTimeoutError)
            && !m_clientInfo.hasHelloMessage) {
        m_report = QString("secure connection was not established, %1 bytes were received before client was disconnected")
                .arg(m_rawDataRecv.size());
        setResult(SSLTEST_RESULT_UNDEFINED);
        m_clientInfo.isBrokenSslClient = true;
        return true;
    }

    if ((m_rawDataRecv.size() > 0)
            && !m_sslConnectionEstablished
            && !m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)
            && m_socketErrors.contains(QAbstractSocket::SocketTimeoutError)
            && m_clientInfo.hasHelloMessage
            && (m_sslErrorsStr.size() == 1)
            && m_sslErrorsStr.contains("Network operation timed out")) {
        // client sent HELLO, but as SSL errors list is empty and encrypted connection
        // was not established, something went wrong in the middle of handshake
        // thus, consider client as non-SSL
        m_report = QString("secure connection was not properly established (however, the attempt was made), client was disconnected");
        setResult(SSLTEST_RESULT_UNDEFINED);
        m_clientInfo.isBrokenSslClient = true;
        return true;
    }

    if ((m_rawDataRecv.size() > 0)
            && !m_sslConnectionEstablished
            && !m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)
            && !m_socketErrors.contains(QAbstractSocket::SocketTimeoutError)
            && !m_clientInfo.hasHelloMessage
            && (m_socketErrors.contains(QAbstractSocket::SslHandshakeFailedError)
                && ((m_sslErrorsStr.filter(QString("SSL23_GET_CLIENT_HELLO:http request")).size() > 0)
                    || (m_sslErrorsStr.filter(QString("SSL23_GET_CLIENT_HELLO:unknown protocol")).size() > 0)
                    || (m_sslErrorsStr.filter(QString("SSL3_GET_RECORD:wrong version number")).size() > 0)))) {
        m_report = QString("secure connection was not established, %1 bytes of unexpected protocol were received before the connection was closed")
                .arg(m_rawDataRecv.size());
        setResult(SSLTEST_RESULT_UNDEFINED);
        m_clientInfo.isBrokenSslClient = true;
        return true;
    }

    // failsafe check. this can't be SSL client without HELLO message intercepted
    if ((m_rawDataRecv.size() > 0)
            && !m_clientInfo.hasHelloMessage) {
        m_report = QString("secure connection was not established, %1 bytes were received before the connection was closed")
                .arg(m_rawDataRecv.size());
        setResult(SSLTEST_RESULT_UNDEFINED);
        m_clientInfo.isBrokenSslClient = true;
        return true;
    }
#endif

    return false;
}

bool SslTest::checkForGenericSslErrors()
{
    if (m_socketErrors.contains(QAbstractSocket::SslInternalError)
            || m_socketErrors.contains(QAbstractSocket::SslInvalidUserDataError)) {
        m_report = QString("failure during SSL initialization");
        setResult(SSLTEST_RESULT_UNDEFINED);
        return true;
    }

    return false;
}

void SslCertificatesTest::calcResults()
{
    if (checkForSocketErrors())
        return;

    if (checkForNonSslClient())
        return;

    if (checkForGenericSslErrors())
        return;

    if (m_interceptedData.size() > 0) {
        m_report = QString("test failed, client accepted fake certificate, data was intercepted");
        setResult(SSLTEST_RESULT_DATA_INTERCEPTED);
        return;
    }

    if (m_sslConnectionEstablished
            && (m_interceptedData.size() == 0)
            && !m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)) {
        m_report = QString("test failed, client accepted fake certificate, but no data transmitted");
        setResult(SSLTEST_RESULT_CERT_ACCEPTED);
        return;
    }

    if (!m_sslConnectionEstablished) {
        m_report = QString("test passed, client refused fake certificate");
        setResult(SSLTEST_RESULT_SUCCESS);
        return;
    }

    // this is a controversion decision
    if (m_sslConnectionEstablished
            && (m_interceptedData.size() == 0)
            && m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)) {
        m_report = QString("test succeeded, client accepted fake certificate but disconnected without data transmission");
        setResult(SSLTEST_RESULT_SUCCESS);
        return;
    }

    m_report = QString("unhandled case! please report it to developers!");
    setResult(SSLTEST_RESULT_UNDEFINED);
}

void SslProtocolsCiphersTest::calcResults()
{
    if (checkForSocketErrors())
        return;

    if (checkForNonSslClient())
        return;

    if (checkForGenericSslErrors())
        return;

    if (m_interceptedData.size() > 0) {
        m_report = QString("test failed, client accepted fake certificate and weak protocol, data was intercepted");
        setResult(SSLTEST_RESULT_DATA_INTERCEPTED);
        return;
    }

    if (m_sslConnectionEstablished
            && (m_interceptedData.size() == 0)
            && !m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)) {
        m_report = QString("test failed, client accepted fake certificate and weak protocol, but no data transmitted");
        setResult(SSLTEST_RESULT_CERT_ACCEPTED);
        return;
    }

    if (m_sslConnectionEstablished) {
        m_report = QString("test failed, client accepted weak protocol");
        setResult(SSLTEST_RESULT_PROTO_ACCEPTED);
        return;
    }

    if (!m_sslConnectionEstablished
            && m_socketErrors.contains(QAbstractSocket::SslHandshakeFailedError)
            && ((m_sslErrorsStr.filter(QString("certificate unknown")).size() > 0)
                || (m_sslErrorsStr.filter(QString("unknown ca")).size() > 0)
                || (m_sslErrorsStr.filter(QString("bad certificate")).size() > 0))) {
        m_report = QString("test failed, client accepted weak protocol");
        setResult(SSLTEST_RESULT_PROTO_ACCEPTED_WITH_ERR);
        return;
    } else if (!m_sslConnectionEstablished) {
        m_report = QString("test passed, client does not accept weak protocol");
        setResult(SSLTEST_RESULT_SUCCESS);
        return;
    }

    m_report = QString("unhandled case! please report it to developers!");
    setResult(SSLTEST_RESULT_UNDEFINED);
}

bool SslProtocolsCiphersTest::prepare(const SslUserSettings &settings)
{
    XSslKey key;
    QList<XSslCertificate> chain = settings.getUserCert();
    if (chain.size() != 0) {
        key = settings.getUserKey();
    }

    if ((chain.size() == 0) || key.isNull()) {
        QString cn;

        if (settings.getUserCN().length() > 0) {
            cn = settings.getUserCN();
        } else {
            cn = "www.example.com";
        }

        QPair<XSslCertificate, XSslKey> generatedCert = SslCertGen::genSignedCert(cn);
        chain.clear();
        chain << generatedCert.first;
        key = generatedCert.second;
    }

    // these parameters should be insignificant, but we tried to make them as much "trustful" as possible
    setLocalCert(chain);
    setPrivateKey(key);

    return setProtoAndCiphers();
}

bool SslProtocolsCiphersTest::setProtoOnly(XSsl::SslProtocol proto)
{
    if (!checkProtoSupport(proto)) {
        QString protoStr = "unknown";
        if (proto == SslUnsafe::SslV2) {
            protoStr = "SSLv2";
        } else if (proto == SslUnsafe::SslV3) {
            protoStr = "SSLv3";
        } else if (proto == SslUnsafe::TlsV1_0) {
            protoStr = "TLSv1.0";
        } else if (proto == SslUnsafe::TlsV1_1) {
            protoStr = "TLSv1.1";
        }
        VERBOSE(QString("the requested protocol (%1) is not supported").arg(protoStr));
        return false;
    }

    setSslProtocol(proto);

    return true;
}

bool SslProtocolsCiphersTest::setProtoAndSupportedCiphers(XSsl::SslProtocol proto)
{
    QList<XSslCipher> ciphers = XSslConfiguration::supportedCiphers();

    if (!setProtoOnly(proto))
        return false;

    setSslCiphers(ciphers);

    return true;
}

bool SslProtocolsCiphersTest::setProtoAndSpecifiedCiphers(XSsl::SslProtocol proto, QString ciphersString, QString name)
{
    QList<XSslCipher> ciphers;
    QStringList opensslCiphers = ciphersString.split(":");

    if (!setProtoOnly(proto))
        return false;

    for (int i = 0; i < opensslCiphers.size(); i++) {
        XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

        if (!cipher.isNull())
            ciphers << cipher;
    }
    if (ciphers.size() == 0) {
        VERBOSE(QString("no %1 ciphers available").arg(name));
        return false;
    }

    setSslCiphers(ciphers);

    return true;
}

bool SslProtocolsCiphersTest::setProtoAndExportCiphers(XSsl::SslProtocol proto)
{
    return setProtoAndSpecifiedCiphers(proto, ciphers_export_str, "EXPORT");
}

bool SslProtocolsCiphersTest::setProtoAndLowCiphers(XSsl::SslProtocol proto)
{
    return setProtoAndSpecifiedCiphers(proto, ciphers_low_str, "LOW");
}

bool SslProtocolsCiphersTest::setProtoAndMediumCiphers(XSsl::SslProtocol proto)
{
    return setProtoAndSpecifiedCiphers(proto, ciphers_medium_str, "MEDIUM");
}
