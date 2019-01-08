#include "ssltest.h"
#include "debug.h"
#include "sslcertgen.h"
#include "ssltests.h"
#include "ciphers.h"

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
    m_report = QString("test results undefined");
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
#ifdef SSL2_MT_ERROR
    isSsl2Supported = true;
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

void SslCertificatesTest::calcResults()
{
    if (m_interceptedData.size() > 0) {
        m_report = QString("test failed, client accepted fake certificate, data was intercepted");
        setResult(SSLTEST_RESULT_DATA_INTERCEPTED);
        return;
    }

    if (m_sslConnectionEstablished && (m_interceptedData.size() == 0)
            && !m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)) {
        m_report = QString("test failed, client accepted fake certificate, but no data transmitted");
        setResult(SSLTEST_RESULT_CERT_ACCEPTED);
        return;
    }

    if (m_socketErrors.contains(QAbstractSocket::SslInternalError)
            || m_socketErrors.contains(QAbstractSocket::SslInvalidUserDataError)) {
        m_report = QString("failure during SSL initialization");
        setResult(SSLTEST_RESULT_INIT_FAILED);
        return;
    }

    m_report = QString("test passed, client refused fake certificate");
    setResult(SSLTEST_RESULT_SUCCESS);
}

void SslProtocolsCiphersTest::calcResults()
{
    if (m_interceptedData.size() > 0) {
        m_report = QString("test failed, client accepted fake certificate and weak protocol, data was intercepted");
        setResult(SSLTEST_RESULT_DATA_INTERCEPTED);
        return;
    }

    if (m_sslConnectionEstablished && (m_interceptedData.size() == 0)
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

    if (m_socketErrors.contains(QAbstractSocket::SslInternalError)
            || m_socketErrors.contains(QAbstractSocket::SslInvalidUserDataError)) {
        m_report = QString("failure during SSL initialization");
        setResult(SSLTEST_RESULT_INIT_FAILED);
        return;
    }

    if (m_socketErrors.contains(QAbstractSocket::SslHandshakeFailedError)
            && ((m_sslErrorsStr.filter(QString("certificate unknown")).size() > 0)
                || (m_sslErrorsStr.filter(QString("unknown ca")).size() > 0)
                || (m_sslErrorsStr.filter(QString("bad certificate")).size() > 0))) {
        m_report = QString("test failed, client accepted weak protocol");
        setResult(SSLTEST_RESULT_PROTO_ACCEPTED_WITH_ERR);
        return;
    }

    m_report = QString("test passed, client does not accept weak protocol");
    setResult(SSLTEST_RESULT_SUCCESS);
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
