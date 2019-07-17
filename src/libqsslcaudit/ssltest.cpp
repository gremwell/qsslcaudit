#include "ssltest.h"
#include "debug.h"
#include "sslcertgen.h"
#include "ssltests.h"
#include "ciphers.h"
#include "sslcheck.h"

#ifdef UNSAFE
#include <openssl-unsafe/ssl.h>
#else
#include <openssl/ssl.h>
#endif


SslTest::~SslTest() {}

void SslTest::clear()
{
    m_result = SslTestResult::NotReady;
    m_resultComment = QString();
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

void SslCertificatesTest::calcResults(const ClientInfo client)
{
    SslCheckReport rep;
    QVector<SslCheck *> checks;

    checks << new SslCheckSocketErrors();

    checks << new SslCheckNoData();
    checks << new SslCheckNonSslData();
    checks << new SslCheckInvalidSsl();

    checks << new SslCheckForGenericSslErrors();

    checks << new SslCheckCertificatesValidation();

    for (int i = 0; i < checks.size(); i++) {
        rep = checks.at(i)->doCheck(client);

        m_result = rep.result;
        m_resultComment = rep.comment;
        m_report = rep.report;

        if (m_result != SslTestResult::Success)
            return;
    }
}

void SslProtocolsCiphersTest::calcResults(const ClientInfo client)
{
    SslCheckReport rep;
    QVector<SslCheck *> checks;

    checks << new SslCheckSocketErrors();

    checks << new SslCheckNoData();
    checks << new SslCheckNonSslData();
    checks << new SslCheckInvalidSsl();

    checks << new SslCheckForGenericSslErrors();

    checks << new SslCheckProtocolsCiphersSupport();

    for (int i = 0; i < checks.size(); i++) {
        rep = checks.at(i)->doCheck(client);

        m_result = rep.result;
        m_resultComment = rep.comment;
        m_report = rep.report;

        if (m_result != SslTestResult::Success)
            return;
    }
}

bool SslProtocolsCiphersTest::prepare(const SslUserSettings &settings)
{
    // in case of DTLS omit protocols test for normal TLS
    switch (m_id) {
    case SslTestId::SslTestCiphersDtls10Exp:
    case SslTestId::SslTestCiphersDtls10Low:
    case SslTestId::SslTestCiphersDtls10Med:
    case SslTestId::SslTestCiphersDtls12Exp:
    case SslTestId::SslTestCiphersDtls12Low:
    case SslTestId::SslTestCiphersDtls12Med:
        if (!settings.getUseDtls())
            return false;
        break;
    default:
        if (settings.getUseDtls())
            return false;
    }

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
    m_localCertsChain = chain;
    m_privateKey = key;

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
        } else if (proto == SslUnsafe::TlsV1_2) {
            protoStr = "TLSv1.2";
        } else if (proto == SslUnsafe::DtlsV1_0) {
            protoStr = "DTLSv1.0";
        } else if (proto == SslUnsafe::DtlsV1_2) {
            protoStr = "DTLSv1.2";
        }
        VERBOSE(QString("the requested protocol (%1) is not supported").arg(protoStr));
        return false;
    }

    m_sslProtocol = proto;

    return true;
}

bool SslProtocolsCiphersTest::setProtoAndSupportedCiphers(XSsl::SslProtocol proto)
{
    QList<XSslCipher> ciphers = XSslConfiguration::supportedCiphers();

    if (!setProtoOnly(proto))
        return false;

    m_sslCiphers = ciphers;

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

    m_sslCiphers = ciphers;

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
