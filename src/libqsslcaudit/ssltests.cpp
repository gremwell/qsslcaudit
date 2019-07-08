
#include "ssltests.h"
#include "sslcertgen.h"
#include "debug.h"

#ifdef UNSAFE_QSSL
#include "sslunsafeconfiguration.h"
#else
#include <QSslConfiguration>
#endif


SslTestsFactory<SslTest> sslTestsFactory;

void fillSslTestsFactory()
{
    // using 'switch ()' to be sure that all tests are registered
    for (int i = 0; i < static_cast<int>(SslTestId::SslTestNonexisting); i++) {
        switch (static_cast<SslTestId>(i)) {
#define ADD_SSLTEST_CASE(type) \
        case SslTestId::type: \
            sslTestsFactory.registerType<type>(SslTestId::type); \
        break;

        ADD_SSLTEST_CASE(SslTestCertCustom1);
        ADD_SSLTEST_CASE(SslTestCertSS1);
        ADD_SSLTEST_CASE(SslTestCertSS2);
        ADD_SSLTEST_CASE(SslTestCertCustom2);
        ADD_SSLTEST_CASE(SslTestCertCustom3);
        ADD_SSLTEST_CASE(SslTestCertCA1);
        ADD_SSLTEST_CASE(SslTestCertCA2);
        ADD_SSLTEST_CASE(SslTestProtoSsl2);
        ADD_SSLTEST_CASE(SslTestProtoSsl3);
        ADD_SSLTEST_CASE(SslTestCiphersSsl3Exp);
        ADD_SSLTEST_CASE(SslTestCiphersSsl3Low);
        ADD_SSLTEST_CASE(SslTestCiphersSsl3Med);
        ADD_SSLTEST_CASE(SslTestProtoTls10);
        ADD_SSLTEST_CASE(SslTestCiphersTls10Exp);
        ADD_SSLTEST_CASE(SslTestCiphersTls10Low);
        ADD_SSLTEST_CASE(SslTestCiphersTls10Med);
        ADD_SSLTEST_CASE(SslTestCiphersTls11Exp);
        ADD_SSLTEST_CASE(SslTestCiphersTls11Low);
        ADD_SSLTEST_CASE(SslTestCiphersTls11Med);
        ADD_SSLTEST_CASE(SslTestCiphersTls12Exp);
        ADD_SSLTEST_CASE(SslTestCiphersTls12Low);
        ADD_SSLTEST_CASE(SslTestCiphersTls12Med);
        ADD_SSLTEST_CASE(SslTestCiphersDtls10Exp);
        ADD_SSLTEST_CASE(SslTestCiphersDtls10Low);
        ADD_SSLTEST_CASE(SslTestCiphersDtls10Med);
        ADD_SSLTEST_CASE(SslTestCiphersDtls12Exp);
        ADD_SSLTEST_CASE(SslTestCiphersDtls12Low);
        ADD_SSLTEST_CASE(SslTestCiphersDtls12Med);

        case SslTestId::SslTestNonexisting:
            break;
        }
    }
}

bool SslTestCertCustom1::prepare(const SslUserSettings &settings)
{
    // if user did not provide a certificate, do not emit error, just skip test initialization
    if (settings.getUserCertPath().isEmpty()) {
        return false;
    }

    QList<XSslCertificate> chain = settings.getUserCert();
    if (chain.size() == 0) {
        RED("can not parse user-supplied certificate");
        return false;
    }

    m_localCertsChain = chain;

    XSslKey key = settings.getUserKey();
    if (key.isNull()) {
        RED("can not parse user-supplied key");
        return false;
    }

    m_privateKey = key;

    m_sslCiphers = XSslConfiguration::supportedCiphers();
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertSS1::prepare(const SslUserSettings &settings)
{
    QPair<XSslCertificate, XSslKey> cert;

    if (settings.getUserCN().length() != 0) {
        QString cn = settings.getUserCN();

        cert = SslCertGen::genSignedCert(cn);
    } else if (settings.getServerAddr().length() != 0) {
        XSslCertificate basecert = settings.getPeerCertificates().first();

        cert = SslCertGen::genSignedCertFromTemplate(basecert);
    } else {
        return false;
    }

    QList<XSslCertificate> chain;
    chain << cert.first;

    m_localCertsChain = chain;
    m_privateKey = cert.second;

    m_sslCiphers = XSslConfiguration::supportedCiphers();
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertSS2::prepare(const SslUserSettings &settings)
{
    QPair<XSslCertificate, XSslKey> cert = SslCertGen::genSignedCert("www.example.com");

    QList<XSslCertificate> chain;
    chain << cert.first;

    m_localCertsChain = chain;
    m_privateKey = cert.second;

    m_sslCiphers = XSslConfiguration::supportedCiphers();
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertCustom2::prepare(const SslUserSettings &settings)
{
    QPair<QList<XSslCertificate>, XSslKey> generatedCert;

    QList<XSslCertificate> chain = settings.getUserCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings.getUserKey();
    if (key.isNull())
        return false;

    if (settings.getUserCN().length() != 0) {
        QString cn = settings.getUserCN();

        generatedCert = SslCertGen::genSignedByCACert(cn, chain.at(0), key);
    } else if (settings.getServerAddr().length() != 0) {
        XSslCertificate basecert = settings.getPeerCertificates().first();

        generatedCert = SslCertGen::genSignedByCACertFromTemplate(basecert, chain.at(0), key);
    } else {
        return false;
    }

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    m_localCertsChain = generatedCert.first;
    m_privateKey = generatedCert.second;

    m_sslCiphers = XSslConfiguration::supportedCiphers();
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertCustom3::prepare(const SslUserSettings &settings)
{
    QList<XSslCertificate> chain = settings.getUserCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings.getUserKey();
    if (key.isNull())
        return false;

    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert("www.example.com", chain.at(0), key);

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    m_localCertsChain = generatedCert.first;
    m_privateKey = generatedCert.second;

    m_sslCiphers = XSslConfiguration::supportedCiphers();
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertCA1::prepare(const SslUserSettings &settings)
{
    QString cn;

    if (settings.getUserCN().length() != 0) {
        cn = settings.getUserCN();
    } else if (settings.getServerAddr().length() != 0) {
        cn = settings.getPeerCertificates().first().subjectInfo(XSslCertificate::CommonName).first();
    } else {
        return false;
    }

    QList<XSslCertificate> chain = settings.getUserCaCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings.getUserCaKey();
    if (key.isNull())
        return false;


    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert(cn, chain.at(0), key);

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    m_localCertsChain = generatedCert.first;
    m_privateKey = generatedCert.second;

    m_sslCiphers = XSslConfiguration::supportedCiphers();
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertCA2::prepare(const SslUserSettings &settings)
{
    QList<XSslCertificate> chain = settings.getUserCaCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings.getUserCaKey();
    if (key.isNull())
        return false;

    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert("www.example.com", chain.at(0), key);

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    m_localCertsChain = generatedCert.first;
    m_privateKey = generatedCert.second;

    m_sslCiphers = XSslConfiguration::supportedCiphers();
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestProtoSsl2::setProtoAndCiphers()
{
    return setProtoAndSupportedCiphers(XSsl::SslV2);
}


bool SslTestProtoSsl3::setProtoAndCiphers()
{
    return setProtoAndSupportedCiphers(XSsl::SslV3);
}


bool SslTestCiphersSsl3Exp::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::SslV3);
}


bool SslTestCiphersSsl3Low::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::SslV3);
}


bool SslTestCiphersSsl3Med::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::SslV3);
}


bool SslTestProtoTls10::setProtoAndCiphers()
{
    return setProtoAndSupportedCiphers(XSsl::TlsV1_0);
}


bool SslTestCiphersTls10Exp::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::TlsV1_0);
}


bool SslTestCiphersTls10Low::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::TlsV1_0);
}


bool SslTestCiphersTls10Med::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::TlsV1_0);
}


bool SslTestCiphersTls11Exp::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::TlsV1_1);
}


bool SslTestCiphersTls11Low::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::TlsV1_1);
}


bool SslTestCiphersTls11Med::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::TlsV1_1);
}


bool SslTestCiphersTls12Exp::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::TlsV1_2);
}


bool SslTestCiphersTls12Low::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::TlsV1_2);
}


bool SslTestCiphersTls12Med::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::TlsV1_2);
}

bool SslTestCiphersDtls10Exp::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::DtlsV1_0);
}


bool SslTestCiphersDtls10Low::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::DtlsV1_0);
}


bool SslTestCiphersDtls10Med::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::DtlsV1_0);
}

bool SslTestCiphersDtls12Exp::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::DtlsV1_2);
}


bool SslTestCiphersDtls12Low::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::DtlsV1_2);
}


bool SslTestCiphersDtls12Med::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::DtlsV1_2);
}
