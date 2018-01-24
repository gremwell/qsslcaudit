
#include "ssltests.h"
#include "sslcertgen.h"
#include "debug.h"
#include "ciphers.h"

#ifdef UNSAFE
#include "sslunsafeconfiguration.h"
#else
#include <QSslConfiguration>
#endif


bool SslTest01::prepare(const SslUserSettings &settings)
{
    QList<XSslCertificate> chain = settings.getUserCert();
    if (chain.size() == 0) {
        RED("can not parse user-supplied certificate");
        return false;
    }

    setLocalCert(chain);

    XSslKey key = settings.getUserKey();
    if (key.isNull()) {
        RED("can not parse user-supplied key");
        return false;
    }

    setPrivateKey(key);

    // the rest of parameters are insignificant
    setSslCiphers(XSslConfiguration::supportedCiphers());
    setSslProtocol(QSsl::TlsV1_0OrLater);

    return true;
}


bool SslTest02::prepare(const SslUserSettings &settings)
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

    setLocalCert(chain);
    setPrivateKey(cert.second);

    // the rest of parameters are insignificant
    setSslCiphers(XSslConfiguration::supportedCiphers());
    setSslProtocol(QSsl::TlsV1_0OrLater);

    return true;
}


bool SslTest03::prepare(const SslUserSettings &settings)
{
    QPair<XSslCertificate, XSslKey> cert = SslCertGen::genSignedCert("www.example.com");

    QList<XSslCertificate> chain;
    chain << cert.first;

    setLocalCert(chain);
    setPrivateKey(cert.second);

    // the rest of parameters are insignificant
    setSslCiphers(XSslConfiguration::supportedCiphers());
    setSslProtocol(QSsl::TlsV1_0OrLater);

    return true;
}


bool SslTest04::prepare(const SslUserSettings &settings)
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

    setLocalCert(generatedCert.first);
    setPrivateKey(generatedCert.second);

    // the rest of parameters are insignificant
    setSslCiphers(XSslConfiguration::supportedCiphers());
    setSslProtocol(QSsl::TlsV1_0OrLater);

    return true;
}


bool SslTest05::prepare(const SslUserSettings &settings)
{
    QList<XSslCertificate> chain = settings.getUserCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings.getUserKey();
    if (key.isNull())
        return false;

    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert("www.example.com", chain.at(0), key);

    setLocalCert(generatedCert.first);
    setPrivateKey(generatedCert.second);

    // the rest of parameters are insignificant
    setSslCiphers(XSslConfiguration::supportedCiphers());
    setSslProtocol(QSsl::TlsV1_0OrLater);

    return true;
}


bool SslTest06::prepare(const SslUserSettings &settings)
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

    setLocalCert(generatedCert.first);
    setPrivateKey(generatedCert.second);

    // the rest of parameters are insignificant
    setSslCiphers(XSslConfiguration::supportedCiphers());
    setSslProtocol(QSsl::TlsV1_0OrLater);

    return true;
}


bool SslTest07::prepare(const SslUserSettings &settings)
{
    QList<XSslCertificate> chain = settings.getUserCaCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings.getUserCaKey();
    if (key.isNull())
        return false;

    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert("www.example.com", chain.at(0), key);

    setLocalCert(generatedCert.first);
    setPrivateKey(generatedCert.second);

    // the rest of parameters are insignificant
    setSslCiphers(XSslConfiguration::supportedCiphers());
    setSslProtocol(QSsl::TlsV1_0OrLater);

    return true;
}


void SslTest08::setProtoAndCiphers()
{
    QSsl::SslProtocol proto = QSsl::SslV2;
    QList<XSslCipher> ciphers = XSslConfiguration::supportedCiphers();

    setSslCiphers(ciphers);
    setSslProtocol(proto);
}


void SslTest09::setProtoAndCiphers()
{
    QSsl::SslProtocol proto = QSsl::SslV3;
    QList<XSslCipher> ciphers = XSslConfiguration::supportedCiphers();

    setSslCiphers(ciphers);
    setSslProtocol(proto);
}


void SslTest10::setProtoAndCiphers()
{
    QSsl::SslProtocol proto = QSsl::SslV3;
    QList<XSslCipher> ciphers;
    QStringList opensslCiphers = ciphers_export_str.split(":");

    for (int i = 0; i < opensslCiphers.size(); i++) {
        XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

        if (!cipher.isNull())
            ciphers << cipher;
    }

    setSslCiphers(ciphers);
    setSslProtocol(proto);
}


void SslTest11::setProtoAndCiphers()
{
    QSsl::SslProtocol proto = QSsl::SslV3;
    QList<XSslCipher> ciphers;
    QStringList opensslCiphers = ciphers_low_str.split(":");

    for (int i = 0; i < opensslCiphers.size(); i++) {
        XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

        if (!cipher.isNull())
            ciphers << cipher;
    }

    setSslCiphers(ciphers);
    setSslProtocol(proto);
}


void SslTest12::setProtoAndCiphers()
{
    QSsl::SslProtocol proto = QSsl::SslV3;
    QList<XSslCipher> ciphers;
    QStringList opensslCiphers = ciphers_medium_str.split(":");

    for (int i = 0; i < opensslCiphers.size(); i++) {
        XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

        if (!cipher.isNull())
            ciphers << cipher;
    }

    setSslCiphers(ciphers);
    setSslProtocol(proto);
}

