
#include "ssltests.h"
#include "sslcertgen.h"
#include "debug.h"

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
    if (settings.getUserCN().length()) {
        return false;
    }

    QPair<XSslCertificate, XSslKey> cert = SslCertGen::genSignedCert(settings.getUserCN());

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
    if (settings.getUserCN().length() == 0)
        return false;

    QList<XSslCertificate> chain = settings.getUserCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings.getUserKey();
    if (key.isNull())
        return false;

    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert(settings.getUserCN(), chain.at(0), key);

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
    if (settings.getUserCN().length() == 0)
        return false;


    QList<XSslCertificate> chain = settings.getUserCaCert();
    if (chain.size() == 0)
        return false;

    XSslKey key = settings.getUserCaKey();
    if (key.isNull())
        return false;


    QPair<QList<XSslCertificate>, XSslKey> generatedCert = SslCertGen::genSignedByCACert(settings.getUserCN(), chain.at(0), key);

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


bool SslTest08::prepare(const SslUserSettings &settings)
{
    QSsl::SslProtocol proto = QSsl::TlsV1_0OrLater;
    QList<XSslCipher> ciphers = XSslConfiguration::supportedCiphers();

    QList<XSslCertificate> chain;
    XSslKey key;
    QString cn;

    if (settings.getUserCN().length() > 0) {
        cn = settings.getUserCN();
    } else {
        cn = "www.example.com";
    }

    chain = settings.getUserCert();
    if (chain.size() != 0) {
        key = settings.getUserKey();
    }

    if ((chain.size() == 0) || key.isNull()) {
        QPair<XSslCertificate, XSslKey> generatedCert = SslCertGen::genSignedCert(cn);
        chain << generatedCert.first;
        key = generatedCert.second;
    }

    // these parameters should be insignificant, but we tried to make them as much "trustful" as possible
    setLocalCert(chain);
    setPrivateKey(key);

    // actual parameters we are testing
    setSslProtocol(proto);
    setSslCiphers(ciphers);

    return true;
}

void SslTest08::report(const QList<XSslError> sslErrors,
                       const QList<QAbstractSocket::SocketError> socketErrors,
                       bool sslConnectionEstablished,
                       bool dataReceived) const
{
    RED("not implemented");
}
