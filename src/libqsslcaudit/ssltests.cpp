
#include "ssltests.h"
#include "sslcertgen.h"
#include "debug.h"

#ifdef UNSAFE_QSSL
#include "sslunsafeconfiguration.h"
#else
#include <QSslConfiguration>
#endif


bool SslTest01::prepare(const SslUserSettings &settings)
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

    setLocalCert(chain);

    XSslKey key = settings.getUserKey();
    if (key.isNull()) {
        RED("can not parse user-supplied key");
        return false;
    }

    setPrivateKey(key);

    setSslCiphers(XSslConfiguration::supportedCiphers());
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        setDtlsProto(true);
        setSslProtocol(XSsl::DtlsV1_0OrLater);
    } else {
        setSslProtocol(XSsl::AnyProtocol);
    }

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

    setSslCiphers(XSslConfiguration::supportedCiphers());
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        setDtlsProto(true);
        setSslProtocol(XSsl::DtlsV1_0OrLater);
    } else {
        setSslProtocol(XSsl::AnyProtocol);
    }

    return true;
}


bool SslTest03::prepare(const SslUserSettings &settings)
{
    QPair<XSslCertificate, XSslKey> cert = SslCertGen::genSignedCert("www.example.com");

    QList<XSslCertificate> chain;
    chain << cert.first;

    setLocalCert(chain);
    setPrivateKey(cert.second);

    setSslCiphers(XSslConfiguration::supportedCiphers());
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        setDtlsProto(true);
        setSslProtocol(XSsl::DtlsV1_0OrLater);
    } else {
        setSslProtocol(XSsl::AnyProtocol);
    }

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

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    setLocalCert(generatedCert.first);
    setPrivateKey(generatedCert.second);

    setSslCiphers(XSslConfiguration::supportedCiphers());
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        setDtlsProto(true);
        setSslProtocol(XSsl::DtlsV1_0OrLater);
    } else {
        setSslProtocol(XSsl::AnyProtocol);
    }

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

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    setLocalCert(generatedCert.first);
    setPrivateKey(generatedCert.second);

    setSslCiphers(XSslConfiguration::supportedCiphers());
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        setDtlsProto(true);
        setSslProtocol(XSsl::DtlsV1_0OrLater);
    } else {
        setSslProtocol(XSsl::AnyProtocol);
    }

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

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    setLocalCert(generatedCert.first);
    setPrivateKey(generatedCert.second);

    setSslCiphers(XSslConfiguration::supportedCiphers());
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        setDtlsProto(true);
        setSslProtocol(XSsl::DtlsV1_0OrLater);
    } else {
        setSslProtocol(XSsl::AnyProtocol);
    }

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

    generatedCert.first << chain.mid(1); // create full chain of certificates (if user provided)

    setLocalCert(generatedCert.first);
    setPrivateKey(generatedCert.second);

    setSslCiphers(XSslConfiguration::supportedCiphers());
    // DTLS mode requires specific protocol to be set
    if (settings.getUseDtls()) {
        setDtlsProto(true);
        setSslProtocol(XSsl::DtlsV1_0OrLater);
    } else {
        setSslProtocol(XSsl::AnyProtocol);
    }

    return true;
}


bool SslTest08::setProtoAndCiphers()
{
    return setProtoAndSupportedCiphers(XSsl::SslV2);
}


bool SslTest09::setProtoAndCiphers()
{
    return setProtoAndSupportedCiphers(XSsl::SslV3);
}


bool SslTest10::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::SslV3);
}


bool SslTest11::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::SslV3);
}


bool SslTest12::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::SslV3);
}


bool SslTest13::setProtoAndCiphers()
{
    return setProtoAndSupportedCiphers(XSsl::TlsV1_0);
}


bool SslTest14::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::TlsV1_0);
}


bool SslTest15::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::TlsV1_0);
}


bool SslTest16::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::TlsV1_0);
}


bool SslTest17::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::TlsV1_1);
}


bool SslTest18::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::TlsV1_1);
}


bool SslTest19::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::TlsV1_1);
}


bool SslTest20::setProtoAndCiphers()
{
    return setProtoAndExportCiphers(XSsl::TlsV1_2);
}


bool SslTest21::setProtoAndCiphers()
{
    return setProtoAndLowCiphers(XSsl::TlsV1_2);
}


bool SslTest22::setProtoAndCiphers()
{
    return setProtoAndMediumCiphers(XSsl::TlsV1_2);
}
