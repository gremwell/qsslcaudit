
#include "sslcertgen.h"

#include <QDebug>
#include <QFile>

#include <keybuilder.h>
#include <certificaterequestbuilder.h>
#include <certificaterequest.h>
#include <certificatebuilder.h>
#include <randomgenerator.h>
#include <certificate.h>

QT_USE_NAMESPACE_CERTIFICATE


SslCertGen::SslCertGen()
{

}

XSslCertificate SslCertGen::certFromFile(const QString &path, QSsl::EncodingFormat format)
{
    XSslCertificate ret;
    QFile certificateFile(path);

    if (!certificateFile.open(QIODevice::ReadOnly)) {
        qDebug() << "failed to open file" << path;
        return ret;
    }

    ret = XSslCertificate(certificateFile.readAll(), format);
    if (ret.isNull())
        qDebug() << "failed to read certificate from file" << path;

    return ret;
}

QList<XSslCertificate> SslCertGen::certChainFromFile(const QString &path, QSsl::EncodingFormat format)
{
    QList<XSslCertificate> ret;
    QFile certificateFile(path);

    if (!certificateFile.open(QIODevice::ReadOnly)) {
        qDebug() << "failed to open file" << path;
        return ret;
    }

    // fromData reads all certificates in file
    ret = XSslCertificate::fromData(certificateFile.readAll(), format);

    return ret;
}

XSslKey SslCertGen::keyFromFile(const QString &path, QSsl::KeyAlgorithm algorithm,
                                QSsl::EncodingFormat format, const QByteArray &passPhrase)
{
    XSslKey ret;
    QFile keyFile(path);

    if (!keyFile.open(QIODevice::ReadOnly)) {
        qDebug() << "failed to open file" << path;
        return ret;
    }

    ret = XSslKey(keyFile.readAll(), algorithm, format, QSsl::PrivateKey, passPhrase);
    if (ret.isNull())
        qDebug() << "failed to read key from file" << path;

    return ret;
}

static CertificateRequest genCertRequest(const XSslKey &key, const QString &commonName, const QString &org = "Gremwell")
{
    CertificateRequestBuilder reqbuilder;
    reqbuilder.setVersion(1);
    reqbuilder.setKey(key);
    reqbuilder.addNameEntry(Certificate::EntryCountryName, "BE");
    reqbuilder.addNameEntry(Certificate::EntryOrganizationName, org.toLocal8Bit());
    if (commonName.length() > 0)
        reqbuilder.addNameEntry(Certificate::EntryCommonName, commonName.toLocal8Bit());

    // sign the request
    CertificateRequest req = reqbuilder.signedRequest(key);

    return req;
}

static void setCertOptions(CertificateBuilder *builder, bool constrains, bool cansign)
{
    // set common options
    builder->setVersion(3);
    builder->setSerial(RandomGenerator::getPositiveBytes(16));
    builder->setActivationTime(QDateTime::currentDateTimeUtc());
    builder->setExpirationTime(QDateTime::currentDateTimeUtc().addYears(10));
    CertificateBuilder::KeyUsageFlags flags = CertificateBuilder::UsageKeyEncipherment | CertificateBuilder::UsageDigitalSignature;
    if (cansign)
        flags |= CertificateBuilder::UsageKeyCertSign;
    builder->setKeyUsage(flags);
    builder->addKeyPurpose(CertificateBuilder::PurposeWebServer);
    builder->addKeyPurpose(CertificateBuilder::PurposeWebClient);
    builder->addSubjectKeyIdentifier();

    builder->setBasicConstraints(constrains);
}

QPair<XSslCertificate, XSslKey> SslCertGen::genSignedCert(const QString &domain, const XSslKey &ukey)
{
    XSslKey key;

    // if null key is provided, then generate self-signed certificate with random private key,
    // otherwise, use the provided key
    if (ukey.isNull()) {
        key = KeyBuilder::generate(QSsl::Rsa, KeyBuilder::StrengthNormal);
    } else {
        key = ukey;
    }

    CertificateRequest req = genCertRequest(key, domain);

    // make a certificate
    CertificateBuilder builder;
    builder.setRequest(req);

    setCertOptions(&builder, false, false);

    XSslCertificate cert = builder.signedCertificate(key);

    return QPair<XSslCertificate, XSslKey>(cert, key);
}

QPair<QList<XSslCertificate>, XSslKey> SslCertGen::genSignedByCACert(const QString &domain,
                                                                     const XSslCertificate &cacert,
                                                                     const XSslKey &cakey)
{
    XSslKey leafkey = KeyBuilder::generate(QSsl::Rsa, KeyBuilder::StrengthNormal);

    CertificateRequest leafreq = genCertRequest(leafkey, domain);

    CertificateBuilder leafbuilder;
    leafbuilder.setRequest(leafreq);

    setCertOptions(&leafbuilder, false, false);

    leafbuilder.addAuthorityKeyIdentifier(cacert);

    XSslCertificate leafcert = leafbuilder.signedCertificate(cacert, cakey);

    QList<XSslCertificate> chain;
    chain.append(leafcert);
    chain.append(cacert);
    return QPair<QList<XSslCertificate>, XSslKey>(chain, leafkey);
}

QPair<QList<XSslCertificate>, XSslKey> SslCertGen::genSignedByCACertChain(const QString &domain,
                                                                          const XSslCertificate &cacert,
                                                                          const XSslKey &cakey)
{
    // make an intermediate
    XSslKey interkey = KeyBuilder::generate(QSsl::Rsa, KeyBuilder::StrengthNormal);

    CertificateRequest interreq = genCertRequest(interkey, "", "Gremwell Intermediate Auth");

    CertificateBuilder interbuilder;
    interbuilder.setRequest(interreq);

    setCertOptions(&interbuilder, true, true);

    interbuilder.copyRequestExtensions(interreq);
    interbuilder.addAuthorityKeyIdentifier(cacert);

    XSslCertificate intercert = interbuilder.signedCertificate(cacert, cakey);

    // Create the leaf
    XSslKey leafkey = KeyBuilder::generate(QSsl::Rsa, KeyBuilder::StrengthNormal);

    CertificateRequest leafreq = genCertRequest(leafkey, domain);

    CertificateBuilder leafbuilder;
    leafbuilder.setRequest(leafreq);

    setCertOptions(&leafbuilder, false, false);

    leafbuilder.copyRequestExtensions(leafreq);
    leafbuilder.addAuthorityKeyIdentifier(intercert);

    XSslCertificate leafcert = leafbuilder.signedCertificate(intercert, interkey);

    QList<XSslCertificate> chain;
    chain.append(leafcert);
    chain.append(intercert);
    chain.append(cacert);
    return QPair<QList<XSslCertificate>, XSslKey>(chain, leafkey);
}
