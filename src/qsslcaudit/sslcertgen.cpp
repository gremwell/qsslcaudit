
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

XSslCertificate SslCertGen::certFromFile(const QString &path, XSsl::EncodingFormat format)
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

QList<XSslCertificate> SslCertGen::certChainFromFile(const QString &path, XSsl::EncodingFormat format)
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

XSslKey SslCertGen::keyFromFile(const QString &path, XSsl::KeyAlgorithm algorithm,
                                XSsl::EncodingFormat format, const QByteArray &passPhrase)
{
    XSslKey ret;
    QFile keyFile(path);

    if (!keyFile.open(QIODevice::ReadOnly)) {
        qDebug() << "failed to open file" << path;
        return ret;
    }

    ret = XSslKey(keyFile.readAll(), algorithm, format, XSsl::PrivateKey, passPhrase);
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

static CertificateRequest genCertRequestFromTemplate(const XSslKey &key, const XSslCertificate &basecert)
{
    CertificateRequestBuilder reqbuilder;
    reqbuilder.setVersion(1);
    reqbuilder.setKey(key);

    QStringList info;

    info = basecert.subjectInfo(XSslCertificate::Organization);
    if (!info.isEmpty()) {
        for (int i = 0; i < info.size(); i++) {
            reqbuilder.addNameEntry(Certificate::EntryOrganizationName, info.at(i).toLocal8Bit());
        }
    }

    info = basecert.subjectInfo(XSslCertificate::CommonName);
    if (!info.isEmpty()) {
        for (int i = 0; i < info.size(); i++) {
            reqbuilder.addNameEntry(Certificate::EntryCommonName, info.at(i).toLocal8Bit());
        }
    }

    info = basecert.subjectInfo(XSslCertificate::LocalityName);
    if (!info.isEmpty()) {
        for (int i = 0; i < info.size(); i++) {
            reqbuilder.addNameEntry(Certificate::EntryLocalityName, info.at(i).toLocal8Bit());
        }
    }

    info = basecert.subjectInfo(XSslCertificate::OrganizationalUnitName);
    if (!info.isEmpty()) {
        for (int i = 0; i < info.size(); i++) {
            reqbuilder.addNameEntry(Certificate::EntryOrganizationalUnitName, info.at(i).toLocal8Bit());
        }
    }

    info = basecert.subjectInfo(XSslCertificate::CountryName);
    if (!info.isEmpty()) {
        for (int i = 0; i < info.size(); i++) {
            reqbuilder.addNameEntry(Certificate::EntryCountryName, info.at(i).toLocal8Bit());
        }
    }

    info = basecert.subjectInfo(XSslCertificate::StateOrProvinceName);
    if (!info.isEmpty()) {
        for (int i = 0; i < info.size(); i++) {
            reqbuilder.addNameEntry(Certificate::EntryStateOrProvinceName, info.at(i).toLocal8Bit());
        }
    }

    info = basecert.subjectInfo(XSslCertificate::DistinguishedNameQualifier);
    if (!info.isEmpty()) {
        for (int i = 0; i < info.size(); i++) {
            reqbuilder.addNameEntry(Certificate::EntryDistinguishedNameQualifier, info.at(i).toLocal8Bit());
        }
    }

    // sign the request
    CertificateRequest req = reqbuilder.signedRequest(key);

    return req;
}

static void setCertOptions(CertificateBuilder *builder, bool constrains, bool cansign, const QByteArray &serial = RandomGenerator::getPositiveBytes(16))
{
    // set common options
    builder->setVersion(3);
    builder->setSerial(serial);
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
        key = KeyBuilder::generate(XSsl::Rsa, KeyBuilder::StrengthNormal);
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

QPair<XSslCertificate, XSslKey> SslCertGen::genSignedCertFromTemplate(const XSslCertificate &basecert,
                                                                      const XSslKey &ukey)
{
    XSslKey key;

    // if null key is provided, then generate self-signed certificate with random private key,
    // otherwise, use the provided key
    if (ukey.isNull()) {
        key = KeyBuilder::generate(XSsl::Rsa, KeyBuilder::StrengthNormal);
    } else {
        key = ukey;
    }

    CertificateRequest req = genCertRequestFromTemplate(key, basecert);

    // make a certificate
    CertificateBuilder builder;
    builder.setRequest(req);

    QStringList serialInfo = basecert.subjectInfo(XSslCertificate::SerialNumber);
    if (serialInfo.isEmpty()) {
        setCertOptions(&builder, false, false);
    } else {
        setCertOptions(&builder, false, false, serialInfo.first().toLocal8Bit());
    }

    XSslCertificate cert = builder.signedCertificate(key);

    return QPair<XSslCertificate, XSslKey>(cert, key);
}

QPair<QList<XSslCertificate>, XSslKey> SslCertGen::genSignedByCACert(const QString &domain,
                                                                     const XSslCertificate &cacert,
                                                                     const XSslKey &cakey)
{
    XSslKey leafkey = KeyBuilder::generate(XSsl::Rsa, KeyBuilder::StrengthNormal);

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

QPair<QList<XSslCertificate>, XSslKey> SslCertGen::genSignedByCACertFromTemplate(const XSslCertificate &basecert,
                                                                                 const XSslCertificate &cacert,
                                                                                 const XSslKey &cakey)
{
    XSslKey leafkey = KeyBuilder::generate(XSsl::Rsa, KeyBuilder::StrengthNormal);

    CertificateRequest leafreq = genCertRequestFromTemplate(leafkey, basecert);

    CertificateBuilder leafbuilder;
    leafbuilder.setRequest(leafreq);

    QStringList serialInfo = basecert.subjectInfo(XSslCertificate::SerialNumber);
    if (serialInfo.isEmpty()) {
        setCertOptions(&leafbuilder, false, false);
    } else {
        setCertOptions(&leafbuilder, false, false, serialInfo.first().toLocal8Bit());
    }

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
    XSslKey interkey = KeyBuilder::generate(XSsl::Rsa, KeyBuilder::StrengthNormal);

    CertificateRequest interreq = genCertRequest(interkey, "", "Gremwell Intermediate Auth");

    CertificateBuilder interbuilder;
    interbuilder.setRequest(interreq);

    setCertOptions(&interbuilder, true, true);

    interbuilder.copyRequestExtensions(interreq);
    interbuilder.addAuthorityKeyIdentifier(cacert);

    XSslCertificate intercert = interbuilder.signedCertificate(cacert, cakey);

    // Create the leaf
    XSslKey leafkey = KeyBuilder::generate(XSsl::Rsa, KeyBuilder::StrengthNormal);

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
