#ifndef SSLCERTGEN_H
#define SSLCERTGEN_H

#include <QPair>
#ifdef UNSAFE
#include "sslunsafecertificate.h"
#include "sslunsafekey.h"
#else
#include <QSslCertificate>
#include <QSslKey>
#endif

#ifdef UNSAFE
#define XSslCertificate SslUnsafeCertificate
#define XSslKey SslUnsafeKey
#else
#define XSslCertificate QSslCertificate
#define XSslKey QSslKey
#endif

class SslCertGen
{
public:
    SslCertGen();

    static XSslCertificate certFromFile(const QString &path, QSsl::EncodingFormat format = QSsl::Pem);

    static QList<XSslCertificate> certChainFromFile(const QString &path, QSsl::EncodingFormat format = QSsl::Pem);

    static XSslKey keyFromFile(const QString &path, QSsl::KeyAlgorithm algorithm = QSsl::Rsa,
                               QSsl::EncodingFormat format = QSsl::Pem, const QByteArray &passPhrase = QByteArray());

    static QPair<XSslCertificate, XSslKey> genSignedCert(const QString &domain, const XSslKey &key = XSslKey());

    static QPair<QList<XSslCertificate>, XSslKey> genSignedByCACert(const QString &domain,
                                                                    const XSslCertificate &cacert,
                                                                    const XSslKey &cakey);

    static QPair<QList<XSslCertificate>, XSslKey> genSignedByCACertChain(const QString &domain,
                                                                         const XSslCertificate &cacert,
                                                                         const XSslKey &cakey);
};

#endif // SSLCERTGEN_H
