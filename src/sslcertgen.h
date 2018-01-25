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
#define XSsl SslUnsafe
#define XSslCertificate SslUnsafeCertificate
#define XSslKey SslUnsafeKey
#else
#define XSsl QSsl
#define XSslCertificate QSslCertificate
#define XSslKey QSslKey
#endif

class SslCertGen
{
public:
    SslCertGen();

    static XSslCertificate certFromFile(const QString &path, XSsl::EncodingFormat format = XSsl::Pem);

    static QList<XSslCertificate> certChainFromFile(const QString &path, XSsl::EncodingFormat format = XSsl::Pem);

    static XSslKey keyFromFile(const QString &path, XSsl::KeyAlgorithm algorithm = XSsl::Rsa,
                               XSsl::EncodingFormat format = XSsl::Pem, const QByteArray &passPhrase = QByteArray());

    static QPair<XSslCertificate, XSslKey> genSignedCert(const QString &domain, const XSslKey &key = XSslKey());

    static QPair<XSslCertificate, XSslKey> genSignedCertFromTemplate(const XSslCertificate &basecert,
                                                                     const XSslKey &key = XSslKey());

    static QPair<QList<XSslCertificate>, XSslKey> genSignedByCACert(const QString &domain,
                                                                    const XSslCertificate &cacert,
                                                                    const XSslKey &cakey);

    static QPair<QList<XSslCertificate>, XSslKey> genSignedByCACertFromTemplate(const XSslCertificate &basecert,
                                                                                const XSslCertificate &cacert,
                                                                                const XSslKey &cakey);

    static QPair<QList<XSslCertificate>, XSslKey> genSignedByCACertChain(const QString &domain,
                                                                         const XSslCertificate &cacert,
                                                                         const XSslKey &cakey);
};

#endif // SSLCERTGEN_H
