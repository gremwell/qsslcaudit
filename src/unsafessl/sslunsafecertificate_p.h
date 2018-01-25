#ifndef SSLUNSAFECERTIFICATE_OPENSSL_P_H
#define SSLUNSAFECERTIFICATE_OPENSSL_P_H

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "sslunsafecertificate.h"

#include "sslunsafesocket_p.h"
#include "sslunsafecertificateextension.h"
#include <QtCore/qdatetime.h>
#include <QtCore/qmap.h>

#ifndef QT_NO_OPENSSL
#include <openssl/x509.h>
#else
struct X509;
struct X509_EXTENSION;
struct ASN1_OBJECT;
#endif

#ifdef Q_OS_WINRT
#include <wrl.h>
#include <windows.security.cryptography.certificates.h>
#endif

// forward declaration

class SslUnsafeCertificatePrivate
{
public:
    SslUnsafeCertificatePrivate()
        : null(true), x509(0)
    {
        SslUnsafeSocketPrivate::ensureInitialized();
    }

    ~SslUnsafeCertificatePrivate()
    {
#ifndef QT_NO_OPENSSL
        if (x509)
            q_X509_free(x509);
#endif
    }

    bool null;
    QByteArray versionString;
    QByteArray serialNumberString;

    QMap<QByteArray, QString> issuerInfo;
    QMap<QByteArray, QString> subjectInfo;
    QDateTime notValidAfter;
    QDateTime notValidBefore;

#ifdef QT_NO_OPENSSL
    bool subjectMatchesIssuer;
    QSsl::KeyAlgorithm publicKeyAlgorithm;
    QByteArray publicKeyDerData;
    QMultiMap<QSsl::AlternativeNameEntryType, QString> subjectAlternativeNames;
    QList<QSslCertificateExtension> extensions;

    QByteArray derData;

    bool parse(const QByteArray &data);
    bool parseExtension(const QByteArray &data, QSslCertificateExtension *extension);
#endif
    X509 *x509;

    void init(const QByteArray &data, QSsl::EncodingFormat format);

    static QByteArray asn1ObjectId(ASN1_OBJECT *object);
    static QByteArray asn1ObjectName(ASN1_OBJECT *object);
    static QByteArray QByteArray_from_X509(X509 *x509, QSsl::EncodingFormat format);
    static QString text_from_X509(X509 *x509);
    static SslUnsafeCertificate SslUnsafeCertificate_from_X509(X509 *x509);
    static QList<SslUnsafeCertificate> certificatesFromPem(const QByteArray &pem, int count = -1);
    static QList<SslUnsafeCertificate> certificatesFromDer(const QByteArray &der, int count = -1);
    static bool isBlacklisted(const SslUnsafeCertificate &certificate);
    static SslUnsafeCertificateExtension convertExtension(X509_EXTENSION *ext);
    static QByteArray subjectInfoToString(SslUnsafeCertificate::SubjectInfo info);

    friend class SslUnsafeSocketBackendPrivate;

    QAtomicInt ref;

#ifdef Q_OS_WINRT
    Microsoft::WRL::ComPtr<ABI::Windows::Security::Cryptography::Certificates::ICertificate> certificate;

    static SslUnsafeCertificate QSslCertificate_from_Certificate(ABI::Windows::Security::Cryptography::Certificates::ICertificate *iCertificate);
#endif
};

#endif // QSSLCERTIFICATE_OPENSSL_P_H
