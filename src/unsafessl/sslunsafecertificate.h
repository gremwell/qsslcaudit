#ifndef SSLUNSAFECERTIFICATE_H
#define SSLUNSAFECERTIFICATE_H

#ifdef verify
#undef verify
#endif

//#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/qnamespace.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qcryptographichash.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qregexp.h>
#include <QtCore/qsharedpointer.h>
#include <QtCore/qmap.h>
#include "sslunsafe.h"

#ifndef QT_NO_SSL

class QDateTime;
class QIODevice;
class SslUnsafeError;
class SslUnsafeKey;
class SslUnsafeCertificateExtension;
class QStringList;

class SslUnsafeCertificate;
// qHash is a friend, but we can't use default arguments for friends (§8.3.6.4)
uint qHash(const SslUnsafeCertificate &key, uint seed = 0) Q_DECL_NOTHROW;

class SslUnsafeCertificatePrivate;
class SslUnsafeCertificate
{
public:
    enum SubjectInfo {
        Organization,
        CommonName,
        LocalityName,
        OrganizationalUnitName,
        CountryName,
        StateOrProvinceName,
        DistinguishedNameQualifier,
        SerialNumber,
        EmailAddress
    };

    explicit SslUnsafeCertificate(QIODevice *device, SslUnsafe::EncodingFormat format = SslUnsafe::Pem);
    explicit SslUnsafeCertificate(const QByteArray &data = QByteArray(), SslUnsafe::EncodingFormat format = SslUnsafe::Pem);
    SslUnsafeCertificate(const SslUnsafeCertificate &other);
    ~SslUnsafeCertificate();
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeCertificate &operator=(SslUnsafeCertificate &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeCertificate &operator=(const SslUnsafeCertificate &other);

    void swap(SslUnsafeCertificate &other) Q_DECL_NOTHROW
    { qSwap(d, other.d); }

    bool operator==(const SslUnsafeCertificate &other) const;
    inline bool operator!=(const SslUnsafeCertificate &other) const { return !operator==(other); }

    bool isNull() const;
#if QT_DEPRECATED_SINCE(5,0)
    QT_DEPRECATED inline bool isValid() const {
        const QDateTime currentTime = QDateTime::currentDateTimeUtc();
        return currentTime >= effectiveDate() &&
               currentTime <= expiryDate() &&
               !isBlacklisted();
    }
#endif
    bool isBlacklisted() const;
    bool isSelfSigned() const;
    void clear();

    // Certificate info
    QByteArray version() const;
    QByteArray serialNumber() const;
    QByteArray digest(QCryptographicHash::Algorithm algorithm = QCryptographicHash::Md5) const;
    QStringList issuerInfo(SubjectInfo info) const;
    QStringList issuerInfo(const QByteArray &attribute) const;
    QStringList subjectInfo(SubjectInfo info) const;
    QStringList subjectInfo(const QByteArray &attribute) const;
    QList<QByteArray> subjectInfoAttributes() const;
    QList<QByteArray> issuerInfoAttributes() const;
#if QT_DEPRECATED_SINCE(5,0)
    QT_DEPRECATED inline QMultiMap<SslUnsafe::AlternateNameEntryType, QString>
                  alternateSubjectNames() const { return subjectAlternativeNames(); }
#endif
    QMultiMap<SslUnsafe::AlternativeNameEntryType, QString> subjectAlternativeNames() const;
    QDateTime effectiveDate() const;
    QDateTime expiryDate() const;
    SslUnsafeKey publicKey() const;
    QList<SslUnsafeCertificateExtension> extensions() const;

    QByteArray toPem() const;
    QByteArray toDer() const;
    QString toText() const;

    static QList<SslUnsafeCertificate> fromPath(
        const QString &path, SslUnsafe::EncodingFormat format = SslUnsafe::Pem,
        QRegExp::PatternSyntax syntax = QRegExp::FixedString);
    static QList<SslUnsafeCertificate> fromDevice(
        QIODevice *device, SslUnsafe::EncodingFormat format = SslUnsafe::Pem);
    static QList<SslUnsafeCertificate> fromData(
        const QByteArray &data, SslUnsafe::EncodingFormat format = SslUnsafe::Pem);

#if QT_VERSION >= QT_VERSION_CHECK(6,0,0)
    static QList<SslUnsafeError> verify(const QList<SslUnsafeCertificate> &certificateChain, const QString &hostName = QString());
#else
    static QList<SslUnsafeError> verify(QList<SslUnsafeCertificate> certificateChain, const QString &hostName = QString());
#endif

    static bool importPkcs12(QIODevice *device,
                             SslUnsafeKey *key, SslUnsafeCertificate *cert,
                             QList<SslUnsafeCertificate> *caCertificates = Q_NULLPTR,
                             const QByteArray &passPhrase=QByteArray());

    Qt::HANDLE handle() const;

private:
    QExplicitlySharedDataPointer<SslUnsafeCertificatePrivate> d;
    friend class SslUnsafeCertificatePrivate;
    friend class QSslSocketBackendPrivate;

    friend Q_NETWORK_EXPORT uint qHash(const SslUnsafeCertificate &key, uint seed) Q_DECL_NOTHROW;
};
Q_DECLARE_SHARED(SslUnsafeCertificate)

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const SslUnsafeCertificate &certificate);
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, SslUnsafeCertificate::SubjectInfo info);
#endif

Q_DECLARE_METATYPE(SslUnsafeCertificate)

#endif // QT_NO_SSL

#endif
