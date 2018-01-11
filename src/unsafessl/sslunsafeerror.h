#ifndef SSLUNSAFEERROR_H
#define SSLUNSAFEERROR_H

#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/qvariant.h>
#include "sslunsafecertificate.h"


#ifndef QT_NO_SSL

class SslUnsafeErrorPrivate;
class SslUnsafeError
{
public:
    enum SslError {
        NoError,
        UnableToGetIssuerCertificate,
        UnableToDecryptCertificateSignature,
        UnableToDecodeIssuerPublicKey,
        CertificateSignatureFailed,
        CertificateNotYetValid,
        CertificateExpired,
        InvalidNotBeforeField,
        InvalidNotAfterField,
        SelfSignedCertificate,
        SelfSignedCertificateInChain,
        UnableToGetLocalIssuerCertificate,
        UnableToVerifyFirstCertificate,
        CertificateRevoked,
        InvalidCaCertificate,
        PathLengthExceeded,
        InvalidPurpose,
        CertificateUntrusted,
        CertificateRejected,
        SubjectIssuerMismatch, // hostname mismatch?
        AuthorityIssuerSerialNumberMismatch,
        NoPeerCertificate,
        HostNameMismatch,
        NoSslSupport,
        CertificateBlacklisted,
        UnspecifiedError = -1
    };

    // RVCT compiler in debug build does not like about default values in const-
    // So as an workaround we define all constructor overloads here explicitly
    SslUnsafeError();
    SslUnsafeError(SslError error);
    SslUnsafeError(SslError error, const SslUnsafeCertificate &certificate);

    SslUnsafeError(const SslUnsafeError &other);

    void swap(SslUnsafeError &other) Q_DECL_NOTHROW
    { qSwap(d, other.d); }

    ~SslUnsafeError();
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeError &operator=(SslUnsafeError &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeError &operator=(const SslUnsafeError &other);
    bool operator==(const SslUnsafeError &other) const;
    inline bool operator!=(const SslUnsafeError &other) const
    { return !(*this == other); }

    SslError error() const;
    QString errorString() const;
    SslUnsafeCertificate certificate() const;

private:
    QScopedPointer<SslUnsafeErrorPrivate> d;
};
Q_DECLARE_SHARED(SslUnsafeError)

uint qHash(const SslUnsafeError &key, uint seed = 0) Q_DECL_NOTHROW;

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
QDebug operator<<(QDebug debug, const SslUnsafeError &error);
QDebug operator<<(QDebug debug, const SslUnsafeError::SslError &error);
#endif

#endif // QT_NO_SSL

#ifndef QT_NO_SSL
Q_DECLARE_METATYPE(QList<SslUnsafeError>)
#endif

#endif
