#ifndef SSLUNSAFEKEY_H
#define SSLUNSAFEKEY_H

#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/qnamespace.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qsharedpointer.h>
#include <QtNetwork/qssl.h>


#ifndef QT_NO_SSL

template <typename A, typename B> struct QPair;

class QIODevice;

class SslUnsafeKeyPrivate;
class SslUnsafeKey
{
public:
    SslUnsafeKey();
    SslUnsafeKey(const QByteArray &encoded, QSsl::KeyAlgorithm algorithm,
            QSsl::EncodingFormat format = QSsl::Pem,
            QSsl::KeyType type = QSsl::PrivateKey,
            const QByteArray &passPhrase = QByteArray());
    SslUnsafeKey(QIODevice *device, QSsl::KeyAlgorithm algorithm,
            QSsl::EncodingFormat format = QSsl::Pem,
            QSsl::KeyType type = QSsl::PrivateKey,
            const QByteArray &passPhrase = QByteArray());
    explicit SslUnsafeKey(Qt::HANDLE handle, QSsl::KeyType type = QSsl::PrivateKey);
    SslUnsafeKey(const SslUnsafeKey &other);
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeKey &operator=(SslUnsafeKey &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeKey &operator=(const SslUnsafeKey &other);
    ~SslUnsafeKey();

    void swap(SslUnsafeKey &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    bool isNull() const;
    void clear();

    int length() const;
    QSsl::KeyType type() const;
    QSsl::KeyAlgorithm algorithm() const;

    QByteArray toPem(const QByteArray &passPhrase = QByteArray()) const;
    QByteArray toDer(const QByteArray &passPhrase = QByteArray()) const;

    Qt::HANDLE handle() const;

    bool operator==(const SslUnsafeKey &key) const;
    inline bool operator!=(const SslUnsafeKey &key) const { return !operator==(key); }

private:
    QExplicitlySharedDataPointer<SslUnsafeKeyPrivate> d;
    friend class SslUnsafeCertificate;
    friend class SslUnsafeSocketBackendPrivate;
};

Q_DECLARE_SHARED(SslUnsafeKey)

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
QDebug operator<<(QDebug debug, const SslUnsafeKey &key);
#endif

#endif // QT_NO_SSL

#endif
