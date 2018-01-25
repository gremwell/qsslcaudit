
#ifndef SSLUNSAFECIPHER_H
#define SSLUNSAFECIPHER_H

#include <QtCore/qstring.h>
#include <QtCore/qscopedpointer.h>
#include "sslunsafe.h"


#ifndef QT_NO_SSL

class SslUnsafeCipherPrivate;
class SslUnsafeCipher
{
public:
    SslUnsafeCipher();
    explicit SslUnsafeCipher(const QString &name);
    SslUnsafeCipher(const QString &name, SslUnsafe::SslProtocol protocol);
    SslUnsafeCipher(const SslUnsafeCipher &other);
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeCipher &operator=(SslUnsafeCipher &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeCipher &operator=(const SslUnsafeCipher &other);
    ~SslUnsafeCipher();

    void swap(SslUnsafeCipher &other) Q_DECL_NOTHROW
    { qSwap(d, other.d); }

    bool operator==(const SslUnsafeCipher &other) const;
    inline bool operator!=(const SslUnsafeCipher &other) const { return !operator==(other); }

    bool isNull() const;
    QString name() const;
    int supportedBits() const;
    int usedBits() const;

    QString keyExchangeMethod() const;
    QString authenticationMethod() const;
    QString encryptionMethod() const;
    QString protocolString() const;
    SslUnsafe::SslProtocol protocol() const;

private:
    QScopedPointer<SslUnsafeCipherPrivate> d;
    friend class SslUnsafeSocketBackendPrivate;
};

Q_DECLARE_SHARED(SslUnsafeCipher)

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
QDebug operator<<(QDebug debug, const SslUnsafeCipher &cipher);
#endif

#endif // QT_NO_SSL

#endif
