#ifndef SSLUNSAFEDIFFIEHELLMANPARAMETERS_H
#define SSLUNSAFEDIFFIEHELLMANPARAMETERS_H

#include "sslunsafe.h"
#include <QtCore/qnamespace.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qshareddata.h>

#ifndef QT_NO_SSL

class QIODevice;
class SslUnsafeContext;
class SslUnsafeDiffieHellmanParametersPrivate;

class SslUnsafeDiffieHellmanParameters;
// qHash is a friend, but we can't use default arguments for friends (§8.3.6.4)
uint qHash(const SslUnsafeDiffieHellmanParameters &dhparam, uint seed = 0) Q_DECL_NOTHROW;

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const SslUnsafeDiffieHellmanParameters &dhparams);
#endif

Q_NETWORK_EXPORT bool operator==(const SslUnsafeDiffieHellmanParameters &lhs, const SslUnsafeDiffieHellmanParameters &rhs) Q_DECL_NOTHROW;

inline bool operator!=(const SslUnsafeDiffieHellmanParameters &lhs, const SslUnsafeDiffieHellmanParameters &rhs) Q_DECL_NOTHROW
{
    return !operator==(lhs, rhs);
}

class SslUnsafeDiffieHellmanParameters
{
public:
    enum Error {
        NoError,
        InvalidInputDataError,
        UnsafeParametersError
    };

    static SslUnsafeDiffieHellmanParameters defaultParameters();

    SslUnsafeDiffieHellmanParameters();
    SslUnsafeDiffieHellmanParameters(const SslUnsafeDiffieHellmanParameters &other);
    SslUnsafeDiffieHellmanParameters(SslUnsafeDiffieHellmanParameters &&other) Q_DECL_NOTHROW : d(other.d) { other.d = nullptr; }
    ~SslUnsafeDiffieHellmanParameters();

    SslUnsafeDiffieHellmanParameters &operator=(const SslUnsafeDiffieHellmanParameters &other);
    SslUnsafeDiffieHellmanParameters &operator=(SslUnsafeDiffieHellmanParameters &&other) Q_DECL_NOTHROW { swap(other); return *this; }

    void swap(SslUnsafeDiffieHellmanParameters &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    static SslUnsafeDiffieHellmanParameters fromEncoded(const QByteArray &encoded, SslUnsafe::EncodingFormat format = SslUnsafe::Pem);
    static SslUnsafeDiffieHellmanParameters fromEncoded(QIODevice *device, SslUnsafe::EncodingFormat format = SslUnsafe::Pem);

    bool isEmpty() const Q_DECL_NOTHROW;
    bool isValid() const Q_DECL_NOTHROW;
    Error error() const Q_DECL_NOTHROW;
    QString errorString() const Q_DECL_NOTHROW;

private:
    SslUnsafeDiffieHellmanParametersPrivate *d;
    friend class SslUnsafeContext;
    friend Q_NETWORK_EXPORT bool operator==(const SslUnsafeDiffieHellmanParameters &lhs, const SslUnsafeDiffieHellmanParameters &rhs) Q_DECL_NOTHROW;
#ifndef QT_NO_DEBUG_STREAM
    friend Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const SslUnsafeDiffieHellmanParameters &dhparam);
#endif
    friend Q_NETWORK_EXPORT uint qHash(const SslUnsafeDiffieHellmanParameters &dhparam, uint seed) Q_DECL_NOTHROW;
};

Q_DECLARE_SHARED(SslUnsafeDiffieHellmanParameters)

#endif // QT_NO_SSL

#endif
