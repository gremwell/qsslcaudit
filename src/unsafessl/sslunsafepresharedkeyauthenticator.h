#ifndef SSLUNSAFEPRESHAREDKEYAUTHENTICATOR_H
#define SSLUNSAFEPRESHAREDKEYAUTHENTICATOR_H

#include <QtNetwork/qtnetworkglobal.h>
#include <QtCore/QString>
#include <QtCore/QSharedDataPointer>
#include <QtCore/QMetaType>

class SslUnsafePreSharedKeyAuthenticatorPrivate;

class SslUnsafePreSharedKeyAuthenticator
{
public:
    SslUnsafePreSharedKeyAuthenticator();
    ~SslUnsafePreSharedKeyAuthenticator();
    SslUnsafePreSharedKeyAuthenticator(const SslUnsafePreSharedKeyAuthenticator &authenticator);
    SslUnsafePreSharedKeyAuthenticator &operator=(const SslUnsafePreSharedKeyAuthenticator &authenticator);

#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafePreSharedKeyAuthenticator &operator=(SslUnsafePreSharedKeyAuthenticator &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif

    void swap(SslUnsafePreSharedKeyAuthenticator &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    QByteArray identityHint() const;

    void setIdentity(const QByteArray &identity);
    QByteArray identity() const;
    int maximumIdentityLength() const;

    void setPreSharedKey(const QByteArray &preSharedKey);
    QByteArray preSharedKey() const;
    int maximumPreSharedKeyLength() const;

private:
    friend bool operator==(const SslUnsafePreSharedKeyAuthenticator &lhs, const SslUnsafePreSharedKeyAuthenticator &rhs);
    friend class SslUnsafeSocketBackendPrivate;

    QSharedDataPointer<SslUnsafePreSharedKeyAuthenticatorPrivate> d;
};

inline bool operator!=(const SslUnsafePreSharedKeyAuthenticator &lhs, const SslUnsafePreSharedKeyAuthenticator &rhs)
{
    return !operator==(lhs, rhs);
}

Q_DECLARE_SHARED(SslUnsafePreSharedKeyAuthenticator)

Q_DECLARE_METATYPE(SslUnsafePreSharedKeyAuthenticator)
Q_DECLARE_METATYPE(SslUnsafePreSharedKeyAuthenticator*)

#endif // SslUnsafePreSharedKeyAuthenticator_H
