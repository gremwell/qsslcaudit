
#include "sslunsafepresharedkeyauthenticator.h"
#include "sslunsafepresharedkeyauthenticator_p.h"

#include <QSharedData>

/*!
    \internal
*/
SslUnsafePreSharedKeyAuthenticatorPrivate::SslUnsafePreSharedKeyAuthenticatorPrivate()
    : maximumIdentityLength(0),
      maximumPreSharedKeyLength(0)
{
}

/*!
    \class SslUnsafePreSharedKeyAuthenticator

    \brief The SslUnsafePreSharedKeyAuthenticator class provides authentication data for pre
    shared keys (PSK) ciphersuites.

    \inmodule QtNetwork

    \reentrant

    \ingroup network
    \ingroup ssl
    \ingroup shared

    \since 5.5

    The SslUnsafePreSharedKeyAuthenticator class is used by an SSL socket to provide
    the required authentication data in a pre shared key (PSK) ciphersuite.

    In a PSK handshake, the client must derive a key, which must match the key
    set on the server. The exact algorithm of deriving the key depends on the
    application; however, for this purpose, the server may send an \e{identity
    hint} to the client. This hint, combined with other information (for
    instance a passphrase), is then used by the client to construct the shared
    key.

    The SslUnsafePreSharedKeyAuthenticator provides means to client applications for
    completing the PSK handshake. The client application needs to connect a
    slot to the QSslSocket::preSharedKeyAuthenticationRequired() signal:

    \code

    connect(socket, &QSslSocket::preSharedKeyAuthenticationRequired,
            this, &AuthManager::handlePreSharedKeyAuthentication);

    \endcode

    The signal carries a SslUnsafePreSharedKeyAuthenticator object containing the
    identity hint the server sent to the client, and which must be filled with the
    corresponding client identity and the derived key:

    \code

    void AuthManager::handlePreSharedKeyAuthentication(SslUnsafePreSharedKeyAuthenticator *authenticator)
    {
        authenticator->setIdentity("My Qt App");

        const QByteArray key = deriveKey(authenticator->identityHint(), passphrase);
        authenticator->setPreSharedKey(key);
    }

    \endcode

    \note PSK ciphersuites are supported only when using OpenSSL 1.0.1 (or
    greater) as the SSL backend.

    \sa QSslSocket
*/

/*!
    Constructs a default SslUnsafePreSharedKeyAuthenticator object.

    The identity hint, the identity and the key will be initialized to empty
    byte arrays; the maximum length for both the identity and the key will be
    initialized to 0.
*/
SslUnsafePreSharedKeyAuthenticator::SslUnsafePreSharedKeyAuthenticator()
    : d(new SslUnsafePreSharedKeyAuthenticatorPrivate)
{
}

/*!
    Destroys the SslUnsafePreSharedKeyAuthenticator object.
*/
SslUnsafePreSharedKeyAuthenticator::~SslUnsafePreSharedKeyAuthenticator()
{
}

/*!
    Constructs a SslUnsafePreSharedKeyAuthenticator object as a copy of \a authenticator.

    \sa operator=()
*/
SslUnsafePreSharedKeyAuthenticator::SslUnsafePreSharedKeyAuthenticator(const SslUnsafePreSharedKeyAuthenticator &authenticator)
    : d(authenticator.d)
{
}

/*!
    Assigns the SslUnsafePreSharedKeyAuthenticator object \a authenticator to this object,
    and returns a reference to the copy.
*/
SslUnsafePreSharedKeyAuthenticator &SslUnsafePreSharedKeyAuthenticator::operator=(const SslUnsafePreSharedKeyAuthenticator &authenticator)
{
    d = authenticator.d;
    return *this;
}

/*!
    \fn SslUnsafePreSharedKeyAuthenticator &SslUnsafePreSharedKeyAuthenticator::operator=(SslUnsafePreSharedKeyAuthenticator &&authenticator)

    Move-assigns the the SslUnsafePreSharedKeyAuthenticator object \a authenticator to this
    object, and returns a reference to the moved instance.
*/

/*!
    \fn void SslUnsafePreSharedKeyAuthenticator::swap(SslUnsafePreSharedKeyAuthenticator &authenticator)

    Swaps the SslUnsafePreSharedKeyAuthenticator object \a authenticator with this object.
    This operation is very fast and never fails.
*/

/*!
    Returns the PSK identity hint as provided by the server. The interpretation
    of this hint is left to the application.
*/
QByteArray SslUnsafePreSharedKeyAuthenticator::identityHint() const
{
    return d->identityHint;
}

/*!
    Sets the PSK client identity (to be advised to the server) to \a identity.

    \note it is possible to set an identity whose length is greater than
    maximumIdentityLength(); in this case, only the first maximumIdentityLength()
    bytes will be actually sent to the server.

    \sa identity(), maximumIdentityLength()
*/
void SslUnsafePreSharedKeyAuthenticator::setIdentity(const QByteArray &identity)
{
    d->identity = identity;
}

/*!
    Returns the PSK client identity.

    \sa setIdentity()
*/
QByteArray SslUnsafePreSharedKeyAuthenticator::identity() const
{
    return d->identity;
}


/*!
    Returns the maximum length, in bytes, of the PSK client identity.

    \note it is possible to set an identity whose length is greater than
    maximumIdentityLength(); in this case, only the first maximumIdentityLength()
    bytes will be actually sent to the server.

    \sa setIdentity()
*/
int SslUnsafePreSharedKeyAuthenticator::maximumIdentityLength() const
{
    return d->maximumIdentityLength;
}


/*!
    Sets the pre shared key to \a preSharedKey.

    \note it is possible to set a key whose length is greater than the
    maximumPreSharedKeyLength(); in this case, only the first
    maximumPreSharedKeyLength() bytes will be actually sent to the server.

    \sa preSharedKey(), maximumPreSharedKeyLength(), QByteArray::fromHex()
*/
void SslUnsafePreSharedKeyAuthenticator::setPreSharedKey(const QByteArray &preSharedKey)
{
    d->preSharedKey = preSharedKey;
}

/*!
    Returns the pre shared key.

    \sa setPreSharedKey()
*/
QByteArray SslUnsafePreSharedKeyAuthenticator::preSharedKey() const
{
    return d->preSharedKey;
}

/*!
    Returns the maximum length, in bytes, of the pre shared key.

    \note it is possible to set a key whose length is greater than the
    maximumPreSharedKeyLength(); in this case, only the first
    maximumPreSharedKeyLength() bytes will be actually sent to the server.

    \sa setPreSharedKey()
*/
int SslUnsafePreSharedKeyAuthenticator::maximumPreSharedKeyLength() const
{
    return d->maximumPreSharedKeyLength;
}

/*!
    \relates SslUnsafePreSharedKeyAuthenticator
    \since 5.5

    Returns true if the authenticator object \a lhs is equal to \a rhs; false
    otherwise.

    Two authenticator objects are equal if and only if they have the same
    identity hint, identity, pre shared key, maximum length for the identity
    and maximum length for the pre shared key.

*/
bool operator==(const SslUnsafePreSharedKeyAuthenticator &lhs, const SslUnsafePreSharedKeyAuthenticator &rhs)
{
    return ((lhs.d == rhs.d) ||
            (lhs.d->identityHint == rhs.d->identityHint &&
             lhs.d->identity == rhs.d->identity &&
             lhs.d->maximumIdentityLength == rhs.d->maximumIdentityLength &&
             lhs.d->preSharedKey == rhs.d->preSharedKey &&
             lhs.d->maximumPreSharedKeyLength == rhs.d->maximumPreSharedKeyLength));
}

/*!
    \fn bool operator!=(const SslUnsafePreSharedKeyAuthenticator &lhs, const SslUnsafePreSharedKeyAuthenticator &rhs)
    \relates SslUnsafePreSharedKeyAuthenticator
    \since 5.5

    Returns true if the authenticator object \a lhs is different than \a rhs;
    false otherwise.

*/
