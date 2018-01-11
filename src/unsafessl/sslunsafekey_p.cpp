#include "sslunsafekey.h"
#include "sslunsafekey_p.h"
#ifndef QT_NO_OPENSSL
#include "sslunsafesocket_openssl_symbols_p.h"
#endif
#include "sslunsafesocket.h"
#include "sslunsafesocket_p.h"

#include <QtCore/qatomic.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qiodevice.h>
#ifndef QT_NO_DEBUG_STREAM
#include <QtCore/qdebug.h>
#endif

SslUnsafeKey::SslUnsafeKey()
    : d(new SslUnsafeKeyPrivate)
{
}

/*!
    \internal
*/
QByteArray SslUnsafeKeyPrivate::pemHeader() const
{
    if (type == QSsl::PublicKey)
        return QByteArrayLiteral("-----BEGIN PUBLIC KEY-----");
    else if (algorithm == QSsl::Rsa)
        return QByteArrayLiteral("-----BEGIN RSA PRIVATE KEY-----");
    else if (algorithm == QSsl::Dsa)
        return QByteArrayLiteral("-----BEGIN DSA PRIVATE KEY-----");
    else if (algorithm == QSsl::Ec)
        return QByteArrayLiteral("-----BEGIN EC PRIVATE KEY-----");

    Q_UNREACHABLE();
    return QByteArray();
}

/*!
    \internal
*/
QByteArray SslUnsafeKeyPrivate::pemFooter() const
{
    if (type == QSsl::PublicKey)
        return QByteArrayLiteral("-----END PUBLIC KEY-----");
    else if (algorithm == QSsl::Rsa)
        return QByteArrayLiteral("-----END RSA PRIVATE KEY-----");
    else if (algorithm == QSsl::Dsa)
        return QByteArrayLiteral("-----END DSA PRIVATE KEY-----");
    else if (algorithm == QSsl::Ec)
        return QByteArrayLiteral("-----END EC PRIVATE KEY-----");

    Q_UNREACHABLE();
    return QByteArray();
}

/*!
    \internal

    Returns a DER key formatted as PEM.
*/
QByteArray SslUnsafeKeyPrivate::pemFromDer(const QByteArray &der, const QMap<QByteArray, QByteArray> &headers) const
{
    QByteArray pem(der.toBase64());

    const int lineWidth = 64; // RFC 1421
    const int newLines = pem.size() / lineWidth;
    const bool rem = pem.size() % lineWidth;

    // ### optimize
    for (int i = 0; i < newLines; ++i)
        pem.insert((i + 1) * lineWidth + i, '\n');
    if (rem)
        pem.append('\n'); // ###

    QByteArray extra;
    if (!headers.isEmpty()) {
        QMap<QByteArray, QByteArray>::const_iterator it = headers.constEnd();
        do {
            --it;
            extra += it.key() + ": " + it.value() + '\n';
        } while (it != headers.constBegin());
        extra += '\n';
    }
    pem.prepend(pemHeader() + '\n' + extra);
    pem.append(pemFooter() + '\n');

    return pem;
}

/*!
    \internal

    Returns a PEM key formatted as DER.
*/
QByteArray SslUnsafeKeyPrivate::derFromPem(const QByteArray &pem, QMap<QByteArray, QByteArray> *headers) const
{
    const QByteArray header = pemHeader();
    const QByteArray footer = pemFooter();

    QByteArray der(pem);

    const int headerIndex = der.indexOf(header);
    const int footerIndex = der.indexOf(footer);
    if (headerIndex == -1 || footerIndex == -1)
        return QByteArray();

    der = der.mid(headerIndex + header.size(), footerIndex - (headerIndex + header.size()));

    if (der.contains("Proc-Type:")) {
        // taken from QHttpNetworkReplyPrivate::parseHeader
        int i = 0;
        while (i < der.count()) {
            int j = der.indexOf(':', i); // field-name
            if (j == -1)
                break;
            const QByteArray field = der.mid(i, j - i).trimmed();
            j++;
            // any number of LWS is allowed before and after the value
            QByteArray value;
            do {
                i = der.indexOf('\n', j);
                if (i == -1)
                    break;
                if (!value.isEmpty())
                    value += ' ';
                // check if we have CRLF or only LF
                bool hasCR = (i && der[i-1] == '\r');
                int length = i -(hasCR ? 1: 0) - j;
                value += der.mid(j, length).trimmed();
                j = ++i;
            } while (i < der.count() && (der.at(i) == ' ' || der.at(i) == '\t'));
            if (i == -1)
                break; // something is wrong

            headers->insert(field, value);
        }
        der = der.mid(i);
    }

    return QByteArray::fromBase64(der); // ignores newlines
}

/*!
    Constructs a SslUnsafeKey by decoding the string in the byte array
    \a encoded using a specified \a algorithm and \a encoding format.
    \a type specifies whether the key is public or private.

    If the key is encoded as PEM and encrypted, \a passPhrase is used
    to decrypt it.

    After construction, use isNull() to check if \a encoded contained
    a valid key.
*/
SslUnsafeKey::SslUnsafeKey(const QByteArray &encoded, QSsl::KeyAlgorithm algorithm,
                 QSsl::EncodingFormat encoding, QSsl::KeyType type, const QByteArray &passPhrase)
    : d(new SslUnsafeKeyPrivate)
{
    d->type = type;
    d->algorithm = algorithm;
    if (encoding == QSsl::Der)
        d->decodeDer(encoded);
    else
        d->decodePem(encoded, passPhrase);
}

/*!
    Constructs a SslUnsafeKey by reading and decoding data from a
    \a device using a specified \a algorithm and \a encoding format.
    \a type specifies whether the key is public or private.

    If the key is encoded as PEM and encrypted, \a passPhrase is used
    to decrypt it.

    After construction, use isNull() to check if \a device provided
    a valid key.
*/
SslUnsafeKey::SslUnsafeKey(QIODevice *device, QSsl::KeyAlgorithm algorithm, QSsl::EncodingFormat encoding,
                 QSsl::KeyType type, const QByteArray &passPhrase)
    : d(new SslUnsafeKeyPrivate)
{
    QByteArray encoded;
    if (device)
        encoded = device->readAll();
    d->type = type;
    d->algorithm = algorithm;
    if (encoding == QSsl::Der)
        d->decodeDer(encoded);
    else
        d->decodePem(encoded, passPhrase);
}

/*!
    \since 5.0
    Constructs a SslUnsafeKey from a valid native key \a handle.
    \a type specifies whether the key is public or private.

    SslUnsafeKey will take ownership for this key and you must not
    free the key using the native library.
*/
SslUnsafeKey::SslUnsafeKey(Qt::HANDLE handle, QSsl::KeyType type)
    : d(new SslUnsafeKeyPrivate)
{
#ifndef QT_NO_OPENSSL
    EVP_PKEY *evpKey = reinterpret_cast<EVP_PKEY *>(handle);
    if (!evpKey || !d->fromEVP_PKEY(evpKey)) {
        d->opaque = evpKey;
        d->algorithm = QSsl::Opaque;
    } else {
        uq_EVP_PKEY_free(evpKey);
    }
#else
    d->opaque = handle;
    d->algorithm = QSsl::Opaque;
#endif
    d->type = type;
    d->isNull = !d->opaque;
}

/*!
    Constructs an identical copy of \a other.
*/
SslUnsafeKey::SslUnsafeKey(const SslUnsafeKey &other) : d(other.d)
{
}

/*!
    Destroys the SslUnsafeKey object.
*/
SslUnsafeKey::~SslUnsafeKey()
{
}

/*!
    Copies the contents of \a other into this key, making the two keys
    identical.

    Returns a reference to this SslUnsafeKey.
*/
SslUnsafeKey &SslUnsafeKey::operator=(const SslUnsafeKey &other)
{
    d = other.d;
    return *this;
}

/*!
    \fn void SslUnsafeKey::swap(SslUnsafeKey &other)
    \since 5.0

    Swaps this ssl key with \a other. This function is very fast and
    never fails.
*/

/*!
    Returns \c true if this is a null key; otherwise false.

    \sa clear()
*/
bool SslUnsafeKey::isNull() const
{
    return d->isNull;
}

/*!
    Clears the contents of this key, making it a null key.

    \sa isNull()
*/
void SslUnsafeKey::clear()
{
    d = new SslUnsafeKeyPrivate;
}

/*!
    Returns the length of the key in bits, or -1 if the key is null.
*/
int SslUnsafeKey::length() const
{
    return d->length();
}

/*!
    Returns the type of the key (i.e., PublicKey or PrivateKey).
*/
QSsl::KeyType SslUnsafeKey::type() const
{
    return d->type;
}

/*!
    Returns the key algorithm.
*/
QSsl::KeyAlgorithm SslUnsafeKey::algorithm() const
{
    return d->algorithm;
}

/*!
  Returns the key in DER encoding.

  The \a passPhrase argument should be omitted as DER cannot be
  encrypted. It will be removed in a future version of Qt.
*/
QByteArray SslUnsafeKey::toDer(const QByteArray &passPhrase) const
{
    if (d->isNull || d->algorithm == QSsl::Opaque)
        return QByteArray();

    // Encrypted DER is nonsense, see QTBUG-41038.
    if (d->type == QSsl::PrivateKey && !passPhrase.isEmpty())
        return QByteArray();

#ifndef QT_NO_OPENSSL
    QMap<QByteArray, QByteArray> headers;
    return d->derFromPem(toPem(passPhrase), &headers);
#else
    return d->derData;
#endif
}

/*!
  Returns the key in PEM encoding. The result is encrypted with
  \a passPhrase if the key is a private key and \a passPhrase is
  non-empty.
*/
QByteArray SslUnsafeKey::toPem(const QByteArray &passPhrase) const
{
    return d->toPem(passPhrase);
}

/*!
    Returns a pointer to the native key handle, if it is available;
    otherwise a null pointer is returned.

    You can use this handle together with the native API to access
    extended information about the key.

    \warning Use of this function has a high probability of being
    non-portable, and its return value may vary across platforms, and
    between minor Qt releases.
*/
Qt::HANDLE SslUnsafeKey::handle() const
{
    return d->handle();
}

/*!
    Returns \c true if this key is equal to \a other; otherwise returns \c false.
*/
bool SslUnsafeKey::operator==(const SslUnsafeKey &other) const
{
    if (isNull())
        return other.isNull();
    if (other.isNull())
        return isNull();
    if (algorithm() != other.algorithm())
        return false;
    if (type() != other.type())
        return false;
    if (length() != other.length())
        return false;
    if (algorithm() == QSsl::Opaque)
        return handle() == other.handle();
    return toDer() == other.toDer();
}

/*! \fn bool SslUnsafeKey::operator!=(const SslUnsafeKey &other) const

  Returns \c true if this key is not equal to key \a other; otherwise
  returns \c false.
*/

#ifndef QT_NO_DEBUG_STREAM
QDebug operator<<(QDebug debug, const SslUnsafeKey &key)
{
    QDebugStateSaver saver(debug);
    debug.resetFormat().nospace();
    debug << "SslUnsafeKey("
          << (key.type() == QSsl::PublicKey ? "PublicKey" : "PrivateKey")
          << ", " << (key.algorithm() == QSsl::Opaque ? "OPAQUE" :
                      (key.algorithm() == QSsl::Rsa ? "RSA" : ((key.algorithm() == QSsl::Dsa) ? "DSA" : "EC")))
          << ", " << key.length()
          << ')';
    return debug;
}
#endif
