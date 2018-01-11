
#include "sslunsafediffiehellmanparameters.h"
#include "sslunsafediffiehellmanparameters_p.h"
#include "sslunsafesocket.h"
#include "sslunsafesocket_p.h"

#include <QtCore/qcoreapplication.h>
#include <QtCore/qatomic.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qbytearraymatcher.h>
#include <QtCore/qiodevice.h>
#include <QtCore/qdebug.h>

// The 1024-bit MODP group from RFC 2459 (Second Oakley Group)
const char *qssl_dhparams_default_base64 =
    "MIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJR"
    "Sgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL"
    "/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7OZTgf//////////AgEC";

/*!
    Returns the default SslUnsafeDiffieHellmanParameters used by QSslSocket.

    This is currently the 1024-bit MODP group from RFC 2459, also
    known as the Second Oakley Group.
*/
SslUnsafeDiffieHellmanParameters SslUnsafeDiffieHellmanParameters::defaultParameters()
{
    SslUnsafeDiffieHellmanParameters def;
    def.d->derData = QByteArray::fromBase64(QByteArray(qssl_dhparams_default_base64));
    return def;
}

/*!
    Constructs an empty SslUnsafeDiffieHellmanParameters instance.

    If an empty SslUnsafeDiffieHellmanParameters instance is set on a
    QSslConfiguration object, Diffie-Hellman negotiation will
    be disabled.

    \sa isValid()
    \sa QSslConfiguration
*/
SslUnsafeDiffieHellmanParameters::SslUnsafeDiffieHellmanParameters()
    : d(new SslUnsafeDiffieHellmanParametersPrivate)
{
    d->ref.ref();
}

/*!
    Constructs a SslUnsafeDiffieHellmanParameters object using
    the byte array \a encoded in either PEM or DER form as specified by \a encoding.

    Use the isValid() method on the returned object to
    check whether the Diffie-Hellman parameters were valid and
    loaded correctly.

    \sa isValid()
    \sa QSslConfiguration
*/
SslUnsafeDiffieHellmanParameters SslUnsafeDiffieHellmanParameters::fromEncoded(const QByteArray &encoded, QSsl::EncodingFormat encoding)
{
    SslUnsafeDiffieHellmanParameters result;
    switch (encoding) {
    case QSsl::Der:
        result.d->decodeDer(encoded);
        break;
    case QSsl::Pem:
        result.d->decodePem(encoded);
        break;
    }
    return result;
}

/*!
    Constructs a SslUnsafeDiffieHellmanParameters object by
    reading from \a device in either PEM or DER form as specified by \a encoding.

    Use the isValid() method on the returned object
    to check whether the Diffie-Hellman parameters were valid
    and loaded correctly.

    In particular, if \a device is \c nullptr or not open for reading, an invalid
    object will be returned.

    \sa isValid()
    \sa QSslConfiguration
*/
SslUnsafeDiffieHellmanParameters SslUnsafeDiffieHellmanParameters::fromEncoded(QIODevice *device, QSsl::EncodingFormat encoding)
{
    if (device)
        return fromEncoded(device->readAll(), encoding);
    else
        return SslUnsafeDiffieHellmanParameters();
}

/*!
    Constructs an identical copy of \a other.
*/
SslUnsafeDiffieHellmanParameters::SslUnsafeDiffieHellmanParameters(const SslUnsafeDiffieHellmanParameters &other)
    : d(other.d)
{
    if (d)
        d->ref.ref();
}

/*!
    \fn SslUnsafeDiffieHellmanParameters(SslUnsafeDiffieHellmanParameters &&other)

    Move-constructs from \a other.

    \note The moved-from object \a other is placed in a partially-formed state, in which
    the only valid operations are destruction and assignment of a new value.
*/

/*!
    Destroys the SslUnsafeDiffieHellmanParameters object.
*/
SslUnsafeDiffieHellmanParameters::~SslUnsafeDiffieHellmanParameters()
{
    if (d && !d->ref.deref())
        delete d;
}

/*!
    Copies the contents of \a other into this SslUnsafeDiffieHellmanParameters, making the two SslUnsafeDiffieHellmanParameters
    identical.

    Returns a reference to this SslUnsafeDiffieHellmanParameters.
*/
SslUnsafeDiffieHellmanParameters &SslUnsafeDiffieHellmanParameters::operator=(const SslUnsafeDiffieHellmanParameters &other)
{
    SslUnsafeDiffieHellmanParameters copy(other);
    swap(copy);
    return *this;
}

/*!
    \fn SslUnsafeDiffieHellmanParameters &SslUnsafeDiffieHellmanParameters::operator=(SslUnsafeDiffieHellmanParameters &&other)

    Move-assigns \a other to this SslUnsafeDiffieHellmanParameters instance.

    \note The moved-from object \a other is placed in a partially-formed state, in which
    the only valid operations are destruction and assignment of a new value.
*/

/*!
    \fn void SslUnsafeDiffieHellmanParameters::swap(SslUnsafeDiffieHellmanParameters &other)

    Swaps this SslUnsafeDiffieHellmanParameters with \a other. This function is very fast and
    never fails.
*/

/*!
    Returns \c true if this is a an empty SslUnsafeDiffieHellmanParameters instance.

    Setting an empty SslUnsafeDiffieHellmanParameters instance on a QSslSocket-based
    server will disable Diffie-Hellman key exchange.
*/
bool SslUnsafeDiffieHellmanParameters::isEmpty() const Q_DECL_NOTHROW
{
    return d->derData.isNull() && d->error == SslUnsafeDiffieHellmanParameters::NoError;
}

/*!
    Returns \c true if this is a valid SslUnsafeDiffieHellmanParameters; otherwise false.

    This method should be used after constructing a SslUnsafeDiffieHellmanParameters
    object to determine its validity.

    If a SslUnsafeDiffieHellmanParameters object is not valid, you can use the error()
    method to determine what error prevented the object from being constructed.

    \sa error()
*/
bool SslUnsafeDiffieHellmanParameters::isValid() const Q_DECL_NOTHROW
{
    return d->error == SslUnsafeDiffieHellmanParameters::NoError;
}

/*!
    \enum SslUnsafeDiffieHellmanParameters::Error

    Describes a SslUnsafeDiffieHellmanParameters error.

    \value NoError               No error occurred.

    \value InvalidInputDataError The given input data could not be used to
                                 construct a SslUnsafeDiffieHellmanParameters
                                 object.

    \value UnsafeParametersError The Diffie-Hellman parameters are unsafe
                                 and should not be used.
*/

/*!
    Returns the error that caused the SslUnsafeDiffieHellmanParameters object
    to be invalid.
*/
SslUnsafeDiffieHellmanParameters::Error SslUnsafeDiffieHellmanParameters::error() const Q_DECL_NOTHROW
{
    return d->error;
}

/*!
    Returns a human-readable description of the error that caused the
    SslUnsafeDiffieHellmanParameters object to be invalid.
*/
QString SslUnsafeDiffieHellmanParameters::errorString() const Q_DECL_NOTHROW
{
    switch (d->error) {
    case SslUnsafeDiffieHellmanParameters::NoError:
        return QCoreApplication::translate("QSslDiffieHellmanParameter", "No error");
    case SslUnsafeDiffieHellmanParameters::InvalidInputDataError:
        return QCoreApplication::translate("QSslDiffieHellmanParameter", "Invalid input data");
    case SslUnsafeDiffieHellmanParameters::UnsafeParametersError:
        return QCoreApplication::translate("QSslDiffieHellmanParameter", "The given Diffie-Hellman parameters are deemed unsafe");
    }

    Q_UNREACHABLE();
    return QString();
}

/*!
    \since 5.8
    \relates SslUnsafeDiffieHellmanParameters

    Returns \c true if \a lhs is equal to \a rhs; otherwise returns \c false.
*/
bool operator==(const SslUnsafeDiffieHellmanParameters &lhs, const SslUnsafeDiffieHellmanParameters &rhs) Q_DECL_NOTHROW
{
    return lhs.d->derData == rhs.d->derData;
}

#ifndef QT_NO_DEBUG_STREAM
/*!
    \since 5.8
    \relates SslUnsafeDiffieHellmanParameters

    Writes the set of Diffie-Hellman parameters in \a dhparam into the debug object \a debug for
    debugging purposes.

    The Diffie-Hellman parameters will be represented in Base64-encoded DER form.

    \sa {Debugging Techniques}
*/
QDebug operator<<(QDebug debug, const SslUnsafeDiffieHellmanParameters &dhparam)
{
    QDebugStateSaver saver(debug);
    debug.resetFormat().nospace();
    debug << "SslUnsafeDiffieHellmanParameters(" << dhparam.d->derData.toBase64() << ')';
    return debug;
}
#endif

/*!
    \since 5.8
    \relates SslUnsafeDiffieHellmanParameters

    Returns an hash value for \a dhparam, using \a seed to seed
    the calculation.
*/
uint qHash(const SslUnsafeDiffieHellmanParameters &dhparam, uint seed) Q_DECL_NOTHROW
{
    return qHash(dhparam.d->derData, seed);
}
