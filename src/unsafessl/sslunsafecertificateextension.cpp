
#include "sslunsafecertificateextension.h"
#include "sslunsafecertificateextension_p.h"

/*!
    Constructs a SslUnsafeCertificateExtension.
 */
SslUnsafeCertificateExtension::SslUnsafeCertificateExtension()
    : d(new SslUnsafeCertificateExtensionPrivate)
{
}

/*!
    Constructs a copy of \a other.
 */
SslUnsafeCertificateExtension::SslUnsafeCertificateExtension(const SslUnsafeCertificateExtension &other)
    : d(other.d)
{
}

/*!
    Destroys the extension.
 */
SslUnsafeCertificateExtension::~SslUnsafeCertificateExtension()
{
}

/*!
    Assigns \a other to this extension and returns a reference to this extension.
 */
SslUnsafeCertificateExtension &SslUnsafeCertificateExtension::operator=(const SslUnsafeCertificateExtension &other)
{
    d = other.d;
    return *this;
}

/*!
    \fn void SslUnsafeCertificateExtension::swap(SslUnsafeCertificateExtension &other)

    Swaps this certificate extension instance with \a other. This
    function is very fast and never fails.
*/

/*!
    Returns the ASN.1 OID of this extension.
 */
QString SslUnsafeCertificateExtension::oid() const
{
    return d->oid;
}

/*!
    Returns the name of the extension. If no name is known for the
    extension then the OID will be returned.
 */
QString SslUnsafeCertificateExtension::name() const
{
    return d->name;
}

/*!
    Returns the value of the extension. The structure of the value
    returned depends on the extension type.
 */
QVariant SslUnsafeCertificateExtension::value() const
{
    return d->value;
}

/*!
    Returns the criticality of the extension.
 */
bool SslUnsafeCertificateExtension::isCritical() const
{
    return d->critical;
}

/*!
    Returns the true if this extension is supported. In this case,
    supported simply means that the structure of the QVariant returned
    by the value() accessor will remain unchanged between versions.
    Unsupported extensions can be freely used, however there is no
    guarantee that the returned data will have the same structure
    between versions.
 */
bool SslUnsafeCertificateExtension::isSupported() const
{
    return d->supported;
}
