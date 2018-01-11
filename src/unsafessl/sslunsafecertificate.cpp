
#include <QtNetwork/qtnetworkglobal.h>
#ifndef QT_NO_OPENSSL
#include "sslunsafesocket_openssl_symbols_p.h"
#endif
#ifdef Q_OS_WINRT
#include "SslUnsafeSocket_winrt_p.h"
#endif
#ifdef QT_SECURETRANSPORT
#include "SslUnsafeSocket_mac_p.h"
#endif

//#include "qssl_p.h"
#include "sslunsafecertificate.h"
#include "sslunsafecertificate_p.h"
#include "sslunsafekey_p.h"

#include <QtCore/qdir.h>
#include <QtCore/qdiriterator.h>
#include <QtCore/qfile.h>

/*!
    Constructs a SslUnsafeCertificate by reading \a format encoded data
    from \a device and using the first certificate found. You can
    later call isNull() to see if \a device contained a certificate,
    and if this certificate was loaded successfully.
*/
SslUnsafeCertificate::SslUnsafeCertificate(QIODevice *device, QSsl::EncodingFormat format)
    : d(new SslUnsafeCertificatePrivate)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    if (device && SslUnsafeSocket::supportsSsl())
        d->init(device->readAll(), format);
}

/*!
    Constructs a SslUnsafeCertificate by parsing the \a format encoded
    \a data and using the first available certificate found. You can
    later call isNull() to see if \a data contained a certificate,
    and if this certificate was loaded successfully.
*/
SslUnsafeCertificate::SslUnsafeCertificate(const QByteArray &data, QSsl::EncodingFormat format)
    : d(new SslUnsafeCertificatePrivate)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    if (SslUnsafeSocket::supportsSsl())
        d->init(data, format);
}

/*!
    Constructs an identical copy of \a other.
*/
SslUnsafeCertificate::SslUnsafeCertificate(const SslUnsafeCertificate &other) : d(other.d)
{
}

/*!
    Destroys the SslUnsafeCertificate.
*/
SslUnsafeCertificate::~SslUnsafeCertificate()
{
}

/*!
    Copies the contents of \a other into this certificate, making the two
    certificates identical.
*/
SslUnsafeCertificate &SslUnsafeCertificate::operator=(const SslUnsafeCertificate &other)
{
    d = other.d;
    return *this;
}

/*!
    \fn void SslUnsafeCertificate::swap(SslUnsafeCertificate &other)
    \since 5.0

    Swaps this certificate instance with \a other. This function is
    very fast and never fails.
*/

/*!
    \fn bool SslUnsafeCertificate::operator==(const SslUnsafeCertificate &other) const

    Returns \c true if this certificate is the same as \a other; otherwise
    returns \c false.
*/

/*!
    \fn bool SslUnsafeCertificate::operator!=(const SslUnsafeCertificate &other) const

    Returns \c true if this certificate is not the same as \a other; otherwise
    returns \c false.
*/

/*!
    \fn bool SslUnsafeCertificate::isNull() const

    Returns \c true if this is a null certificate (i.e., a certificate
    with no contents); otherwise returns \c false.

    By default, SslUnsafeCertificate constructs a null certificate.

    \sa clear()
*/

#if QT_DEPRECATED_SINCE(5,0)
/*!
    \fn bool SslUnsafeCertificate::isValid() const
    \obsolete

    To verify a certificate, use verify().
    To check if a certificate is blacklisted, use isBlacklisted().
    To check if a certificate has expired or is not yet valid, compare
    expiryDate() and effectiveDate() with QDateTime::currentDateTime()

    This function checks that the current
    date-time is within the date-time range during which the
    certificate is considered valid, and checks that the
    certificate is not in a blacklist of fraudulent certificates.

    \sa isNull(), verify(), isBlacklisted(), expiryDate(), effectiveDate()
*/
#endif

/*!
    Returns \c true if this certificate is blacklisted; otherwise
    returns \c false.

    \sa isNull()
*/
bool SslUnsafeCertificate::isBlacklisted() const
{
    return SslUnsafeCertificatePrivate::isBlacklisted(*this);
}

/*!
    \fn bool SslUnsafeCertificate::isSelfSigned() const
    \since 5.4

    Returns \c true if this certificate is self signed; otherwise
    returns \c false.

    A certificate is considered self-signed its issuer and subject
    are identical.
*/

/*!
    Clears the contents of this certificate, making it a null
    certificate.

    \sa isNull()
*/
void SslUnsafeCertificate::clear()
{
    if (isNull())
        return;
    d = new SslUnsafeCertificatePrivate;
}

/*!
    \fn QByteArray SslUnsafeCertificate::version() const
    Returns the certificate's version string.
*/

/*!
    \fn QByteArray SslUnsafeCertificate::serialNumber() const

    Returns the certificate's serial number string in hexadecimal format.
*/

/*!
    Returns a cryptographic digest of this certificate. By default,
    an MD5 digest will be generated, but you can also specify a
    custom \a algorithm.
*/
QByteArray SslUnsafeCertificate::digest(QCryptographicHash::Algorithm algorithm) const
{
    return QCryptographicHash::hash(toDer(), algorithm);
}

/*!
  \fn QString SslUnsafeCertificate::issuerInfo(SubjectInfo subject) const

  Returns the issuer information for the \a subject from the
  certificate, or an empty list if there is no information for
  \a subject in the certificate. There can be more than one entry
  of each type.

  \sa subjectInfo()
*/

/*!
  \fn QStringList SslUnsafeCertificate::issuerInfo(const QByteArray &attribute) const

  Returns the issuer information for \a attribute from the certificate,
  or an empty list if there is no information for \a attribute in the
  certificate. There can be more than one entry for an attribute.

  \sa subjectInfo()
*/

/*!
  \fn QString SslUnsafeCertificate::subjectInfo(SubjectInfo subject) const

  Returns the information for the \a subject, or an empty list if
  there is no information for \a subject in the certificate. There
  can be more than one entry of each type.

    \sa issuerInfo()
*/

/*!
    \fn QStringList SslUnsafeCertificate::subjectInfo(const QByteArray &attribute) const

    Returns the subject information for \a attribute, or an empty list if
    there is no information for \a attribute in the certificate. There
    can be more than one entry for an attribute.

    \sa issuerInfo()
*/

/*!
    \fn QList<QByteArray> SslUnsafeCertificate::subjectInfoAttributes() const

    \since 5.0
    Returns a list of the attributes that have values in the subject
    information of this certificate. The information associated
    with a given attribute can be accessed using the subjectInfo()
    method. Note that this list may include the OIDs for any
    elements that are not known by the SSL backend.

    \sa subjectInfo()
*/

/*!
    \fn QList<QByteArray> SslUnsafeCertificate::issuerInfoAttributes() const

    \since 5.0
    Returns a list of the attributes that have values in the issuer
    information of this certificate. The information associated
    with a given attribute can be accessed using the issuerInfo()
    method. Note that this list may include the OIDs for any
    elements that are not known by the SSL backend.

    \sa subjectInfo()
*/

#if QT_DEPRECATED_SINCE(5,0)
/*!
  \fn QMultiMap<QSsl::AlternateNameEntryType, QString> SslUnsafeCertificate::alternateSubjectNames() const
  \obsolete

  Use SslUnsafeCertificate::subjectAlternativeNames();
*/
#endif

/*!
  \fn QMultiMap<QSsl::AlternativeNameEntryType, QString> SslUnsafeCertificate::subjectAlternativeNames() const

  Returns the list of alternative subject names for this
  certificate. The alternative names typically contain host
  names, optionally with wildcards, that are valid for this
  certificate.

  These names are tested against the connected peer's host name, if
  either the subject information for \l CommonName doesn't define a
  valid host name, or the subject info name doesn't match the peer's
  host name.

  \sa subjectInfo()
*/

/*!
  \fn QDateTime SslUnsafeCertificate::effectiveDate() const

  Returns the date-time that the certificate becomes valid, or an
  empty QDateTime if this is a null certificate.

  \sa expiryDate()
*/

/*!
  \fn QDateTime SslUnsafeCertificate::expiryDate() const

  Returns the date-time that the certificate expires, or an empty
  QDateTime if this is a null certificate.

    \sa effectiveDate()
*/

/*!
    \fn Qt::HANDLE SslUnsafeCertificate::handle() const
    Returns a pointer to the native certificate handle, if there is
    one, or a null pointer otherwise.

    You can use this handle, together with the native API, to access
    extended information about the certificate.

    \warning Use of this function has a high probability of being
    non-portable, and its return value may vary from platform to
    platform or change from minor release to minor release.
*/

/*!
    \fn QSslKey SslUnsafeCertificate::publicKey() const
    Returns the certificate subject's public key.
*/

/*!
    \fn QList<SslUnsafeCertificateExtension> SslUnsafeCertificate::extensions() const

    Returns a list containing the X509 extensions of this certificate.
    \since 5.0
 */

/*!
    \fn QByteArray SslUnsafeCertificate::toPem() const

    Returns this certificate converted to a PEM (Base64) encoded
    representation.
*/

/*!
    \fn QByteArray SslUnsafeCertificate::toDer() const

    Returns this certificate converted to a DER (binary) encoded
    representation.
*/

/*!
    \fn QString SslUnsafeCertificate::toText() const

    Returns this certificate converted to a human-readable text
    representation.

    \since 5.0
*/

/*!
    Searches all files in the \a path for certificates encoded in the
    specified \a format and returns them in a list. \a path must be a file
    or a pattern matching one or more files, as specified by \a syntax.

    Example:

    \snippet code/src_network_ssl_SslUnsafeCertificate.cpp 0

    \sa fromData()
*/
QList<SslUnsafeCertificate> SslUnsafeCertificate::fromPath(const QString &path,
                                                 QSsl::EncodingFormat format,
                                                 QRegExp::PatternSyntax syntax)
{
    // $, (,), *, +, ., ?, [, ,], ^, {, | and }.

    // make sure to use the same path separators on Windows and Unix like systems.
    QString sourcePath = QDir::fromNativeSeparators(path);

    // Find the path without the filename
    QString pathPrefix = sourcePath.left(sourcePath.lastIndexOf(QLatin1Char('/')));

    // Check if the path contains any special chars
    int pos = -1;
    if (syntax == QRegExp::Wildcard)
        pos = pathPrefix.indexOf(QRegExp(QLatin1String("[*?[]")));
    else if (syntax != QRegExp::FixedString)
        pos = sourcePath.indexOf(QRegExp(QLatin1String("[\\$\\(\\)\\*\\+\\.\\?\\[\\]\\^\\{\\}\\|]")));
    if (pos != -1) {
        // there was a special char in the path so cut of the part containing that char.
        pathPrefix = pathPrefix.left(pos);
        const int lastIndexOfSlash = pathPrefix.lastIndexOf(QLatin1Char('/'));
        if (lastIndexOfSlash != -1)
            pathPrefix = pathPrefix.left(lastIndexOfSlash);
        else
            pathPrefix.clear();
    } else {
        // Check if the path is a file.
        if (QFileInfo(sourcePath).isFile()) {
            QFile file(sourcePath);
            QIODevice::OpenMode openMode = QIODevice::ReadOnly;
            if (format == QSsl::Pem)
                openMode |= QIODevice::Text;
            if (file.open(openMode))
                return SslUnsafeCertificate::fromData(file.readAll(), format);
            return QList<SslUnsafeCertificate>();
        }
    }

    // Special case - if the prefix ends up being nothing, use "." instead.
    int startIndex = 0;
    if (pathPrefix.isEmpty()) {
        pathPrefix = QLatin1String(".");
        startIndex = 2;
    }

    // The path can be a file or directory.
    QList<SslUnsafeCertificate> certs;
    QRegExp pattern(sourcePath, Qt::CaseSensitive, syntax);
    QDirIterator it(pathPrefix, QDir::Files, QDirIterator::FollowSymlinks | QDirIterator::Subdirectories);
    while (it.hasNext()) {
        QString filePath = startIndex == 0 ? it.next() : it.next().mid(startIndex);
        if (!pattern.exactMatch(filePath))
            continue;

        QFile file(filePath);
        QIODevice::OpenMode openMode = QIODevice::ReadOnly;
        if (format == QSsl::Pem)
            openMode |= QIODevice::Text;
        if (file.open(openMode))
            certs += SslUnsafeCertificate::fromData(file.readAll(), format);
    }
    return certs;
}

/*!
    Searches for and parses all certificates in \a device that are
    encoded in the specified \a format and returns them in a list of
    certificates.

    \sa fromData()
*/
QList<SslUnsafeCertificate> SslUnsafeCertificate::fromDevice(QIODevice *device, QSsl::EncodingFormat format)
{
    if (!device) {
        qWarning() << "SslUnsafeCertificate::fromDevice: cannot read from a null device";
        return QList<SslUnsafeCertificate>();
    }
    return fromData(device->readAll(), format);
}

/*!
    Searches for and parses all certificates in \a data that are
    encoded in the specified \a format and returns them in a list of
    certificates.

    \sa fromDevice()
*/
QList<SslUnsafeCertificate> SslUnsafeCertificate::fromData(const QByteArray &data, QSsl::EncodingFormat format)
{
    return (format == QSsl::Pem)
        ? SslUnsafeCertificatePrivate::certificatesFromPem(data)
        : SslUnsafeCertificatePrivate::certificatesFromDer(data);
}

/*!
    Verifies a certificate chain. The chain to be verified is passed in the
    \a certificateChain parameter. The first certificate in the list should
    be the leaf certificate of the chain to be verified. If \a hostName is
    specified then the certificate is also checked to see if it is valid for
    the specified host name.

    Note that the root (CA) certificate should not be included in the list to be verified,
    this will be looked up automatically either using the CA list specified by
    SslUnsafeSocket::defaultCaCertificates() or, if possible, it will be loaded on demand
    on Unix.

    \since 5.0
 */
#if QT_VERSION >= QT_VERSION_CHECK(6,0,0)
QList<SslUnsafeError> SslUnsafeCertificate::verify(const QList<SslUnsafeCertificate> &certificateChain, const QString &hostName)
#else
QList<SslUnsafeError> SslUnsafeCertificate::verify(QList<SslUnsafeCertificate> certificateChain, const QString &hostName)
#endif
{
    return SslUnsafeSocketBackendPrivate::verify(certificateChain, hostName);
}

/*!
  \since 5.4

  Imports a PKCS#12 (pfx) file from the specified \a device. A PKCS#12
  file is a bundle that can contain a number of certificates and keys.
  This method reads a single \a key, its \a certificate and any
  associated \a caCertificates from the bundle. If a \a passPhrase is
  specified then this will be used to decrypt the bundle. Returns
  \c true if the PKCS#12 file was successfully loaded.

  \note The \a device must be open and ready to be read from.
 */
bool SslUnsafeCertificate::importPkcs12(QIODevice *device,
                                   SslUnsafeKey *key, SslUnsafeCertificate *certificate,
                                   QList<SslUnsafeCertificate> *caCertificates,
                                   const QByteArray &passPhrase)
{
    return SslUnsafeSocketBackendPrivate::importPkcs12(device, key, certificate, caCertificates, passPhrase);
}

// These certificates are known to be fraudulent and were created during the comodo
// compromise. See http://www.comodo.com/Comodo-Fraud-Incident-2011-03-23.html
static const char *const certificate_blacklist[] = {
    0
};
#if 0
    "04:7e:cb:e9:fc:a5:5f:7b:d0:9e:ae:36:e1:0c:ae:1e", "mail.google.com", // Comodo
    "f5:c8:6a:f3:61:62:f1:3a:64:f5:4f:6d:c9:58:7c:06", "www.google.com", // Comodo
    "d7:55:8f:da:f5:f1:10:5b:b2:13:28:2b:70:77:29:a3", "login.yahoo.com", // Comodo
    "39:2a:43:4f:0e:07:df:1f:8a:a3:05:de:34:e0:c2:29", "login.yahoo.com", // Comodo
    "3e:75:ce:d4:6b:69:30:21:21:88:30:ae:86:a8:2a:71", "login.yahoo.com", // Comodo
    "e9:02:8b:95:78:e4:15:dc:1a:71:0a:2b:88:15:44:47", "login.skype.com", // Comodo
    "92:39:d5:34:8f:40:d1:69:5a:74:54:70:e1:f2:3f:43", "addons.mozilla.org", // Comodo
    "b0:b7:13:3e:d0:96:f9:b5:6f:ae:91:c8:74:bd:3a:c0", "login.live.com", // Comodo
    "d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0", "global trustee", // Comodo

    "05:e2:e6:a4:cd:09:ea:54:d6:65:b0:75:fe:22:a2:56", "*.google.com", // leaf certificate issued by DigiNotar
    "0c:76:da:9c:91:0c:4e:2c:9e:fe:15:d0:58:93:3c:4c", "DigiNotar Root CA", // DigiNotar root
    "f1:4a:13:f4:87:2b:56:dc:39:df:84:ca:7a:a1:06:49", "DigiNotar Services CA", // DigiNotar intermediate signed by DigiNotar Root
    "36:16:71:55:43:42:1b:9d:e6:cb:a3:64:41:df:24:38", "DigiNotar Services 1024 CA", // DigiNotar intermediate signed by DigiNotar Root
    "0a:82:bd:1e:14:4e:88:14:d7:5b:1a:55:27:be:bf:3e", "DigiNotar Root CA G2", // other DigiNotar Root CA
    "a4:b6:ce:e3:2e:d3:35:46:26:3c:b3:55:3a:a8:92:21", "CertiID Enterprise Certificate Authority", // DigiNotar intermediate signed by "DigiNotar Root CA G2"
    "5b:d5:60:9c:64:17:68:cf:21:0e:35:fd:fb:05:ad:41", "DigiNotar Qualified CA", // DigiNotar intermediate signed by DigiNotar Root

    "46:9c:2c:b0",                                     "DigiNotar Services 1024 CA", // DigiNotar intermediate cross-signed by Entrust
    "07:27:10:0d",                                     "DigiNotar Cyber CA", // DigiNotar intermediate cross-signed by CyberTrust
    "07:27:0f:f9",                                     "DigiNotar Cyber CA", // DigiNotar intermediate cross-signed by CyberTrust
    "07:27:10:03",                                     "DigiNotar Cyber CA", // DigiNotar intermediate cross-signed by CyberTrust
    "01:31:69:b0",                                     "DigiNotar PKIoverheid CA Overheid en Bedrijven", // DigiNotar intermediate cross-signed by the Dutch government
    "01:31:34:bf",                                     "DigiNotar PKIoverheid CA Organisatie - G2", // DigiNotar intermediate cross-signed by the Dutch government
    "d6:d0:29:77:f1:49:fd:1a:83:f2:b9:ea:94:8c:5c:b4", "DigiNotar Extended Validation CA", // DigiNotar intermediate signed by DigiNotar EV Root
    "1e:7d:7a:53:3d:45:30:41:96:40:0f:71:48:1f:45:04", "DigiNotar Public CA 2025", // DigiNotar intermediate
//    "(has not been seen in the wild so far)", "DigiNotar Public CA - G2", // DigiNotar intermediate
//    "(has not been seen in the wild so far)", "Koninklijke Notariele Beroepsorganisatie CA", // compromised during DigiNotar breach
//    "(has not been seen in the wild so far)", "Stichting TTP Infos CA," // compromised during DigiNotar breach
    "46:9c:2c:af",                                     "DigiNotar Root CA", // DigiNotar intermediate cross-signed by Entrust
    "46:9c:3c:c9",                                     "DigiNotar Root CA", // DigiNotar intermediate cross-signed by Entrust

    "07:27:14:a9",                                     "Digisign Server ID (Enrich)", // (Malaysian) Digicert Sdn. Bhd. cross-signed by Verizon CyberTrust
    "4c:0e:63:6a",                                     "Digisign Server ID - (Enrich)", // (Malaysian) Digicert Sdn. Bhd. cross-signed by Entrust
    "72:03:21:05:c5:0c:08:57:3d:8e:a5:30:4e:fe:e8:b0", "UTN-USERFirst-Hardware", // comodogate test certificate
    "41",                                              "MD5 Collisions Inc. (http://www.phreedom.org/md5)", // http://www.phreedom.org/research/rogue-ca/

    "08:27",                                           "*.EGO.GOV.TR", // Turktrust mis-issued intermediate certificate
    "08:64",                                           "e-islem.kktcmerkezbankasi.org", // Turktrust mis-issued intermediate certificate

    "03:1d:a7",                                        "AC DG Tr\xC3\xA9sor SSL", // intermediate certificate linking back to ANSSI French National Security Agency
    "27:83",                                           "NIC Certifying Authority", // intermediate certificate from NIC India (2007)
    "27:92",                                           "NIC CA 2011", // intermediate certificate from NIC India (2011)
    "27:b1",                                           "NIC CA 2014", // intermediate certificate from NIC India (2014)
    0
};
#endif

bool SslUnsafeCertificatePrivate::isBlacklisted(const SslUnsafeCertificate &certificate)
{
    for (int a = 0; certificate_blacklist[a] != 0; a++) {
        QString blacklistedCommonName = QString::fromUtf8(certificate_blacklist[(a+1)]);
        if (certificate.serialNumber() == certificate_blacklist[a++] &&
            (certificate.subjectInfo(SslUnsafeCertificate::CommonName).contains(blacklistedCommonName) ||
             certificate.issuerInfo(SslUnsafeCertificate::CommonName).contains(blacklistedCommonName)))
            return true;
    }
    return false;
}

QByteArray SslUnsafeCertificatePrivate::subjectInfoToString(SslUnsafeCertificate::SubjectInfo info)
{
    QByteArray str;
    switch (info) {
    case SslUnsafeCertificate::Organization: str = QByteArray("O"); break;
    case SslUnsafeCertificate::CommonName: str = QByteArray("CN"); break;
    case SslUnsafeCertificate::LocalityName: str = QByteArray("L"); break;
    case SslUnsafeCertificate::OrganizationalUnitName: str = QByteArray("OU"); break;
    case SslUnsafeCertificate::CountryName: str = QByteArray("C"); break;
    case SslUnsafeCertificate::StateOrProvinceName: str = QByteArray("ST"); break;
    case SslUnsafeCertificate::DistinguishedNameQualifier: str = QByteArray("dnQualifier"); break;
    case SslUnsafeCertificate::SerialNumber: str = QByteArray("serialNumber"); break;
    case SslUnsafeCertificate::EmailAddress: str = QByteArray("emailAddress"); break;
    }
    return str;
}

/*!
    \fn uint qHash(const SslUnsafeCertificate &key, uint seed)

    Returns the hash value for the \a key, using \a seed to seed the calculation.
    \since 5.4
    \relates QHash
*/

#ifndef QT_NO_DEBUG_STREAM
QDebug operator<<(QDebug debug, const SslUnsafeCertificate &certificate)
{
    QDebugStateSaver saver(debug);
    debug.resetFormat().nospace();
    debug << "SslUnsafeCertificate("
          << certificate.version()
          << ", " << certificate.serialNumber()
          << ", " << certificate.digest().toBase64()
          << ", " << certificate.issuerInfo(SslUnsafeCertificate::Organization)
          << ", " << certificate.subjectInfo(SslUnsafeCertificate::Organization)
          << ", " << certificate.subjectAlternativeNames()
#ifndef QT_NO_DATESTRING
          << ", " << certificate.effectiveDate()
          << ", " << certificate.expiryDate()
#endif
          << ')';
    return debug;
}
QDebug operator<<(QDebug debug, SslUnsafeCertificate::SubjectInfo info)
{
    switch (info) {
    case SslUnsafeCertificate::Organization: debug << "Organization"; break;
    case SslUnsafeCertificate::CommonName: debug << "CommonName"; break;
    case SslUnsafeCertificate::CountryName: debug << "CountryName"; break;
    case SslUnsafeCertificate::LocalityName: debug << "LocalityName"; break;
    case SslUnsafeCertificate::OrganizationalUnitName: debug << "OrganizationalUnitName"; break;
    case SslUnsafeCertificate::StateOrProvinceName: debug << "StateOrProvinceName"; break;
    case SslUnsafeCertificate::DistinguishedNameQualifier: debug << "DistinguishedNameQualifier"; break;
    case SslUnsafeCertificate::SerialNumber: debug << "SerialNumber"; break;
    case SslUnsafeCertificate::EmailAddress: debug << "EmailAddress"; break;
    }
    return debug;
}
#endif
