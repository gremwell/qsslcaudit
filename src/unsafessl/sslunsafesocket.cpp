#include "sslunsafesocket.h"

//#define SSLUNSAFESOCKET_DEBUG

//#include "qssl_p.h"
//#include "SslUnsafeSocket.h"

#include "sslunsafesocket_openssl_p.h"

#include "sslunsafeconfiguration_p.h"

#include <QtCore/qdebug.h>
#include <QtCore/qdir.h>
#include <QtCore/qmutex.h>
#include <QtCore/qurl.h>
#include <QtCore/qelapsedtimer.h>
#include <QtNetwork/qhostaddress.h>
#include <QtNetwork/qhostinfo.h>

#include <QNetworkProxy>


class SslUnsafeSocketGlobalData
{
public:
    SslUnsafeSocketGlobalData() : config(new SslUnsafeConfigurationPrivate) {}

    QMutex mutex;
    QList<SslUnsafeCipher> supportedCiphers;
    QVector<SslUnsafeEllipticCurve> supportedEllipticCurves;
    QExplicitlySharedDataPointer<SslUnsafeConfigurationPrivate> config;
};
Q_GLOBAL_STATIC(SslUnsafeSocketGlobalData, globalData)


//SslUnsafeSocket::SslUnsafeSocket(QObject *parent)
//    : QTcpSocket(*new SslUnsafeSocketBackendPrivate, parent)
SslUnsafeSocket::SslUnsafeSocket(QObject *parent)
    : QTcpSocket(parent),
      d_ptr(new SslUnsafeSocketBackendPrivate)
{
    Q_D(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::SslUnsafeSocket(" << parent << "), this =" << (void *)this;
#endif
    d->q_ptr = this;
    d->init();
}

SslUnsafeSocket::~SslUnsafeSocket()
{
    Q_D(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::~SslUnsafeSocket(), this =" << (void *)this;
#endif
    delete d->plainSocket;
    d->plainSocket = 0;
}

void SslUnsafeSocket::connectToHostEncrypted(const QString &hostName, quint16 port, OpenMode mode, NetworkLayerProtocol protocol)
{
    Q_D(SslUnsafeSocket);
    if (d->state() == ConnectedState || d->state() == ConnectingState) {
        qWarning() << "SslUnsafeSocket::connectToHostEncrypted() called when already connecting/connected";
        return;
    }

    d->init();
    d->autoStartHandshake = true;
    d->initialized = true;

    // Note: When connecting to localhost, some platforms (e.g., HP-UX and some BSDs)
    // establish the connection immediately (i.e., first attempt).
    connectToHost(hostName, port, mode, protocol);
}

void SslUnsafeSocket::connectToHostEncrypted(const QString &hostName, quint16 port,
                                        const QString &sslPeerName, OpenMode mode,
                                        NetworkLayerProtocol protocol)
{
    Q_D(SslUnsafeSocket);
    if (d->state() == ConnectedState || d->state() == ConnectingState) {
        qWarning() << "SslUnsafeSocket::connectToHostEncrypted() called when already connecting/connected";
        return;
    }

    d->init();
    d->autoStartHandshake = true;
    d->initialized = true;
    d->verificationPeerName = sslPeerName;

    // Note: When connecting to localhost, some platforms (e.g., HP-UX and some BSDs)
    // establish the connection immediately (i.e., first attempt).
    connectToHost(hostName, port, mode, protocol);
}

bool SslUnsafeSocket::setSocketDescriptor(qintptr socketDescriptor, SocketState state, OpenMode openMode)
{
    Q_D(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::setSocketDescriptor(" << socketDescriptor << ','
             << state << ',' << openMode << ')';
#endif
    if (!d->plainSocket)
        d->createPlainSocket(openMode);
    bool retVal = d->plainSocket->setSocketDescriptor(socketDescriptor, state, openMode);
    d->cachedSocketDescriptor = d->plainSocket->socketDescriptor();
    d->setError(d->plainSocket->error(), d->plainSocket->errorString());
    d->setSocketState(state);
    setOpenMode(openMode);
    setLocalPort(d->plainSocket->localPort());
    setLocalAddress(d->plainSocket->localAddress());
    setPeerPort(d->plainSocket->peerPort());
    setPeerAddress(d->plainSocket->peerAddress());
    setPeerName(d->plainSocket->peerName());
    d->readChannelCount = d->plainSocket->readChannelCount();
    d->writeChannelCount = d->plainSocket->writeChannelCount();
    return retVal;
}

/*!
    \since 4.6
    Sets the given \a option to the value described by \a value.

    \sa socketOption()
*/
void SslUnsafeSocket::setSocketOption(QAbstractSocket::SocketOption option, const QVariant &value)
{
    Q_D(SslUnsafeSocket);
    if (d->plainSocket)
        d->plainSocket->setSocketOption(option, value);
}

/*!
    \since 4.6
    Returns the value of the \a option option.

    \sa setSocketOption()
*/
QVariant SslUnsafeSocket::socketOption(QAbstractSocket::SocketOption option)
{
    Q_D(SslUnsafeSocket);
    if (d->plainSocket)
        return d->plainSocket->socketOption(option);
    else
        return QVariant();
}

/*!
    Returns the current mode for the socket; either UnencryptedMode, where
    SslUnsafeSocket behaves identially to QTcpSocket, or one of SslClientMode or
    SslServerMode, where the client is either negotiating or in encrypted
    mode.

    When the mode changes, SslUnsafeSocket emits modeChanged()

    \sa SslMode
*/
SslUnsafeSocket::SslMode SslUnsafeSocket::mode() const
{
    Q_D(const SslUnsafeSocket);
    return d->mode;
}

/*!
    Returns \c true if the socket is encrypted; otherwise, false is returned.

    An encrypted socket encrypts all data that is written by calling write()
    or putChar() before the data is written to the network, and decrypts all
    incoming data as the data is received from the network, before you call
    read(), readLine() or getChar().

    SslUnsafeSocket emits encrypted() when it enters encrypted mode.

    You can call sessionCipher() to find which cryptographic cipher is used to
    encrypt and decrypt your data.

    \sa mode()
*/
bool SslUnsafeSocket::isEncrypted() const
{
    Q_D(const SslUnsafeSocket);
    return d->connectionEncrypted;
}

/*!
    Returns the socket's SSL protocol. By default, \l QSsl::SecureProtocols is used.

    \sa setProtocol()
*/
QSsl::SslProtocol SslUnsafeSocket::protocol() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.protocol;
}

/*!
    Sets the socket's SSL protocol to \a protocol. This will affect the next
    initiated handshake; calling this function on an already-encrypted socket
    will not affect the socket's protocol.
*/
void SslUnsafeSocket::setProtocol(QSsl::SslProtocol protocol)
{
    Q_D(SslUnsafeSocket);
    d->configuration.protocol = protocol;
}

/*!
    \since 4.4

    Returns the socket's verify mode. This mode decides whether
    SslUnsafeSocket should request a certificate from the peer (i.e., the client
    requests a certificate from the server, or a server requesting a
    certificate from the client), and whether it should require that this
    certificate is valid.

    The default mode is AutoVerifyPeer, which tells SslUnsafeSocket to use
    VerifyPeer for clients and QueryPeer for servers.

    \sa setPeerVerifyMode(), peerVerifyDepth(), mode()
*/
SslUnsafeSocket::PeerVerifyMode SslUnsafeSocket::peerVerifyMode() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.peerVerifyMode;
}

/*!
    \since 4.4

    Sets the socket's verify mode to \a mode. This mode decides whether
    SslUnsafeSocket should request a certificate from the peer (i.e., the client
    requests a certificate from the server, or a server requesting a
    certificate from the client), and whether it should require that this
    certificate is valid.

    The default mode is AutoVerifyPeer, which tells SslUnsafeSocket to use
    VerifyPeer for clients and QueryPeer for servers.

    Setting this mode after encryption has started has no effect on the
    current connection.

    \sa peerVerifyMode(), setPeerVerifyDepth(), mode()
*/
void SslUnsafeSocket::setPeerVerifyMode(SslUnsafeSocket::PeerVerifyMode mode)
{
    Q_D(SslUnsafeSocket);
    d->configuration.peerVerifyMode = mode;
}

/*!
    \since 4.4

    Returns the maximum number of certificates in the peer's certificate chain
    to be checked during the SSL handshake phase, or 0 (the default) if no
    maximum depth has been set, indicating that the whole certificate chain
    should be checked.

    The certificates are checked in issuing order, starting with the peer's
    own certificate, then its issuer's certificate, and so on.

    \sa setPeerVerifyDepth(), peerVerifyMode()
*/
int SslUnsafeSocket::peerVerifyDepth() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.peerVerifyDepth;
}

/*!
    \since 4.4

    Sets the maximum number of certificates in the peer's certificate chain to
    be checked during the SSL handshake phase, to \a depth. Setting a depth of
    0 means that no maximum depth is set, indicating that the whole
    certificate chain should be checked.

    The certificates are checked in issuing order, starting with the peer's
    own certificate, then its issuer's certificate, and so on.

    \sa peerVerifyDepth(), setPeerVerifyMode()
*/
void SslUnsafeSocket::setPeerVerifyDepth(int depth)
{
    Q_D(SslUnsafeSocket);
    if (depth < 0) {
        qWarning() << "SslUnsafeSocket::setPeerVerifyDepth: cannot set negative depth of " << depth;
        return;
    }
    d->configuration.peerVerifyDepth = depth;
}

/*!
    \since 4.8

    Returns the different hostname for the certificate validation, as set by
    setPeerVerifyName or by connectToHostEncrypted.

    \sa setPeerVerifyName(), connectToHostEncrypted()
*/
QString SslUnsafeSocket::peerVerifyName() const
{
    Q_D(const SslUnsafeSocket);
    return d->verificationPeerName;
}

/*!
    \since 4.8

    Sets a different host name, given by \a hostName, for the certificate
    validation instead of the one used for the TCP connection.

    \sa connectToHostEncrypted()
*/
void SslUnsafeSocket::setPeerVerifyName(const QString &hostName)
{
    Q_D(SslUnsafeSocket);
    d->verificationPeerName = hostName;
}

/*!
    \reimp

    Returns the number of decrypted bytes that are immediately available for
    reading.
*/
qint64 SslUnsafeSocket::bytesAvailable() const
{
    Q_D(const SslUnsafeSocket);
    if (d->mode == UnencryptedMode)
        return QIODevice::bytesAvailable() + (d->plainSocket ? d->plainSocket->bytesAvailable() : 0);
    return QIODevice::bytesAvailable();
}

/*!
    \reimp

    Returns the number of unencrypted bytes that are waiting to be encrypted
    and written to the network.
*/
qint64 SslUnsafeSocket::bytesToWrite() const
{
    Q_D(const SslUnsafeSocket);
    if (d->mode == UnencryptedMode)
        return d->plainSocket ? d->plainSocket->bytesToWrite() : 0;
    return d->writeBuffer.size();
}

/*!
    \since 4.4

    Returns the number of encrypted bytes that are awaiting decryption.
    Normally, this function will return 0 because SslUnsafeSocket decrypts its
    incoming data as soon as it can.
*/
qint64 SslUnsafeSocket::encryptedBytesAvailable() const
{
    Q_D(const SslUnsafeSocket);
    if (d->mode == UnencryptedMode)
        return 0;
    return d->plainSocket->bytesAvailable();
}

/*!
    \since 4.4

    Returns the number of encrypted bytes that are waiting to be written to
    the network.
*/
qint64 SslUnsafeSocket::encryptedBytesToWrite() const
{
    Q_D(const SslUnsafeSocket);
    if (d->mode == UnencryptedMode)
        return 0;
    return d->plainSocket->bytesToWrite();
}

/*!
    \reimp

    Returns \c true if you can read one while line (terminated by a single ASCII
    '\\n' character) of decrypted characters; otherwise, false is returned.
*/
bool SslUnsafeSocket::canReadLine() const
{
    Q_D(const SslUnsafeSocket);
    if (d->mode == UnencryptedMode)
        return QIODevice::canReadLine() || (d->plainSocket && d->plainSocket->canReadLine());
    return QIODevice::canReadLine();
}

/*!
    \reimp
*/
void SslUnsafeSocket::close()
{
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::close()";
#endif
    Q_D(SslUnsafeSocket);
    if (encryptedBytesToWrite() || !d->writeBuffer.isEmpty())
        flush();
    if (d->plainSocket)
        d->plainSocket->close();
    QTcpSocket::close();

    // must be cleared, reading/writing not possible on closed socket:
    d->buffer.clear();
    d->writeBuffer.clear();
}

/*!
    \reimp
*/
bool SslUnsafeSocket::atEnd() const
{
    Q_D(const SslUnsafeSocket);
    if (d->mode == UnencryptedMode)
        return QIODevice::atEnd() && (!d->plainSocket || d->plainSocket->atEnd());
    return QIODevice::atEnd();
}

/*!
    This function writes as much as possible from the internal write buffer to
    the underlying network socket, without blocking. If any data was written,
    this function returns \c true; otherwise false is returned.

    Call this function if you need SslUnsafeSocket to start sending buffered data
    immediately. The number of bytes successfully written depends on the
    operating system. In most cases, you do not need to call this function,
    because QAbstractSocket will start sending data automatically once control
    goes back to the event loop. In the absence of an event loop, call
    waitForBytesWritten() instead.

    \sa write(), waitForBytesWritten()
*/
#if 0
bool SslUnsafeSocket::flush()
{
    return d_func()->flush();
}
#endif

/*!
    \since 4.4

    Sets the size of SslUnsafeSocket's internal read buffer to be \a size bytes.
*/
void SslUnsafeSocket::setReadBufferSize(qint64 size)
{
    Q_D(SslUnsafeSocket);
    d->readBufferMaxSize = size;

    if (d->plainSocket)
        d->plainSocket->setReadBufferSize(size);
}

/*!
    Aborts the current connection and resets the socket. Unlike
    disconnectFromHost(), this function immediately closes the socket,
    clearing any pending data in the write buffer.

    \sa disconnectFromHost(), close()
*/
void SslUnsafeSocket::abort()
{
    Q_D(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::abort()";
#endif
    if (d->plainSocket)
        d->plainSocket->abort();
    close();
}

/*!
    \since 4.4

    Returns the socket's SSL configuration state. The default SSL
    configuration of a socket is to use the default ciphers,
    default CA certificates, no local private key or certificate.

    The SSL configuration also contains fields that can change with
    time without notice.

    \sa localCertificate(), peerCertificate(), peerCertificateChain(),
        sessionCipher(), privateKey(), ciphers(), caCertificates()
*/
SslUnsafeConfiguration SslUnsafeSocket::sslConfiguration() const
{
    Q_D(const SslUnsafeSocket);

    // create a deep copy of our configuration
    SslUnsafeConfigurationPrivate *copy = new SslUnsafeConfigurationPrivate(d->configuration);
    copy->ref.store(0);              // the QSslConfiguration constructor refs up
    copy->sessionCipher = d->sessionCipher();
    copy->sessionProtocol = d->sessionProtocol();

    return SslUnsafeConfiguration(copy);
}

/*!
    \since 4.4

    Sets the socket's SSL configuration to be the contents of \a configuration.
    This function sets the local certificate, the ciphers, the private key and the CA
    certificates to those stored in \a configuration.

    It is not possible to set the SSL-state related fields.

    \sa setLocalCertificate(), setPrivateKey(), setCaCertificates(), setCiphers()
*/
void SslUnsafeSocket::setSslConfiguration(const SslUnsafeConfiguration &configuration)
{
    Q_D(SslUnsafeSocket);
    d->configuration.localCertificateChain = configuration.localCertificateChain();
    d->configuration.privateKey = configuration.privateKey();
    d->configuration.ciphers = configuration.ciphers();
    d->configuration.ellipticCurves = configuration.ellipticCurves();
    d->configuration.preSharedKeyIdentityHint = configuration.preSharedKeyIdentityHint();
    d->configuration.dhParams = configuration.diffieHellmanParameters();
    d->configuration.caCertificates = configuration.caCertificates();
    d->configuration.peerVerifyDepth = configuration.peerVerifyDepth();
    d->configuration.peerVerifyMode = configuration.peerVerifyMode();
    d->configuration.protocol = configuration.protocol();
    d->configuration.sslOptions = configuration.d->sslOptions;
    d->configuration.sslSession = configuration.sessionTicket();
    d->configuration.sslSessionTicketLifeTimeHint = configuration.sessionTicketLifeTimeHint();
    d->configuration.nextAllowedProtocols = configuration.allowedNextProtocols();
    d->configuration.nextNegotiatedProtocol = configuration.nextNegotiatedProtocol();
    d->configuration.nextProtocolNegotiationStatus = configuration.nextProtocolNegotiationStatus();

    // if the CA certificates were set explicitly (either via
    // QSslConfiguration::setCaCertificates() or SslUnsafeSocket::setCaCertificates(),
    // we cannot load the certificates on demand
    if (!configuration.d->allowRootCertOnDemandLoading)
        d->allowRootCertOnDemandLoading = false;
}

/*!
    Sets the certificate chain to be presented to the peer during the
    SSL handshake to be \a localChain.

    \sa QSslConfiguration::setLocalCertificateChain()
    \since 5.1
 */
void SslUnsafeSocket::setLocalCertificateChain(const QList<SslUnsafeCertificate> &localChain)
{
    Q_D(SslUnsafeSocket);
    d->configuration.localCertificateChain = localChain;
}

/*!
    Returns the socket's local \l {SslUnsafeCertificate} {certificate} chain,
    or an empty list if no local certificates have been assigned.

    \sa setLocalCertificateChain()
    \since 5.1
*/
QList<SslUnsafeCertificate> SslUnsafeSocket::localCertificateChain() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.localCertificateChain;
}

/*!
    Sets the socket's local certificate to \a certificate. The local
    certificate is necessary if you need to confirm your identity to the
    peer. It is used together with the private key; if you set the local
    certificate, you must also set the private key.

    The local certificate and private key are always necessary for server
    sockets, but are also rarely used by client sockets if the server requires
    the client to authenticate.

    \note Secure Transport SSL backend on macOS may update the default keychain
    (the default is probably your login keychain) by importing your local certificates
    and keys. This can also result in system dialogs showing up and asking for
    permission when your application is using these private keys. If such behavior
    is undesired, set the QT_SSL_USE_TEMPORARY_KEYCHAIN environment variable to a
    non-zero value; this will prompt SslUnsafeSocket to use its own temporary keychain.

    \sa localCertificate(), setPrivateKey()
*/
void SslUnsafeSocket::setLocalCertificate(const SslUnsafeCertificate &certificate)
{
    Q_D(SslUnsafeSocket);
    d->configuration.localCertificateChain = QList<SslUnsafeCertificate>();
    d->configuration.localCertificateChain += certificate;
}

/*!
    \overload

    Sets the socket's local \l {SslUnsafeCertificate} {certificate} to the
    first one found in file \a path, which is parsed according to the
    specified \a format.
*/
void SslUnsafeSocket::setLocalCertificate(const QString &path,
                                     QSsl::EncodingFormat format)
{
    QFile file(path);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text))
        setLocalCertificate(SslUnsafeCertificate(file.readAll(), format));

}

/*!
    Returns the socket's local \l {SslUnsafeCertificate} {certificate}, or
    an empty certificate if no local certificate has been assigned.

    \sa setLocalCertificate(), privateKey()
*/
SslUnsafeCertificate SslUnsafeSocket::localCertificate() const
{
    Q_D(const SslUnsafeSocket);
    if (d->configuration.localCertificateChain.isEmpty())
        return SslUnsafeCertificate();
    return d->configuration.localCertificateChain[0];
}

/*!
    Returns the peer's digital certificate (i.e., the immediate
    certificate of the host you are connected to), or a null
    certificate, if the peer has not assigned a certificate.

    The peer certificate is checked automatically during the
    handshake phase, so this function is normally used to fetch
    the certificate for display or for connection diagnostic
    purposes. It contains information about the peer, including
    its host name, the certificate issuer, and the peer's public
    key.

    Because the peer certificate is set during the handshake phase, it
    is safe to access the peer certificate from a slot connected to
    the sslErrors() signal or the encrypted() signal.

    If a null certificate is returned, it can mean the SSL handshake
    failed, or it can mean the host you are connected to doesn't have
    a certificate, or it can mean there is no connection.

    If you want to check the peer's complete chain of certificates,
    use peerCertificateChain() to get them all at once.

    \sa peerCertificateChain()
*/
SslUnsafeCertificate SslUnsafeSocket::peerCertificate() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.peerCertificate;
}

/*!
    Returns the peer's chain of digital certificates, or an empty list
    of certificates.

    Peer certificates are checked automatically during the handshake
    phase. This function is normally used to fetch certificates for
    display, or for performing connection diagnostics. Certificates
    contain information about the peer and the certificate issuers,
    including host name, issuer names, and issuer public keys.

    The peer certificates are set in SslUnsafeSocket during the handshake
    phase, so it is safe to call this function from a slot connected
    to the sslErrors() signal or the encrypted() signal.

    If an empty list is returned, it can mean the SSL handshake
    failed, or it can mean the host you are connected to doesn't have
    a certificate, or it can mean there is no connection.

    If you want to get only the peer's immediate certificate, use
    peerCertificate().

    \sa peerCertificate()
*/
QList<SslUnsafeCertificate> SslUnsafeSocket::peerCertificateChain() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.peerCertificateChain;
}

/*!
    Returns the socket's cryptographic \l {SslUnsafeCipher} {cipher}, or a
    null cipher if the connection isn't encrypted. The socket's cipher
    for the session is set during the handshake phase. The cipher is
    used to encrypt and decrypt data transmitted through the socket.

    SslUnsafeSocket also provides functions for setting the ordered list of
    ciphers from which the handshake phase will eventually select the
    session cipher. This ordered list must be in place before the
    handshake phase begins.

    \sa ciphers(), setCiphers(), setDefaultCiphers(), defaultCiphers(),
    supportedCiphers()
*/
SslUnsafeCipher SslUnsafeSocket::sessionCipher() const
{
    Q_D(const SslUnsafeSocket);
    return d->sessionCipher();
}

/*!
    Returns the socket's SSL/TLS protocol or UnknownProtocol if the
    connection isn't encrypted. The socket's protocol for the session
    is set during the handshake phase.

    \sa protocol(), setProtocol()
    \since 5.4
*/
QSsl::SslProtocol SslUnsafeSocket::sessionProtocol() const
{
    Q_D(const SslUnsafeSocket);
    return d->sessionProtocol();
}


/*!
    Sets the socket's private \l {SslUnsafeKey} {key} to \a key. The
    private key and the local \l {SslUnsafeCertificate} {certificate} are
    used by clients and servers that must prove their identity to
    SSL peers.

    Both the key and the local certificate are required if you are
    creating an SSL server socket. If you are creating an SSL client
    socket, the key and local certificate are required if your client
    must identify itself to an SSL server.

    \sa privateKey(), setLocalCertificate()
*/
void SslUnsafeSocket::setPrivateKey(const SslUnsafeKey &key)
{
    Q_D(SslUnsafeSocket);
    d->configuration.privateKey = key;
}

/*!
    \overload

    Reads the string in file \a fileName and decodes it using
    a specified \a algorithm and encoding \a format to construct
    an \l {SslUnsafeKey} {SSL key}. If the encoded key is encrypted,
    \a passPhrase is used to decrypt it.

    The socket's private key is set to the constructed key. The
    private key and the local \l {SslUnsafeCertificate} {certificate} are
    used by clients and servers that must prove their identity to SSL
    peers.

    Both the key and the local certificate are required if you are
    creating an SSL server socket. If you are creating an SSL client
    socket, the key and local certificate are required if your client
    must identify itself to an SSL server.

    \sa privateKey(), setLocalCertificate()
*/
void SslUnsafeSocket::setPrivateKey(const QString &fileName, QSsl::KeyAlgorithm algorithm,
                               QSsl::EncodingFormat format, const QByteArray &passPhrase)
{
    Q_D(SslUnsafeSocket);
    QFile file(fileName);
    if (file.open(QIODevice::ReadOnly)) {
        d->configuration.privateKey = SslUnsafeKey(file.readAll(), algorithm,
                                              format, QSsl::PrivateKey, passPhrase);
    }
}

/*!
    Returns this socket's private key.

    \sa setPrivateKey(), localCertificate()
*/
SslUnsafeKey SslUnsafeSocket::privateKey() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.privateKey;
}

/*!
  Searches all files in the \a path for certificates encoded in the
  specified \a format and adds them to this socket's CA certificate
  database. \a path must be a file or a pattern matching one or more
  files, as specified by \a syntax. Returns \c true if one or more
  certificates are added to the socket's CA certificate database;
  otherwise returns \c false.

  The CA certificate database is used by the socket during the
  handshake phase to validate the peer's certificate.

  For more precise control, use addCaCertificate().

  \sa addCaCertificate(), SslUnsafeCertificate::fromPath()
*/
bool SslUnsafeSocket::addCaCertificates(const QString &path, QSsl::EncodingFormat format,
                                   QRegExp::PatternSyntax syntax)
{
    Q_D(SslUnsafeSocket);
    QList<SslUnsafeCertificate> certs = SslUnsafeCertificate::fromPath(path, format, syntax);
    if (certs.isEmpty())
        return false;

    d->configuration.caCertificates += certs;
    return true;
}

/*!
  Adds the \a certificate to this socket's CA certificate database.
  The CA certificate database is used by the socket during the
  handshake phase to validate the peer's certificate.

  To add multiple certificates, use addCaCertificates().

  \sa caCertificates(), setCaCertificates()
*/
void SslUnsafeSocket::addCaCertificate(const SslUnsafeCertificate &certificate)
{
    Q_D(SslUnsafeSocket);
    d->configuration.caCertificates += certificate;
}

/*!
  Adds the \a certificates to this socket's CA certificate database.
  The CA certificate database is used by the socket during the
  handshake phase to validate the peer's certificate.

  For more precise control, use addCaCertificate().

  \sa caCertificates(), addDefaultCaCertificate()
*/
void SslUnsafeSocket::addCaCertificates(const QList<SslUnsafeCertificate> &certificates)
{
    Q_D(SslUnsafeSocket);
    d->configuration.caCertificates += certificates;
}

/*!
    Searches all files in the \a path for certificates with the
    specified \a encoding and adds them to the default CA certificate
    database. \a path can be an explicit file, or it can contain
    wildcards in the format specified by \a syntax. Returns \c true if
    any CA certificates are added to the default database.

    Each SSL socket's CA certificate database is initialized to the
    default CA certificate database.

    \sa defaultCaCertificates(), addCaCertificates(), addDefaultCaCertificate()
*/
bool SslUnsafeSocket::addDefaultCaCertificates(const QString &path, QSsl::EncodingFormat encoding,
                                          QRegExp::PatternSyntax syntax)
{
    return SslUnsafeSocketPrivate::addDefaultCaCertificates(path, encoding, syntax);
}

/*!
    Adds \a certificate to the default CA certificate database.  Each
    SSL socket's CA certificate database is initialized to the default
    CA certificate database.

    \sa defaultCaCertificates(), addCaCertificates()
*/
void SslUnsafeSocket::addDefaultCaCertificate(const SslUnsafeCertificate &certificate)
{
    SslUnsafeSocketPrivate::addDefaultCaCertificate(certificate);
}

/*!
    Adds \a certificates to the default CA certificate database.  Each
    SSL socket's CA certificate database is initialized to the default
    CA certificate database.

    \sa defaultCaCertificates(), addCaCertificates()
*/
void SslUnsafeSocket::addDefaultCaCertificates(const QList<SslUnsafeCertificate> &certificates)
{
    SslUnsafeSocketPrivate::addDefaultCaCertificates(certificates);
}

/*!
    Waits until the socket is connected, or \a msecs milliseconds,
    whichever happens first. If the connection has been established,
    this function returns \c true; otherwise it returns \c false.

    \sa QAbstractSocket::waitForConnected()
*/
bool SslUnsafeSocket::waitForConnected(int msecs)
{
    Q_D(SslUnsafeSocket);
    if (!d->plainSocket)
        return false;
    bool retVal = d->plainSocket->waitForConnected(msecs);
    if (!retVal) {
        setSocketState(d->plainSocket->state());
        d->setError(d->plainSocket->error(), d->plainSocket->errorString());
    }
    return retVal;
}

/*!
    Waits until the socket has completed the SSL handshake and has
    emitted encrypted(), or \a msecs milliseconds, whichever comes
    first. If encrypted() has been emitted, this function returns
    true; otherwise (e.g., the socket is disconnected, or the SSL
    handshake fails), false is returned.

    The following example waits up to one second for the socket to be
    encrypted:

    \snippet code/src_network_ssl_SslUnsafeSocket.cpp 5

    If msecs is -1, this function will not time out.

    \sa startClientEncryption(), startServerEncryption(), encrypted(), isEncrypted()
*/
bool SslUnsafeSocket::waitForEncrypted(int msecs)
{
    Q_D(SslUnsafeSocket);
    if (!d->plainSocket || d->connectionEncrypted)
        return false;
    if (d->mode == UnencryptedMode && !d->autoStartHandshake)
        return false;

    QElapsedTimer stopWatch;
    stopWatch.start();

    if (d->plainSocket->state() != QAbstractSocket::ConnectedState) {
        // Wait until we've entered connected state.
        if (!d->plainSocket->waitForConnected(msecs))
            return false;
    }

    while (!d->connectionEncrypted) {
        // Start the handshake, if this hasn't been started yet.
        if (d->mode == UnencryptedMode)
            startClientEncryption();
        // Loop, waiting until the connection has been encrypted or an error
        // occurs.
        if (!d->plainSocket->waitForReadyRead(qt_subtract_from_timeout(msecs, stopWatch.elapsed())))
            return false;
    }
    return d->connectionEncrypted;
}

/*!
    \reimp
*/
bool SslUnsafeSocket::waitForReadyRead(int msecs)
{
    Q_D(SslUnsafeSocket);
    if (!d->plainSocket)
        return false;
    if (d->mode == UnencryptedMode && !d->autoStartHandshake)
        return d->plainSocket->waitForReadyRead(msecs);

    // This function must return true if and only if readyRead() *was* emitted.
    // So we initialize "readyReadEmitted" to false and check if it was set to true.
    // waitForReadyRead() could be called recursively, so we can't use the same variable
    // (the inner waitForReadyRead() may fail, but the outer one still succeeded)
    bool readyReadEmitted = false;
    bool *previousReadyReadEmittedPointer = d->readyReadEmittedPointer;
    d->readyReadEmittedPointer = &readyReadEmitted;

    QElapsedTimer stopWatch;
    stopWatch.start();

    if (!d->connectionEncrypted) {
        // Wait until we've entered encrypted mode, or until a failure occurs.
        if (!waitForEncrypted(msecs)) {
            d->readyReadEmittedPointer = previousReadyReadEmittedPointer;
            return false;
        }
    }

    if (!d->writeBuffer.isEmpty()) {
        // empty our cleartext write buffer first
        d->transmit();
    }

    // test readyReadEmitted first because either operation above
    // (waitForEncrypted or transmit) may have set it
    while (!readyReadEmitted &&
           d->plainSocket->waitForReadyRead(qt_subtract_from_timeout(msecs, stopWatch.elapsed()))) {
    }

    d->readyReadEmittedPointer = previousReadyReadEmittedPointer;
    return readyReadEmitted;
}

/*!
    \reimp
*/
bool SslUnsafeSocket::waitForBytesWritten(int msecs)
{
    Q_D(SslUnsafeSocket);
    if (!d->plainSocket)
        return false;
    if (d->mode == UnencryptedMode)
        return d->plainSocket->waitForBytesWritten(msecs);

    QElapsedTimer stopWatch;
    stopWatch.start();

    if (!d->connectionEncrypted) {
        // Wait until we've entered encrypted mode, or until a failure occurs.
        if (!waitForEncrypted(msecs))
            return false;
    }
    if (!d->writeBuffer.isEmpty()) {
        // empty our cleartext write buffer first
        d->transmit();
    }

    return d->plainSocket->waitForBytesWritten(qt_subtract_from_timeout(msecs, stopWatch.elapsed()));
}

/*!
    Waits until the socket has disconnected or \a msecs milliseconds,
    whichever comes first. If the connection has been disconnected,
    this function returns \c true; otherwise it returns \c false.

    \sa QAbstractSocket::waitForDisconnected()
*/
bool SslUnsafeSocket::waitForDisconnected(int msecs)
{
    Q_D(SslUnsafeSocket);

    // require calling connectToHost() before waitForDisconnected()
    if (state() == UnconnectedState) {
        qWarning() << "SslUnsafeSocket::waitForDisconnected() is not allowed in UnconnectedState";
        return false;
    }

    if (!d->plainSocket)
        return false;
    // Forward to the plain socket unless the connection is secure.
    if (d->mode == UnencryptedMode && !d->autoStartHandshake)
        return d->plainSocket->waitForDisconnected(msecs);

    QElapsedTimer stopWatch;
    stopWatch.start();

    if (!d->connectionEncrypted) {
        // Wait until we've entered encrypted mode, or until a failure occurs.
        if (!waitForEncrypted(msecs))
            return false;
    }
    // We are delaying the disconnect, if the write buffer is not empty.
    // So, start the transmission.
    if (!d->writeBuffer.isEmpty())
        d->transmit();

    // At this point, the socket might be disconnected, if disconnectFromHost()
    // was called just after the connectToHostEncrypted() call. Also, we can
    // lose the connection as a result of the transmit() call.
    if (state() == UnconnectedState)
        return true;

    bool retVal = d->plainSocket->waitForDisconnected(qt_subtract_from_timeout(msecs, stopWatch.elapsed()));
    if (!retVal) {
        setSocketState(d->plainSocket->state());
        d->setError(d->plainSocket->error(), d->plainSocket->errorString());
    }
    return retVal;
}

/*!
    Returns a list of the last SSL errors that occurred. This is the
    same list as SslUnsafeSocket passes via the sslErrors() signal. If the
    connection has been encrypted with no errors, this function will
    return an empty list.

    \sa connectToHostEncrypted()
*/
QList<SslUnsafeError> SslUnsafeSocket::sslErrors() const
{
    Q_D(const SslUnsafeSocket);
    return d->sslErrors;
}

/*!
    Returns \c true if this platform supports SSL; otherwise, returns
    false. If the platform doesn't support SSL, the socket will fail
    in the connection phase.
*/
bool SslUnsafeSocket::supportsSsl()
{
    return SslUnsafeSocketPrivate::supportsSsl();
}

/*!
    \since 5.0
    Returns the version number of the SSL library in use. Note that
    this is the version of the library in use at run-time not compile
    time. If no SSL support is available then this will return an
    undefined value.
*/
long SslUnsafeSocket::sslLibraryVersionNumber()
{
    return SslUnsafeSocketPrivate::sslLibraryVersionNumber();
}

/*!
    \since 5.0
    Returns the version string of the SSL library in use. Note that
    this is the version of the library in use at run-time not compile
    time. If no SSL support is available then this will return an empty value.
*/
QString SslUnsafeSocket::sslLibraryVersionString()
{
    return SslUnsafeSocketPrivate::sslLibraryVersionString();
}

/*!
    \since 5.4
    Returns the version number of the SSL library in use at compile
    time. If no SSL support is available then this will return an
    undefined value.

    \sa sslLibraryVersionNumber()
*/
long SslUnsafeSocket::sslLibraryBuildVersionNumber()
{
    return SslUnsafeSocketPrivate::sslLibraryBuildVersionNumber();
}

/*!
    \since 5.4
    Returns the version string of the SSL library in use at compile
    time. If no SSL support is available then this will return an
    empty value.

    \sa sslLibraryVersionString()
*/
QString SslUnsafeSocket::sslLibraryBuildVersionString()
{
    return SslUnsafeSocketPrivate::sslLibraryBuildVersionString();
}

/*!
    Starts a delayed SSL handshake for a client connection. This
    function can be called when the socket is in the \l ConnectedState
    but still in the \l UnencryptedMode. If it is not yet connected,
    or if it is already encrypted, this function has no effect.

    Clients that implement STARTTLS functionality often make use of
    delayed SSL handshakes. Most other clients can avoid calling this
    function directly by using connectToHostEncrypted() instead, which
    automatically performs the handshake.

    \sa connectToHostEncrypted(), startServerEncryption()
*/
void SslUnsafeSocket::startClientEncryption()
{
    Q_D(SslUnsafeSocket);
    if (d->mode != UnencryptedMode) {
        qWarning() << "SslUnsafeSocket::startClientEncryption: cannot start handshake on non-plain connection";
        return;
    }
    if (state() != ConnectedState) {
        qWarning() << "SslUnsafeSocket::startClientEncryption: cannot start handshake when not connected";
        return;
    }
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::startClientEncryption()";
#endif
    d->mode = SslClientMode;
    emit modeChanged(d->mode);
    d->startClientEncryption();
}

/*!
    Starts a delayed SSL handshake for a server connection. This
    function can be called when the socket is in the \l ConnectedState
    but still in \l UnencryptedMode. If it is not connected or it is
    already encrypted, the function has no effect.

    For server sockets, calling this function is the only way to
    initiate the SSL handshake. Most servers will call this function
    immediately upon receiving a connection, or as a result of having
    received a protocol-specific command to enter SSL mode (e.g, the
    server may respond to receiving the string "STARTTLS\\r\\n" by
    calling this function).

    The most common way to implement an SSL server is to create a
    subclass of QTcpServer and reimplement
    QTcpServer::incomingConnection(). The returned socket descriptor
    is then passed to SslUnsafeSocket::setSocketDescriptor().

    \sa connectToHostEncrypted(), startClientEncryption()
*/
void SslUnsafeSocket::startServerEncryption()
{
    Q_D(SslUnsafeSocket);
    if (d->mode != UnencryptedMode) {
        qWarning() << "SslUnsafeSocket::startServerEncryption: cannot start handshake on non-plain connection";
        return;
    }
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::startServerEncryption()";
#endif
    d->mode = SslServerMode;
    emit modeChanged(d->mode);
    d->startServerEncryption();
}

/*!
    This slot tells SslUnsafeSocket to ignore errors during SslUnsafeSocket's
    handshake phase and continue connecting. If you want to continue
    with the connection even if errors occur during the handshake
    phase, then you must call this slot, either from a slot connected
    to sslErrors(), or before the handshake phase. If you don't call
    this slot, either in response to errors or before the handshake,
    the connection will be dropped after the sslErrors() signal has
    been emitted.

    If there are no errors during the SSL handshake phase (i.e., the
    identity of the peer is established with no problems), SslUnsafeSocket
    will not emit the sslErrors() signal, and it is unnecessary to
    call this function.

    \warning Be sure to always let the user inspect the errors
    reported by the sslErrors() signal, and only call this method
    upon confirmation from the user that proceeding is ok.
    If there are unexpected errors, the connection should be aborted.
    Calling this method without inspecting the actual errors will
    most likely pose a security risk for your application. Use it
    with great care!

    \sa sslErrors()
*/
void SslUnsafeSocket::ignoreSslErrors()
{
    Q_D(SslUnsafeSocket);
    d->ignoreAllSslErrors = true;
}

/*!
    \overload
    \since 4.6

    This method tells SslUnsafeSocket to ignore only the errors given in \a
    errors.

    \note Because most SSL errors are associated with a certificate, for most
    of them you must set the expected certificate this SSL error is related to.
    If, for instance, you want to connect to a server that uses
    a self-signed certificate, consider the following snippet:

    \snippet code/src_network_ssl_SslUnsafeSocket.cpp 6

    Multiple calls to this function will replace the list of errors that
    were passed in previous calls.
    You can clear the list of errors you want to ignore by calling this
    function with an empty list.

    \sa sslErrors()
*/
void SslUnsafeSocket::ignoreSslErrors(const QList<SslUnsafeError> &errors)
{
    Q_D(SslUnsafeSocket);
    d->ignoreErrorsList = errors;
}

/*!
    \internal
*/
void SslUnsafeSocket::connectToHost(const QString &hostName, quint16 port, OpenMode openMode, NetworkLayerProtocol protocol)
{
    Q_D(SslUnsafeSocket);
    d->preferredNetworkLayerProtocol = protocol;
    if (!d->initialized)
        d->init();
    d->initialized = false;

#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::connectToHost("
             << hostName << ',' << port << ',' << openMode << ')';
#endif
    if (!d->plainSocket) {
#ifdef SSLUNSAFESOCKET_DEBUG
        qDebug() << "\tcreating internal plain socket";
#endif
        d->createPlainSocket(openMode);
    }
#ifndef QT_NO_NETWORKPROXY
    d->plainSocket->setProxy(proxy());
#endif
    QIODevice::open(openMode);
    d->readChannelCount = d->writeChannelCount = 0;
    d->plainSocket->connectToHost(hostName, port, openMode, d->preferredNetworkLayerProtocol);
    d->cachedSocketDescriptor = d->plainSocket->socketDescriptor();
}

/*!
    \internal
*/
void SslUnsafeSocket::disconnectFromHost()
{
    Q_D(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::disconnectFromHost()";
#endif
    if (!d->plainSocket)
        return;
    if (d->state() == UnconnectedState)
        return;
    if (d->mode == UnencryptedMode && !d->autoStartHandshake) {
        d->plainSocket->disconnectFromHost();
        return;
    }
    if (d->state() <= ConnectingState) {
        d->pendingClose = true;
        return;
    }

    // Perhaps emit closing()
    if (d->state() != ClosingState) {
        d->setSocketState(ClosingState);
        emit stateChanged(d->state());
    }

    if (!d->writeBuffer.isEmpty()) {
        d->pendingClose = true;
        return;
    }

    if (d->mode == UnencryptedMode) {
        d->plainSocket->disconnectFromHost();
    } else {
        d->disconnectFromHost();
    }
}

/*!
    \reimp
*/
qint64 SslUnsafeSocket::readData(char *data, qint64 maxlen)
{
    Q_D(SslUnsafeSocket);
    qint64 readBytes = 0;

    if (d->mode == UnencryptedMode && !d->autoStartHandshake) {
        readBytes = d->plainSocket->read(data, maxlen);
#ifdef SSLUNSAFESOCKET_DEBUG
        qDebug() << "SslUnsafeSocket::readData(" << (void *)data << ',' << maxlen << ") =="
                 << readBytes;
#endif
    } else {
        // possibly trigger another transmit() to decrypt more data from the socket
        if (d->plainSocket->bytesAvailable()) {
            QMetaObject::invokeMethod(this, "_q_flushReadBuffer", Qt::QueuedConnection);
        } else {
            readBytes = d->buffer.read(data, maxlen);
        }
    }

    return readBytes;
}

/*!
    \reimp
*/
qint64 SslUnsafeSocket::writeData(const char *data, qint64 len)
{
    Q_D(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::writeData(" << (void *)data << ',' << len << ')';
#endif
    if (d->mode == UnencryptedMode && !d->autoStartHandshake)
        return d->plainSocket->write(data, len);

    d->writeBuffer.append(data, len);

    // make sure we flush to the plain socket's buffer
    QMetaObject::invokeMethod(this, "_q_flushWriteBuffer", Qt::QueuedConnection);

    return len;
}

/*!
    \internal
*/
SslUnsafeSocketPrivate::SslUnsafeSocketPrivate()
    : initialized(false)
    , mode(SslUnsafeSocket::UnencryptedMode)
    , autoStartHandshake(false)
    , connectionEncrypted(false)
    , shutdown(false)
    , ignoreAllSslErrors(false)
    , readyReadEmittedPointer(0)
    , allowRootCertOnDemandLoading(true)
    , plainSocket(0)
    , paused(false)
{
    SslUnsafeConfigurationPrivate::deepCopyDefaultConfiguration(&configuration);

    readBuffers << SslUnsafeRingBuffer(writeBufferChunkSize);
    writeBuffers << SslUnsafeRingBuffer(writeBufferChunkSize);

    buffer.m_buf = &readBuffers[0];
    writeBuffer.m_buf = &writeBuffers[0];
}

/*!
    \internal
*/
SslUnsafeSocketPrivate::~SslUnsafeSocketPrivate()
{
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::init()
{
    mode = SslUnsafeSocket::UnencryptedMode;
    autoStartHandshake = false;
    connectionEncrypted = false;
    ignoreAllSslErrors = false;
    shutdown = false;
    pendingClose = false;

    // we don't want to clear the ignoreErrorsList, so
    // that it is possible setting it before connecting
//    ignoreErrorsList.clear();

    buffer.clear();
    writeBuffer.clear();
    configuration.peerCertificate.clear();
    configuration.peerCertificateChain.clear();
}

/*!
    \internal
*/
QList<SslUnsafeCipher> SslUnsafeSocketPrivate::defaultCiphers()
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    return globalData()->config->ciphers;
}

/*!
    \internal
*/
QList<SslUnsafeCipher> SslUnsafeSocketPrivate::supportedCiphers()
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    return globalData()->supportedCiphers;
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::setDefaultCiphers(const QList<SslUnsafeCipher> &ciphers)
{
    QMutexLocker locker(&globalData()->mutex);
    globalData()->config.detach();
    globalData()->config->ciphers = ciphers;
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::setDefaultSupportedCiphers(const QList<SslUnsafeCipher> &ciphers)
{
    QMutexLocker locker(&globalData()->mutex);
    globalData()->config.detach();
    globalData()->supportedCiphers = ciphers;
}

/*!
    \internal
*/
QVector<SslUnsafeEllipticCurve> SslUnsafeSocketPrivate::supportedEllipticCurves()
{
    SslUnsafeSocketPrivate::ensureInitialized();
    const QMutexLocker locker(&globalData()->mutex);
    return globalData()->supportedEllipticCurves;
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::setDefaultSupportedEllipticCurves(const QVector<SslUnsafeEllipticCurve> &curves)
{
    const QMutexLocker locker(&globalData()->mutex);
    globalData()->config.detach();
    globalData()->supportedEllipticCurves = curves;
}

/*!
    \internal
*/
QList<SslUnsafeCertificate> SslUnsafeSocketPrivate::defaultCaCertificates()
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    return globalData()->config->caCertificates;
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::setDefaultCaCertificates(const QList<SslUnsafeCertificate> &certs)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    globalData()->config.detach();
    globalData()->config->caCertificates = certs;
    // when the certificates are set explicitly, we do not want to
    // load the system certificates on demand
    s_loadRootCertsOnDemand = false;
}

/*!
    \internal
*/
bool SslUnsafeSocketPrivate::addDefaultCaCertificates(const QString &path, QSsl::EncodingFormat format,
                                                 QRegExp::PatternSyntax syntax)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QList<SslUnsafeCertificate> certs = SslUnsafeCertificate::fromPath(path, format, syntax);
    if (certs.isEmpty())
        return false;

    QMutexLocker locker(&globalData()->mutex);
    globalData()->config.detach();
    globalData()->config->caCertificates += certs;
    return true;
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::addDefaultCaCertificate(const SslUnsafeCertificate &cert)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    globalData()->config.detach();
    globalData()->config->caCertificates += cert;
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::addDefaultCaCertificates(const QList<SslUnsafeCertificate> &certs)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    globalData()->config.detach();
    globalData()->config->caCertificates += certs;
}

/*!
    \internal
*/
SslUnsafeConfiguration SslUnsafeConfigurationPrivate::defaultConfiguration()
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    return SslUnsafeConfiguration(globalData()->config.data());
}

/*!
    \internal
*/
void SslUnsafeConfigurationPrivate::setDefaultConfiguration(const SslUnsafeConfiguration &configuration)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    if (globalData()->config == configuration.d)
        return;                 // nothing to do

    globalData()->config = const_cast<SslUnsafeConfigurationPrivate*>(configuration.d.constData());
}

/*!
    \internal
*/
void SslUnsafeConfigurationPrivate::deepCopyDefaultConfiguration(SslUnsafeConfigurationPrivate *ptr)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    const SslUnsafeConfigurationPrivate *global = globalData()->config.constData();

    if (!global)
        return;

    ptr->ref.store(1);
    ptr->peerCertificate = global->peerCertificate;
    ptr->peerCertificateChain = global->peerCertificateChain;
    ptr->localCertificateChain = global->localCertificateChain;
    ptr->privateKey = global->privateKey;
    ptr->sessionCipher = global->sessionCipher;
    ptr->sessionProtocol = global->sessionProtocol;
    ptr->ciphers = global->ciphers;
    ptr->caCertificates = global->caCertificates;
    ptr->protocol = global->protocol;
    ptr->peerVerifyMode = global->peerVerifyMode;
    ptr->peerVerifyDepth = global->peerVerifyDepth;
    ptr->sslOptions = global->sslOptions;
    ptr->ellipticCurves = global->ellipticCurves;
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::createPlainSocket(QIODevice::OpenMode openMode)
{
    Q_Q(SslUnsafeSocket);
    q->setOpenMode(openMode); // <- from QIODevice
    q->setSocketState(QAbstractSocket::UnconnectedState);
    q->setSocketError(QAbstractSocket::UnknownSocketError);
    q->setLocalPort(0);
    q->setLocalAddress(QHostAddress());
    q->setPeerPort(0);
    q->setPeerAddress(QHostAddress());
    q->setPeerName(QString());

    plainSocket = new QTcpSocket(q);
#ifndef QT_NO_BEARERMANAGEMENT
    //copy network session down to the plain socket (if it has been set)
    plainSocket->setProperty("_q_networksession", q->property("_q_networksession"));
#endif
    q->connect(plainSocket, SIGNAL(connected()),
               q, SLOT(_q_connectedSlot()),
               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(hostFound()),
               q, SLOT(_q_hostFoundSlot()),
               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(disconnected()),
               q, SLOT(_q_disconnectedSlot()),
               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
               q, SLOT(_q_stateChangedSlot(QAbstractSocket::SocketState)),
               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(error(QAbstractSocket::SocketError)),
               q, SLOT(_q_errorSlot(QAbstractSocket::SocketError)),
               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(readyRead()),
               q, SLOT(_q_readyReadSlot()),
               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(channelReadyRead(int)),
               q, SLOT(_q_channelReadyReadSlot(int)),
               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(bytesWritten(qint64)),
               q, SLOT(_q_bytesWrittenSlot(qint64)),
               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(channelBytesWritten(int, qint64)),
               q, SLOT(_q_channelBytesWrittenSlot(int, qint64)),
               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(readChannelFinished()),
               q, SLOT(_q_readChannelFinishedSlot()),
               Qt::DirectConnection);
#ifndef QT_NO_NETWORKPROXY
    q->connect(plainSocket, SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)),
               q, SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)));
#endif

    buffer.clear();
    writeBuffer.clear();
    connectionEncrypted = false;
    configuration.peerCertificate.clear();
    configuration.peerCertificateChain.clear();
    mode = SslUnsafeSocket::UnencryptedMode;
    q->setReadBufferSize(readBufferMaxSize);
}

void SslUnsafeSocketPrivate::pauseSocketNotifiers(SslUnsafeSocket *socket)
{
    if (!socket->d_func()->plainSocket)
        return;
    //QAbstractSocketPrivate::pauseSocketNotifiers(socket->d_func()->plainSocket);
}

void SslUnsafeSocketPrivate::resumeSocketNotifiers(SslUnsafeSocket *socket)
{
    if (!socket->d_func()->plainSocket)
        return;
    //QAbstractSocketPrivate::resumeSocketNotifiers(socket->d_func()->plainSocket);
}

bool SslUnsafeSocketPrivate::isPaused() const
{
    return paused;
}

bool SslUnsafeSocketPrivate::bind(const QHostAddress &address, quint16 port, QAbstractSocket::BindMode mode)
{
    // this function is called from QAbstractSocket::bind
    if (!initialized)
        init();
    initialized = false;

#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::bind(" << address << ',' << port << ',' << mode << ')';
#endif
    if (!plainSocket) {
#ifdef SSLUNSAFESOCKET_DEBUG
        qDebug() << "\tcreating internal plain socket";
#endif
        createPlainSocket(QIODevice::ReadWrite);
    }
    bool ret = plainSocket->bind(address, port, mode);
    setLocalPort(plainSocket->localPort());
    //localPort = plainSocket->localPort();
    //localAddress = plainSocket->localAddress();
    setLocalAddress(plainSocket->localAddress());
    cachedSocketDescriptor = plainSocket->socketDescriptor();
    readChannelCount = writeChannelCount = 0;
    return ret;
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_connectedSlot()
{
    Q_Q(SslUnsafeSocket);
    q->setLocalPort(plainSocket->localPort());
    q->setLocalAddress(plainSocket->localAddress());
    q->setPeerPort(plainSocket->peerPort());
    q->setPeerAddress(plainSocket->peerAddress());
    q->setPeerName(plainSocket->peerName());
    cachedSocketDescriptor = plainSocket->socketDescriptor();
    readChannelCount = plainSocket->readChannelCount();
    writeChannelCount = plainSocket->writeChannelCount();

#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::_q_connectedSlot()";
    qDebug() << "\tstate =" << q->state();
    qDebug() << "\tpeer =" << q->peerName() << q->peerAddress() << q->peerPort();
    qDebug() << "\tlocal =" << QHostInfo::fromName(q->localAddress().toString()).hostName()
             << q->localAddress() << q->localPort();
#endif

    if (autoStartHandshake)
        q->startClientEncryption();

    emit q->connected();

    if (pendingClose && !autoStartHandshake) {
        pendingClose = false;
        q->disconnectFromHost();
    }
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_hostFoundSlot()
{
    Q_Q(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::_q_hostFoundSlot()";
    qDebug() << "\tstate =" << q->state();
#endif
    emit q->hostFound();
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_disconnectedSlot()
{
    Q_Q(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::_q_disconnectedSlot()";
    qDebug() << "\tstate =" << q->state();
#endif
    disconnected();
    emit q->disconnected();

    q->setLocalPort(0);
    q->setLocalAddress(QHostAddress());
    q->setPeerPort(0);
    q->setPeerAddress(QHostAddress());
    q->setPeerName(QString());
    cachedSocketDescriptor = -1;
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_stateChangedSlot(QAbstractSocket::SocketState state)
{
    Q_Q(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::_q_stateChangedSlot(" << state << ')';
#endif
    q->setSocketState(state);
    emit q->stateChanged(state);
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_errorSlot(QAbstractSocket::SocketError error)
{
    Q_UNUSED(error)
#ifdef SSLUNSAFESOCKET_DEBUG
    Q_Q(SslUnsafeSocket);
    qDebug() << "SslUnsafeSocket::_q_errorSlot(" << error << ')';
    qDebug() << "\tstate =" << q->state();
    qDebug() << "\terrorString =" << q->errorString();
#endif
    // this moves encrypted bytes from plain socket into our buffer
    if (plainSocket->bytesAvailable()) {
        qint64 tmpReadBufferMaxSize = readBufferMaxSize;
        readBufferMaxSize = 0; // reset temporarily so the plain sockets completely drained drained
        transmit();
        readBufferMaxSize = tmpReadBufferMaxSize;
    }

    setErrorAndEmit(plainSocket->error(), plainSocket->errorString());
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_readyReadSlot()
{
    Q_Q(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::_q_readyReadSlot() -" << plainSocket->bytesAvailable() << "bytes available";
#endif
    if (mode == SslUnsafeSocket::UnencryptedMode) {
        if (readyReadEmittedPointer)
            *readyReadEmittedPointer = true;
        emit q->readyRead();
        return;
    }

    transmit();
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_channelReadyReadSlot(int channel)
{
    Q_Q(SslUnsafeSocket);
    if (mode == SslUnsafeSocket::UnencryptedMode)
        emit q->channelReadyRead(channel);
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_bytesWrittenSlot(qint64 written)
{
    Q_Q(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocket::_q_bytesWrittenSlot(" << written << ')';
#endif

    if (mode == SslUnsafeSocket::UnencryptedMode)
        emit q->bytesWritten(written);
    else
        emit q->encryptedBytesWritten(written);
    if (state() == QAbstractSocket::ClosingState && writeBuffer.isEmpty())
        q->disconnectFromHost();
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_channelBytesWrittenSlot(int channel, qint64 written)
{
    Q_Q(SslUnsafeSocket);
    if (mode == SslUnsafeSocket::UnencryptedMode)
        emit q->channelBytesWritten(channel, written);
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_readChannelFinishedSlot()
{
    Q_Q(SslUnsafeSocket);
    emit q->readChannelFinished();
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_flushWriteBuffer()
{
    Q_Q(SslUnsafeSocket);
    if (!writeBuffer.isEmpty())
        q->flush();
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_flushReadBuffer()
{
    // trigger a read from the plainSocket into SSL
    if (mode != SslUnsafeSocket::UnencryptedMode)
        transmit();
}

/*!
    \internal
*/
#if 0
void SslUnsafeSocketPrivate::_q_resumeImplementation()
{
    if (plainSocket)
        plainSocket->resume();
    paused = false;
    if (!connectionEncrypted) {
        if (verifyErrorsHaveBeenIgnored()) {
            continueHandshake();
        } else {
            setErrorAndEmit(QAbstractSocket::SslHandshakeFailedError, sslErrors.constFirst().errorString());
            plainSocket->disconnectFromHost();
            return;
        }
    }
    transmit();
}
#endif

/*!
    \internal
*/
bool SslUnsafeSocketPrivate::verifyErrorsHaveBeenIgnored()
{
    bool doEmitSslError;
    if (!ignoreErrorsList.empty()) {
        // check whether the errors we got are all in the list of expected errors
        // (applies only if the method SslUnsafeSocket::ignoreSslErrors(const QList<SslUnsafeError> &errors)
        // was called)
        doEmitSslError = false;
        for (int a = 0; a < sslErrors.count(); a++) {
            if (!ignoreErrorsList.contains(sslErrors.at(a))) {
                doEmitSslError = true;
                break;
            }
        }
    } else {
        // if SslUnsafeSocket::ignoreSslErrors(const QList<SslUnsafeError> &errors) was not called and
        // we get an SSL error, emit a signal unless we ignored all errors (by calling
        // SslUnsafeSocket::ignoreSslErrors() )
        doEmitSslError = !ignoreAllSslErrors;
    }
    return !doEmitSslError;
}

/*!
    \internal
*/
qint64 SslUnsafeSocketPrivate::peek(char *data, qint64 maxSize)
{
    if (mode == SslUnsafeSocket::UnencryptedMode && !autoStartHandshake) {
        //unencrypted mode - do not use QIODevice::peek, as it reads ahead data from the plain socket
        //peek at data already in the QIODevice buffer (from a previous read)
        qint64 r = buffer.peek(data, maxSize, transactionPos);
        if (r == maxSize)
            return r;
        data += r;
        //peek at data in the plain socket
        if (plainSocket) {
            qint64 r2 = plainSocket->peek(data, maxSize - r);
            if (r2 < 0)
                return (r > 0 ? r : r2);
            return r + r2;
        } else {
            return -1;
        }
    } else {
        //encrypted mode - the socket engine will read and decrypt data into the QIODevice buffer
        return QTcpSocket::peek(data, maxSize);
    }
}

/*!
    \internal
*/
QByteArray SslUnsafeSocketPrivate::peek(qint64 maxSize)
{
    if (mode == SslUnsafeSocket::UnencryptedMode && !autoStartHandshake) {
        //unencrypted mode - do not use QIODevice::peek, as it reads ahead data from the plain socket
        //peek at data already in the QIODevice buffer (from a previous read)
        QByteArray ret;
        ret.reserve(maxSize);
        ret.resize(buffer.peek(ret.data(), maxSize, transactionPos));
        if (ret.length() == maxSize)
            return ret;
        //peek at data in the plain socket
        if (plainSocket)
            return ret + plainSocket->peek(maxSize - ret.length());
        else
            return QByteArray();
    } else {
        //encrypted mode - the socket engine will read and decrypt data into the QIODevice buffer
        return QTcpSocket::peek(maxSize);
    }
}

/*!
    \internal
*/
bool SslUnsafeSocketPrivate::flush()
{
#ifdef SSLUNSAFESOCKET_DEBUG
    qDebug() << "SslUnsafeSocketPrivate::flush()";
#endif
    if (mode != SslUnsafeSocket::UnencryptedMode) {
        // encrypt any unencrypted bytes in our buffer
        transmit();
    }

    return plainSocket && plainSocket->flush();
}

/*!
    \internal
*/
bool SslUnsafeSocketPrivate::rootCertOnDemandLoadingSupported()
{
    return s_loadRootCertsOnDemand;
}

/*!
    \internal
*/
QList<QByteArray> SslUnsafeSocketPrivate::unixRootCertDirectories()
{
    return QList<QByteArray>() <<  "/etc/ssl/certs/" // (K)ubuntu, OpenSUSE, Mandriva ...
                               << "/usr/lib/ssl/certs/" // Gentoo, Mandrake
                               << "/usr/share/ssl/" // Centos, Redhat, SuSE
                               << "/usr/local/ssl/" // Normal OpenSSL Tarball
                               << "/var/ssl/certs/" // AIX
                               << "/usr/local/ssl/certs/" // Solaris
                               << "/etc/openssl/certs/" // BlackBerry
                               << "/opt/openssl/certs/" // HP-UX
                               << "/etc/ssl/"; // OpenBSD
}

/*!
    \internal
*/
void SslUnsafeSocketPrivate::checkSettingSslContext(SslUnsafeSocket* socket, QSharedPointer<SslUnsafeContext> sslContext)
{
    if (socket->d_func()->sslContextPointer.isNull())
        socket->d_func()->sslContextPointer = sslContext;
}

/*!
    \internal
*/
QSharedPointer<SslUnsafeContext> SslUnsafeSocketPrivate::sslContext(SslUnsafeSocket *socket)
{
    return (socket) ? socket->d_func()->sslContextPointer : QSharedPointer<SslUnsafeContext>();
}

bool SslUnsafeSocketPrivate::isMatchingHostname(const SslUnsafeCertificate &cert, const QString &peerName)
{
    const QString lowerPeerName = QString::fromLatin1(QUrl::toAce(peerName));
    const QStringList commonNames = cert.subjectInfo(SslUnsafeCertificate::CommonName);

    for (const QString &commonName : commonNames) {
        if (isMatchingHostname(commonName, lowerPeerName))
            return true;
    }

    const auto subjectAlternativeNames = cert.subjectAlternativeNames();
    const auto altNames = subjectAlternativeNames.equal_range(QSsl::DnsEntry);
    for (auto it = altNames.first; it != altNames.second; ++it) {
        if (isMatchingHostname(*it, lowerPeerName))
            return true;
    }

    return false;
}

/*! \internal
   Checks if the certificate's name \a cn matches the \a hostname.
   \a hostname must be normalized in ASCII-Compatible Encoding, but \a cn is not normalized
 */
bool SslUnsafeSocketPrivate::isMatchingHostname(const QString &cn, const QString &hostname)
{
    int wildcard = cn.indexOf(QLatin1Char('*'));

    // Check this is a wildcard cert, if not then just compare the strings
    if (wildcard < 0)
        return QLatin1String(QUrl::toAce(cn)) == hostname;

    int firstCnDot = cn.indexOf(QLatin1Char('.'));
    int secondCnDot = cn.indexOf(QLatin1Char('.'), firstCnDot+1);

    // Check at least 3 components
    if ((-1 == secondCnDot) || (secondCnDot+1 >= cn.length()))
        return false;

    // Check * is last character of 1st component (ie. there's a following .)
    if (wildcard+1 != firstCnDot)
        return false;

    // Check only one star
    if (cn.lastIndexOf(QLatin1Char('*')) != wildcard)
        return false;

    // Reject wildcard character embedded within the A-labels or U-labels of an internationalized
    // domain name (RFC6125 section 7.2)
    if (cn.startsWith(QLatin1String("xn--"), Qt::CaseInsensitive))
        return false;

    // Check characters preceding * (if any) match
    if (wildcard && hostname.leftRef(wildcard).compare(cn.leftRef(wildcard), Qt::CaseInsensitive) != 0)
        return false;

    // Check characters following first . match
    int hnDot = hostname.indexOf(QLatin1Char('.'));
    if (hostname.midRef(hnDot + 1) != cn.midRef(firstCnDot + 1)
        && hostname.midRef(hnDot + 1) != QLatin1String(QUrl::toAce(cn.mid(firstCnDot + 1)))) {
        return false;
    }

    // Check if the hostname is an IP address, if so then wildcards are not allowed
    QHostAddress addr(hostname);
    if (!addr.isNull())
        return false;

    // Ok, I guess this was a wildcard CN and the hostname matches.
    return true;
}

void SslUnsafeSocketPrivate::setError(QAbstractSocket::SocketError errorCode,
                                      const QString &errStr)
{
    Q_Q(SslUnsafeSocket);
    socketError = errorCode;
    q->setErrorString(errStr);
}

void SslUnsafeSocketPrivate::setErrorAndEmit(QAbstractSocket::SocketError errorCode,
                                             const QString &errorString)
{
    Q_Q(SslUnsafeSocket);
    setError(errorCode, errorString);
    emit q->error(errorCode);
}

#include "moc_sslunsafesocket.cpp"
