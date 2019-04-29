/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Copyright (C) 2014 BlackBerry Limited. All rights reserved.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/


//#define SSLUNSAFESOCKET_DEBUG

/*!
    \class SslUnsafeSocket
    \brief The SslUnsafeSocket class provides an SSL encrypted socket for both
    clients and servers.
    \since 4.3

    \reentrant
    \ingroup network
    \ingroup ssl
    \inmodule QtNetwork

    SslUnsafeSocket establishes a secure, encrypted TCP connection you can
    use for transmitting encrypted data. It can operate in both client
    and server mode, and it supports modern SSL protocols, including
    SSL 3 and TLS 1.2. By default, SslUnsafeSocket uses only SSL protocols
    which are considered to be secure (SslUnsafe::SecureProtocols), but you can
    change the SSL protocol by calling setProtocol() as long as you do
    it before the handshake has started.

    SSL encryption operates on top of the existing TCP stream after
    the socket enters the ConnectedState. There are two simple ways to
    establish a secure connection using SslUnsafeSocket: With an immediate
    SSL handshake, or with a delayed SSL handshake occurring after the
    connection has been established in unencrypted mode.

    The most common way to use SslUnsafeSocket is to construct an object
    and start a secure connection by calling connectToHostEncrypted().
    This method starts an immediate SSL handshake once the connection
    has been established.

    \snippet code/src_network_ssl_qsslsocket.cpp 0

    As with a plain QTcpSocket, SslUnsafeSocket enters the HostLookupState,
    ConnectingState, and finally the ConnectedState, if the connection
    is successful. The handshake then starts automatically, and if it
    succeeds, the encrypted() signal is emitted to indicate the socket
    has entered the encrypted state and is ready for use.

    Note that data can be written to the socket immediately after the
    return from connectToHostEncrypted() (i.e., before the encrypted()
    signal is emitted). The data is queued in SslUnsafeSocket until after
    the encrypted() signal is emitted.

    An example of using the delayed SSL handshake to secure an
    existing connection is the case where an SSL server secures an
    incoming connection. Suppose you create an SSL server class as a
    subclass of QTcpServer. You would override
    QTcpServer::incomingConnection() with something like the example
    below, which first constructs an instance of SslUnsafeSocket and then
    calls setSocketDescriptor() to set the new socket's descriptor to
    the existing one passed in. It then initiates the SSL handshake
    by calling startServerEncryption().

    \snippet code/src_network_ssl_qsslsocket.cpp 1

    If an error occurs, SslUnsafeSocket emits the sslErrors() signal. In this
    case, if no action is taken to ignore the error(s), the connection
    is dropped. To continue, despite the occurrence of an error, you
    can call ignoreSslErrors(), either from within this slot after the
    error occurs, or any time after construction of the SslUnsafeSocket and
    before the connection is attempted. This will allow SslUnsafeSocket to
    ignore the errors it encounters when establishing the identity of
    the peer. Ignoring errors during an SSL handshake should be used
    with caution, since a fundamental characteristic of secure
    connections is that they should be established with a successful
    handshake.

    Once encrypted, you use SslUnsafeSocket as a regular QTcpSocket. When
    readyRead() is emitted, you can call read(), canReadLine() and
    readLine(), or getChar() to read decrypted data from SslUnsafeSocket's
    internal buffer, and you can call write() or putChar() to write
    data back to the peer. SslUnsafeSocket will automatically encrypt the
    written data for you, and emit encryptedBytesWritten() once
    the data has been written to the peer.

    As a convenience, SslUnsafeSocket supports QTcpSocket's blocking
    functions waitForConnected(), waitForReadyRead(),
    waitForBytesWritten(), and waitForDisconnected(). It also provides
    waitForEncrypted(), which will block the calling thread until an
    encrypted connection has been established.

    \snippet code/src_network_ssl_qsslsocket.cpp 2

    SslUnsafeSocket provides an extensive, easy-to-use API for handling
    cryptographic ciphers, private keys, and local, peer, and
    Certification Authority (CA) certificates. It also provides an API
    for handling errors that occur during the handshake phase.

    The following features can also be customized:

    \list
    \li The socket's cryptographic cipher suite can be customized before
    the handshake phase with setCiphers() and setDefaultCiphers().
    \li The socket's local certificate and private key can be customized
    before the handshake phase with setLocalCertificate() and
    setPrivateKey().
    \li The CA certificate database can be extended and customized with
    addCaCertificate(), addCaCertificates(), addDefaultCaCertificate(),
    addDefaultCaCertificates(), and SslUnsafeConfiguration::defaultConfiguration().setCaCertificates().
    \endlist

    \note If available, root certificates on Unix (excluding \macos) will be
    loaded on demand from the standard certificate directories. If you do not
    want to load root certificates on demand, you need to call either
    SslUnsafeConfiguration::defaultConfiguration().setCaCertificates() before the first
    SSL handshake is made in your application (for example, via passing
    SslUnsafeSocket::systemCaCertificates() to it), or call
    SslUnsafeConfiguration::defaultConfiguration()::setCaCertificates() on your SslUnsafeSocket instance
    prior to the SSL handshake.

    For more information about ciphers and certificates, refer to SslUnsafeCipher and
    SslUnsafeCertificate.

    This product includes software developed by the OpenSSL Project
    for use in the OpenSSL Toolkit (\l{http://www.openssl.org/}).

    \note Be aware of the difference between the bytesWritten() signal and
    the encryptedBytesWritten() signal. For a QTcpSocket, bytesWritten()
    will get emitted as soon as data has been written to the TCP socket.
    For a SslUnsafeSocket, bytesWritten() will get emitted when the data
    is being encrypted and encryptedBytesWritten()
    will get emitted as soon as data has been written to the TCP socket.

    \sa SslUnsafeCertificate, SslUnsafeCipher, SslUnsafeError
*/

/*!
    \enum SslUnsafeSocket::SslMode

    Describes the connection modes available for SslUnsafeSocket.

    \value UnencryptedMode The socket is unencrypted. Its
    behavior is identical to QTcpSocket.

    \value SslClientMode The socket is a client-side SSL socket.
    It is either alreayd encrypted, or it is in the SSL handshake
    phase (see SslUnsafeSocket::isEncrypted()).

    \value SslServerMode The socket is a server-side SSL socket.
    It is either already encrypted, or it is in the SSL handshake
    phase (see SslUnsafeSocket::isEncrypted()).
*/

/*!
    \enum SslUnsafeSocket::PeerVerifyMode
    \since 4.4

    Describes the peer verification modes for SslUnsafeSocket. The default mode is
    AutoVerifyPeer, which selects an appropriate mode depending on the
    socket's QSocket::SslMode.

    \value VerifyNone SslUnsafeSocket will not request a certificate from the
    peer. You can set this mode if you are not interested in the identity of
    the other side of the connection. The connection will still be encrypted,
    and your socket will still send its local certificate to the peer if it's
    requested.

    \value QueryPeer SslUnsafeSocket will request a certificate from the peer, but
    does not require this certificate to be valid. This is useful when you
    want to display peer certificate details to the user without affecting the
    actual SSL handshake. This mode is the default for servers.

    \value VerifyPeer SslUnsafeSocket will request a certificate from the peer
    during the SSL handshake phase, and requires that this certificate is
    valid. On failure, SslUnsafeSocket will emit the SslUnsafeSocket::sslErrors()
    signal. This mode is the default for clients.

    \value AutoVerifyPeer SslUnsafeSocket will automatically use QueryPeer for
    server sockets and VerifyPeer for client sockets.

    \sa SslUnsafeSocket::peerVerifyMode()
*/

/*!
    \fn void SslUnsafeSocket::encrypted()

    This signal is emitted when SslUnsafeSocket enters encrypted mode. After this
    signal has been emitted, SslUnsafeSocket::isEncrypted() will return true, and
    all further transmissions on the socket will be encrypted.

    \sa SslUnsafeSocket::connectToHostEncrypted(), SslUnsafeSocket::isEncrypted()
*/

/*!
    \fn void SslUnsafeSocket::modeChanged(SslUnsafeSocket::SslMode mode)

    This signal is emitted when SslUnsafeSocket changes from \l
    SslUnsafeSocket::UnencryptedMode to either \l SslUnsafeSocket::SslClientMode or \l
    SslUnsafeSocket::SslServerMode. \a mode is the new mode.

    \sa SslUnsafeSocket::mode()
*/

/*!
    \fn void SslUnsafeSocket::encryptedBytesWritten(qint64 written)
    \since 4.4

    This signal is emitted when SslUnsafeSocket writes its encrypted data to the
    network. The \a written parameter contains the number of bytes that were
    successfully written.

    \sa QIODevice::bytesWritten()
*/

/*!
    \fn void SslUnsafeSocket::peerVerifyError(const SslUnsafeError &error)
    \since 4.4

    SslUnsafeSocket can emit this signal several times during the SSL handshake,
    before encryption has been established, to indicate that an error has
    occurred while establishing the identity of the peer. The \a error is
    usually an indication that SslUnsafeSocket is unable to securely identify the
    peer.

    This signal provides you with an early indication when something's wrong.
    By connecting to this signal, you can manually choose to tear down the
    connection from inside the connected slot before the handshake has
    completed. If no action is taken, SslUnsafeSocket will proceed to emitting
    SslUnsafeSocket::sslErrors().

    \sa sslErrors()
*/

/*!
    \fn void SslUnsafeSocket::sslErrors(const QList<SslUnsafeError> &errors);

    SslUnsafeSocket emits this signal after the SSL handshake to indicate that one
    or more errors have occurred while establishing the identity of the
    peer. The errors are usually an indication that SslUnsafeSocket is unable to
    securely identify the peer. Unless any action is taken, the connection
    will be dropped after this signal has been emitted.

    If you want to continue connecting despite the errors that have occurred,
    you must call SslUnsafeSocket::ignoreSslErrors() from inside a slot connected to
    this signal. If you need to access the error list at a later point, you
    can call sslErrors() (without arguments).

    \a errors contains one or more errors that prevent SslUnsafeSocket from
    verifying the identity of the peer.

    \note You cannot use Qt::QueuedConnection when connecting to this signal,
    or calling SslUnsafeSocket::ignoreSslErrors() will have no effect.

    \sa peerVerifyError()
*/

/*!
    \fn void SslUnsafeSocket::preSharedKeyAuthenticationRequired(SslUnsafePreSharedKeyAuthenticator *authenticator)
    \since 5.5

    SslUnsafeSocket emits this signal when it negotiates a PSK ciphersuite, and
    therefore a PSK authentication is then required.

    When using PSK, the client must send to the server a valid identity and a
    valid pre shared key, in order for the SSL handshake to continue.
    Applications can provide this information in a slot connected to this
    signal, by filling in the passed \a authenticator object according to their
    needs.

    \note Ignoring this signal, or failing to provide the required credentials,
    will cause the handshake to fail, and therefore the connection to be aborted.

    \note The \a authenticator object is owned by the socket and must not be
    deleted by the application.

    \sa SslUnsafePreSharedKeyAuthenticator
*/

#include "sslunsafe_p.h"
#include "sslunsafesocket.h"
#include "sslunsafecipher.h"
#ifndef QT_NO_OPENSSL
#include "sslunsafesocket_openssl_p.h"
#endif
#ifdef Q_OS_WINRT
#include "sslunsafesocket_winrt_p.h"
#endif
#ifdef QT_SECURETRANSPORT
#include "sslunsafesocket_mac_p.h"
#endif
#include "sslunsafeconfiguration_p.h"

#include <QtCore/qdebug.h>
#include <QtCore/qdir.h>
#include <QtCore/qmutex.h>
#include <QtCore/qurl.h>
#include <QtCore/qelapsedtimer.h>
#include <QtNetwork/qhostaddress.h>
#include <QtNetwork/qhostinfo.h>
#include <QNetworkProxy>

QT_BEGIN_NAMESPACE

class SslUnsafeSocketGlobalData
{
public:
    SslUnsafeSocketGlobalData()
        : config(new SslUnsafeConfigurationPrivate),
          dtlsConfig(new SslUnsafeConfigurationPrivate)
    {
#if 1 // QT_CONFIG(dtls)
        dtlsConfig->protocol = SslUnsafe::DtlsV1_2OrLater;
#endif // dtls
    }

    QMutex mutex;
    QList<SslUnsafeCipher> supportedCiphers;
    QVector<SslUnsafeEllipticCurve> supportedEllipticCurves;
    QExplicitlySharedDataPointer<SslUnsafeConfigurationPrivate> config;
    QExplicitlySharedDataPointer<SslUnsafeConfigurationPrivate> dtlsConfig;
};
Q_GLOBAL_STATIC(SslUnsafeSocketGlobalData, globalData)

/*!
    Constructs a SslUnsafeSocket object. \a parent is passed to QObject's
    constructor. The new socket's \l {SslUnsafeCipher} {cipher} suite is
    set to the one returned by the static method defaultCiphers().
*/
SslUnsafeSocket::SslUnsafeSocket(QObject *parent)
    : QTcpSocket(parent),
      d_ptr(new SslUnsafeSocketBackendPrivate)
{
    Q_D(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qCDebug(lcSsl) << "SslUnsafeSocket::SslUnsafeSocket(" << parent << "), this =" << (void *)this;
#endif
    d->q_ptr = this;
    d->init();
}

/*!
    Destroys the SslUnsafeSocket.
*/
SslUnsafeSocket::~SslUnsafeSocket()
{
    Q_D(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qCDebug(lcSsl) << "SslUnsafeSocket::~SslUnsafeSocket(), this =" << (void *)this;
#endif
    delete d->plainSocket;
    d->plainSocket = nullptr;
}

/*!
    \reimp

    \since 5.0

    Continues data transfer on the socket after it has been paused. If
    "setPauseMode(QAbstractSocket::PauseOnSslErrors);" has been called on
    this socket and a sslErrors() signal is received, calling this method
    is necessary for the socket to continue.

    \sa QAbstractSocket::pauseMode(), QAbstractSocket::setPauseMode()
*/
void SslUnsafeSocket::resume()
{
    Q_D(SslUnsafeSocket);
    if (!d->paused)
        return;
    // continuing might emit signals, rather do this through the event loop
    QMetaObject::invokeMethod(this, "_q_resumeImplementation", Qt::QueuedConnection);
}

/*!
    Starts an encrypted connection to the device \a hostName on \a
    port, using \a mode as the \l OpenMode. This is equivalent to
    calling connectToHost() to establish the connection, followed by a
    call to startClientEncryption(). The \a protocol parameter can be
    used to specify which network protocol to use (eg. IPv4 or IPv6).

    SslUnsafeSocket first enters the HostLookupState. Then, after entering
    either the event loop or one of the waitFor...() functions, it
    enters the ConnectingState, emits connected(), and then initiates
    the SSL client handshake. At each state change, SslUnsafeSocket emits
    signal stateChanged().

    After initiating the SSL client handshake, if the identity of the
    peer can't be established, signal sslErrors() is emitted. If you
    want to ignore the errors and continue connecting, you must call
    ignoreSslErrors(), either from inside a slot function connected to
    the sslErrors() signal, or prior to entering encrypted mode. If
    ignoreSslErrors() is not called, the connection is dropped, signal
    disconnected() is emitted, and SslUnsafeSocket returns to the
    UnconnectedState.

    If the SSL handshake is successful, SslUnsafeSocket emits encrypted().

    \snippet code/src_network_ssl_qsslsocket.cpp 3

    \note The example above shows that text can be written to
    the socket immediately after requesting the encrypted connection,
    before the encrypted() signal has been emitted. In such cases, the
    text is queued in the object and written to the socket \e after
    the connection is established and the encrypted() signal has been
    emitted.

    The default for \a mode is \l ReadWrite.

    If you want to create a SslUnsafeSocket on the server side of a connection, you
    should instead call startServerEncryption() upon receiving the incoming
    connection through QTcpServer.

    \sa connectToHost(), startClientEncryption(), waitForConnected(), waitForEncrypted()
*/
void SslUnsafeSocket::connectToHostEncrypted(const QString &hostName, quint16 port, OpenMode mode, NetworkLayerProtocol protocol)
{
    Q_D(SslUnsafeSocket);
    if (d->state() == ConnectedState || d->state() == ConnectingState) {
        qCWarning(lcSsl,
                  "SslUnsafeSocket::connectToHostEncrypted() called when already connecting/connected");
        return;
    }

    if (!supportsSsl()) {
        qCWarning(lcSsl, "SslUnsafeSocket::connectToHostEncrypted: TLS initialization failed");
        d->setErrorAndEmit(QAbstractSocket::SslInternalError, tr("TLS initialization failed"));
        return;
    }

    d->init();
    d->autoStartHandshake = true;
    d->initialized = true;

    // Note: When connecting to localhost, some platforms (e.g., HP-UX and some BSDs)
    // establish the connection immediately (i.e., first attempt).
    connectToHost(hostName, port, mode, protocol);
}

/*!
    \since 4.6
    \overload

    In addition to the original behaviour of connectToHostEncrypted,
    this overloaded method enables the usage of a different hostname
    (\a sslPeerName) for the certificate validation instead of
    the one used for the TCP connection (\a hostName).

    \sa connectToHostEncrypted()
*/
void SslUnsafeSocket::connectToHostEncrypted(const QString &hostName, quint16 port,
                                        const QString &sslPeerName, OpenMode mode,
                                        NetworkLayerProtocol protocol)
{
    Q_D(SslUnsafeSocket);
    if (d->state() == ConnectedState || d->state() == ConnectingState) {
        qCWarning(lcSsl,
                  "SslUnsafeSocket::connectToHostEncrypted() called when already connecting/connected");
        return;
    }

    if (!supportsSsl()) {
        qCWarning(lcSsl, "SslUnsafeSocket::connectToHostEncrypted: TLS initialization failed");
        d->setErrorAndEmit(QAbstractSocket::SslInternalError, tr("TLS initialization failed"));
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

/*!
    Initializes SslUnsafeSocket with the native socket descriptor \a
    socketDescriptor. Returns \c true if \a socketDescriptor is accepted
    as a valid socket descriptor; otherwise returns \c false.
    The socket is opened in the mode specified by \a openMode, and
    enters the socket state specified by \a state.

    \note It is not possible to initialize two sockets with the same
    native socket descriptor.

    \sa socketDescriptor()
*/
bool SslUnsafeSocket::setSocketDescriptor(qintptr socketDescriptor, SocketState state, OpenMode openMode)
{
    Q_D(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qCDebug(lcSsl) << "SslUnsafeSocket::setSocketDescriptor(" << socketDescriptor << ','
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
    // d->readChannelCount = d->plainSocket->readChannelCount();
    // d->writeChannelCount = d->plainSocket->writeChannelCount();
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
    Returns the socket's SSL protocol. By default, \l SslUnsafe::SecureProtocols is used.

    \sa setProtocol()
*/
SslUnsafe::SslProtocol SslUnsafeSocket::protocol() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.protocol;
}

/*!
    Sets the socket's SSL protocol to \a protocol. This will affect the next
    initiated handshake; calling this function on an already-encrypted socket
    will not affect the socket's protocol.
*/
void SslUnsafeSocket::setProtocol(SslUnsafe::SslProtocol protocol)
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
        qCWarning(lcSsl, "SslUnsafeSocket::setPeerVerifyDepth: cannot set negative depth of %d", depth);
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
    qCDebug(lcSsl) << "SslUnsafeSocket::close()";
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

    // do not clear raw*Buffer as we need them even after connection was closed
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
bool SslUnsafeSocket::flush()
{
    return d_func()->flush();
}

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
    qCDebug(lcSsl) << "SslUnsafeSocket::abort()";
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
    copy->ref.store(0);              // the SslUnsafeConfiguration constructor refs up
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
    d->configuration.backendConfig = configuration.backendConfiguration();
    d->configuration.sslOptions = configuration.d->sslOptions;
    d->configuration.sslSession = configuration.sessionTicket();
    d->configuration.sslSessionTicketLifeTimeHint = configuration.sessionTicketLifeTimeHint();
    d->configuration.nextAllowedProtocols = configuration.allowedNextProtocols();
    d->configuration.nextNegotiatedProtocol = configuration.nextNegotiatedProtocol();
    d->configuration.nextProtocolNegotiationStatus = configuration.nextProtocolNegotiationStatus();

    // if the CA certificates were set explicitly (either via
    // SslUnsafeConfiguration::setCaCertificates() or SslUnsafeSocket::setCaCertificates(),
    // we cannot load the certificates on demand
    if (!configuration.d->allowRootCertOnDemandLoading)
        d->allowRootCertOnDemandLoading = false;
}

/*!
    Sets the certificate chain to be presented to the peer during the
    SSL handshake to be \a localChain.

    \sa SslUnsafeConfiguration::setLocalCertificateChain()
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
                                     SslUnsafe::EncodingFormat format)
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
SslUnsafe::SslProtocol SslUnsafeSocket::sessionProtocol() const
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
void SslUnsafeSocket::setPrivateKey(const QString &fileName, SslUnsafe::KeyAlgorithm algorithm,
                               SslUnsafe::EncodingFormat format, const QByteArray &passPhrase)
{
    Q_D(SslUnsafeSocket);
    QFile file(fileName);
    if (file.open(QIODevice::ReadOnly)) {
        d->configuration.privateKey = SslUnsafeKey(file.readAll(), algorithm,
                                              format, SslUnsafe::PrivateKey, passPhrase);
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
    \deprecated

    Use SslUnsafeConfiguration::ciphers() instead.

    Returns this socket's current cryptographic cipher suite. This
    list is used during the socket's handshake phase for choosing a
    session cipher. The returned list of ciphers is ordered by
    descending preference. (i.e., the first cipher in the list is the
    most preferred cipher). The session cipher will be the first one
    in the list that is also supported by the peer.

    By default, the handshake phase can choose any of the ciphers
    supported by this system's SSL libraries, which may vary from
    system to system. The list of ciphers supported by this system's
    SSL libraries is returned by supportedCiphers(). You can restrict
    the list of ciphers used for choosing the session cipher for this
    socket by calling setCiphers() with a subset of the supported
    ciphers. You can revert to using the entire set by calling
    setCiphers() with the list returned by supportedCiphers().

    You can restrict the list of ciphers used for choosing the session
    cipher for \e all sockets by calling setDefaultCiphers() with a
    subset of the supported ciphers. You can revert to using the
    entire set by calling setCiphers() with the list returned by
    supportedCiphers().

    \sa setCiphers(), defaultCiphers(), setDefaultCiphers(), supportedCiphers()
*/
QList<SslUnsafeCipher> SslUnsafeSocket::ciphers() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.ciphers;
}

/*!
    \deprecated

    USe SslUnsafeConfiguration::setCiphers() instead.

    Sets the cryptographic cipher suite for this socket to \a ciphers,
    which must contain a subset of the ciphers in the list returned by
    supportedCiphers().

    Restricting the cipher suite must be done before the handshake
    phase, where the session cipher is chosen.

    \sa ciphers(), setDefaultCiphers(), supportedCiphers()
*/
void SslUnsafeSocket::setCiphers(const QList<SslUnsafeCipher> &ciphers)
{
    Q_D(SslUnsafeSocket);
    d->configuration.ciphers = ciphers;
}

/*!
    \deprecated

    Use SslUnsafeConfiguration::setCiphers() instead.

    Sets the cryptographic cipher suite for this socket to \a ciphers, which
    is a colon-separated list of cipher suite names. The ciphers are listed in
    order of preference, starting with the most preferred cipher. For example:

    \snippet code/src_network_ssl_qsslsocket.cpp 4

    Each cipher name in \a ciphers must be the name of a cipher in the
    list returned by supportedCiphers().  Restricting the cipher suite
    must be done before the handshake phase, where the session cipher
    is chosen.

    \sa ciphers(), setDefaultCiphers(), supportedCiphers()
*/
void SslUnsafeSocket::setCiphers(const QString &ciphers)
{
    Q_D(SslUnsafeSocket);
    d->configuration.ciphers.clear();
    const auto cipherNames = ciphers.split(QLatin1Char(':'), QString::SkipEmptyParts);
    for (const QString &cipherName : cipherNames) {
        SslUnsafeCipher cipher(cipherName);
        if (!cipher.isNull())
            d->configuration.ciphers << cipher;
    }
}

/*!
    \deprecated

    Use SslUnsafeConfiguration::setCiphers() on the default SslUnsafeConfiguration instead.

    Sets the default cryptographic cipher suite for all sockets in
    this application to \a ciphers, which must contain a subset of the
    ciphers in the list returned by supportedCiphers().

    Restricting the default cipher suite only affects SSL sockets
    that perform their handshake phase after the default cipher
    suite has been changed.

    \sa setCiphers(), defaultCiphers(), supportedCiphers()
*/
void SslUnsafeSocket::setDefaultCiphers(const QList<SslUnsafeCipher> &ciphers)
{
    SslUnsafeSocketPrivate::setDefaultCiphers(ciphers);
}

/*!
    \deprecated

    Use SslUnsafeConfiguration::ciphers() on the default SslUnsafeConfiguration instead.

    Returns the default cryptographic cipher suite for all sockets in
    this application. This list is used during the socket's handshake
    phase when negotiating with the peer to choose a session cipher.
    The list is ordered by preference (i.e., the first cipher in the
    list is the most preferred cipher).

    By default, the handshake phase can choose any of the ciphers
    supported by this system's SSL libraries, which may vary from
    system to system. The list of ciphers supported by this system's
    SSL libraries is returned by supportedCiphers().

    \sa supportedCiphers()
*/
QList<SslUnsafeCipher> SslUnsafeSocket::defaultCiphers()
{
    return SslUnsafeSocketPrivate::defaultCiphers();
}

/*!
    \deprecated

    Use SslUnsafeConfiguration::supportedCiphers() instead.

    Returns the list of cryptographic ciphers supported by this
    system. This list is set by the system's SSL libraries and may
    vary from system to system.

    \sa defaultCiphers(), ciphers(), setCiphers()
*/
QList<SslUnsafeCipher> SslUnsafeSocket::supportedCiphers()
{
    return SslUnsafeSocketPrivate::supportedCiphers();
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
bool SslUnsafeSocket::addCaCertificates(const QString &path, SslUnsafe::EncodingFormat format,
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
  \deprecated

  Use SslUnsafeConfiguration::setCaCertificates() instead.

  Sets this socket's CA certificate database to be \a certificates.
  The certificate database must be set prior to the SSL handshake.
  The CA certificate database is used by the socket during the
  handshake phase to validate the peer's certificate.

  The CA certificate database can be reset to the current default CA
  certificate database by calling this function with the list of CA
  certificates returned by defaultCaCertificates().

  \sa defaultCaCertificates()
*/
void SslUnsafeSocket::setCaCertificates(const QList<SslUnsafeCertificate> &certificates)
{
    Q_D(SslUnsafeSocket);
    d->configuration.caCertificates = certificates;
    d->allowRootCertOnDemandLoading = false;
}

/*!
  \deprecated

  Use SslUnsafeConfiguration::caCertificates() instead.

  Returns this socket's CA certificate database. The CA certificate
  database is used by the socket during the handshake phase to
  validate the peer's certificate. It can be moodified prior to the
  handshake with addCaCertificate(), addCaCertificates(), and
  setCaCertificates().

  \note On Unix, this method may return an empty list if the root
  certificates are loaded on demand.

  \sa addCaCertificate(), addCaCertificates(), setCaCertificates()
*/
QList<SslUnsafeCertificate> SslUnsafeSocket::caCertificates() const
{
    Q_D(const SslUnsafeSocket);
    return d->configuration.caCertificates;
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
bool SslUnsafeSocket::addDefaultCaCertificates(const QString &path, SslUnsafe::EncodingFormat encoding,
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
    \deprecated

    Use SslUnsafeConfiguration::setCaCertificates() on the default SslUnsafeConfiguration instead.

    Sets the default CA certificate database to \a certificates. The
    default CA certificate database is originally set to your system's
    default CA certificate database. You can override the default CA
    certificate database with your own CA certificate database using
    this function.

    Each SSL socket's CA certificate database is initialized to the
    default CA certificate database.

    \sa addDefaultCaCertificate()
*/
void SslUnsafeSocket::setDefaultCaCertificates(const QList<SslUnsafeCertificate> &certificates)
{
    SslUnsafeSocketPrivate::setDefaultCaCertificates(certificates);
}

/*!
    \deprecated

    Use SslUnsafeConfiguration::caCertificates() on the default SslUnsafeConfiguration instead.

    Returns the current default CA certificate database. This database
    is originally set to your system's default CA certificate database.
    If no system default database is found, an empty database will be
    returned. You can override the default CA certificate database
    with your own CA certificate database using setDefaultCaCertificates().

    Each SSL socket's CA certificate database is initialized to the
    default CA certificate database.

    \note On Unix, this method may return an empty list if the root
    certificates are loaded on demand.

    \sa caCertificates()
*/
QList<SslUnsafeCertificate> SslUnsafeSocket::defaultCaCertificates()
{
    return SslUnsafeSocketPrivate::defaultCaCertificates();
}

/*!
    \deprecated

    Use SslUnsafeConfiguration::systemDefaultCaCertificates instead.

    This function provides the CA certificate database
    provided by the operating system. The CA certificate database
    returned by this function is used to initialize the database
    returned by defaultCaCertificates(). You can replace that database
    with your own with setDefaultCaCertificates().

    \note: On OS X, only certificates that are either trusted for all
    purposes or trusted for the purpose of SSL in the keychain will be
    returned.

    \sa caCertificates(), defaultCaCertificates(), setDefaultCaCertificates()
*/
QList<SslUnsafeCertificate> SslUnsafeSocket::systemCaCertificates()
{
    // we are calling ensureInitialized() in the method below
    return SslUnsafeSocketPrivate::systemCaCertificates();
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

    \snippet code/src_network_ssl_qsslsocket.cpp 5

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
        qCWarning(lcSsl, "SslUnsafeSocket::waitForDisconnected() is not allowed in UnconnectedState");
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
        qCWarning(lcSsl,
                  "SslUnsafeSocket::startClientEncryption: cannot start handshake on non-plain connection");
        return;
    }
    if (state() != ConnectedState) {
        qCWarning(lcSsl,
                  "SslUnsafeSocket::startClientEncryption: cannot start handshake when not connected");
        return;
    }

    if (!supportsSsl()) {
        qCWarning(lcSsl, "SslUnsafeSocket::startClientEncryption: TLS initialization failed");
        d->setErrorAndEmit(QAbstractSocket::SslInternalError, tr("TLS initialization failed"));
        return;
    }
#ifdef SSLUNSAFESOCKET_DEBUG
    qCDebug(lcSsl) << "SslUnsafeSocket::startClientEncryption()";
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
        qCWarning(lcSsl, "SslUnsafeSocket::startServerEncryption: cannot start handshake on non-plain connection");
        return;
    }
#ifdef SSLUNSAFESOCKET_DEBUG
    qCDebug(lcSsl) << "SslUnsafeSocket::startServerEncryption()";
#endif
    if (!supportsSsl()) {
        qCWarning(lcSsl, "SslUnsafeSocket::startServerEncryption: TLS initialization failed");
        d->setErrorAndEmit(QAbstractSocket::SslInternalError, tr("TLS initialization failed"));
        return;
    }
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

    \snippet code/src_network_ssl_qsslsocket.cpp 6

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
    qCDebug(lcSsl) << "SslUnsafeSocket::connectToHost("
             << hostName << ',' << port << ',' << openMode << ')';
#endif
    if (!d->plainSocket) {
#ifdef SSLUNSAFESOCKET_DEBUG
        qCDebug(lcSsl) << "\tcreating internal plain socket";
#endif
        d->createPlainSocket(openMode);
    }
#ifndef QT_NO_NETWORKPROXY
    d->plainSocket->setProxy(proxy());
#endif
    QIODevice::open(openMode);
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
    qCDebug(lcSsl) << "SslUnsafeSocket::disconnectFromHost()";
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
        d->rawReadBuffer.append(data, readBytes);
#ifdef SSLUNSAFESOCKET_DEBUG
        qCDebug(lcSsl) << "SslUnsafeSocket::readData(" << (void *)data << ',' << maxlen << ") =="
                 << readBytes;
#endif
    } else {
        // possibly trigger another transmit() to decrypt more data from the socket
        if (d->plainSocket->bytesAvailable()) {
            QMetaObject::invokeMethod(this, "_q_flushReadBuffer", Qt::QueuedConnection);
        } else {
            readBytes = d->buffer.read(data, maxlen);
            // do not append this data to raw buffer, it will be handled in transmit()
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
    qCDebug(lcSsl) << "SslUnsafeSocket::writeData(" << (void *)data << ',' << len << ')';
#endif
    if (d->mode == UnencryptedMode && !d->autoStartHandshake) {
        d->rawWriteBuffer.append(data, len);
        return d->plainSocket->write(data, len);
    }

    d->writeBuffer.append(data, len);
    // do not append this data to raw buffer as it will be handled later in transmit()

    // make sure we flush to the plain socket's buffer
    if (!d->flushTriggered) {
        d->flushTriggered = true;
        QMetaObject::invokeMethod(this, "_q_flushWriteBuffer", Qt::QueuedConnection);
    }

    return len;
}

QByteArray SslUnsafeSocket::getRawReadData()
{
    Q_D(SslUnsafeSocket);
    return d->rawReadBuffer;
}

QByteArray SslUnsafeSocket::getRawWrittenData()
{
    Q_D(SslUnsafeSocket);
    return d->rawWriteBuffer;
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
    , readyReadEmittedPointer(nullptr)
    , allowRootCertOnDemandLoading(true)
    , plainSocket(nullptr)
    , paused(false)
    , flushTriggered(false)
{
    SslUnsafeConfigurationPrivate::deepCopyDefaultConfiguration(&configuration);

    readBuffers << SslUnsafeRingBuffer();
    writeBuffers << SslUnsafeRingBuffer();

    buffer.m_buf = &readBuffers[0];
    writeBuffer.m_buf = &writeBuffers[0];

    transactionPos = 0;
    readBufferMaxSize = 0;
    emittedBytesWritten = false;
    pendingClose = false;
    cachedSocketDescriptor = -1;
    readBufferMaxSize = 0;
    socketError = QAbstractSocket::UnknownSocketError;
    preferredNetworkLayerProtocol = QAbstractSocket::UnknownNetworkLayerProtocol;
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
    flushTriggered = false;

    // we don't want to clear the ignoreErrorsList, so
    // that it is possible setting it before connecting
//    ignoreErrorsList.clear();

    buffer.clear();
    writeBuffer.clear();
    configuration.peerCertificate.clear();
    configuration.peerCertificateChain.clear();

    rawReadBuffer.clear();
    rawWriteBuffer.clear();
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
void q_setDefaultDtlsCiphers(const QList<SslUnsafeCipher> &ciphers)
{
    QMutexLocker locker(&globalData()->mutex);
    globalData()->dtlsConfig.detach();
    globalData()->dtlsConfig->ciphers = ciphers;
}

/*!
    \internal
*/
QList<SslUnsafeCipher> q_getDefaultDtlsCiphers()
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    return globalData()->dtlsConfig->ciphers;
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
    globalData()->dtlsConfig.detach();
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
    globalData()->dtlsConfig.detach();
    globalData()->dtlsConfig->caCertificates = certs;
    // when the certificates are set explicitly, we do not want to
    // load the system certificates on demand
    s_loadRootCertsOnDemand = false;
}

/*!
    \internal
*/
bool SslUnsafeSocketPrivate::addDefaultCaCertificates(const QString &path, SslUnsafe::EncodingFormat format,
                                                 QRegExp::PatternSyntax syntax)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QList<SslUnsafeCertificate> certs = SslUnsafeCertificate::fromPath(path, format, syntax);
    if (certs.isEmpty())
        return false;

    QMutexLocker locker(&globalData()->mutex);
    globalData()->config.detach();
    globalData()->config->caCertificates += certs;
    globalData()->dtlsConfig.detach();
    globalData()->dtlsConfig->caCertificates += certs;
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
    globalData()->dtlsConfig.detach();
    globalData()->dtlsConfig->caCertificates += cert;
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
    globalData()->dtlsConfig.detach();
    globalData()->dtlsConfig->caCertificates += certs;
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
    ptr->backendConfig = global->backendConfig;
#if 1 // QT_CONFIG(dtls)
    ptr->dtlsCookieEnabled = global->dtlsCookieEnabled;
#endif
}

/*!
    \internal
*/
SslUnsafeConfiguration SslUnsafeConfigurationPrivate::defaultDtlsConfiguration()
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);

    return SslUnsafeConfiguration(globalData()->dtlsConfig.data());
}

/*!
    \internal
*/
void SslUnsafeConfigurationPrivate::setDefaultDtlsConfiguration(const SslUnsafeConfiguration &configuration)
{
    SslUnsafeSocketPrivate::ensureInitialized();
    QMutexLocker locker(&globalData()->mutex);
    if (globalData()->dtlsConfig == configuration.d)
        return;                 // nothing to do

    globalData()->dtlsConfig = const_cast<SslUnsafeConfigurationPrivate*>(configuration.d.constData());
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
//    q->connect(plainSocket, SIGNAL(channelReadyRead(int)),
//               q, SLOT(_q_channelReadyReadSlot(int)),
//               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(bytesWritten(qint64)),
               q, SLOT(_q_bytesWrittenSlot(qint64)),
               Qt::DirectConnection);
//    q->connect(plainSocket, SIGNAL(channelBytesWritten(int,qint64)),
//               q, SLOT(_q_channelBytesWrittenSlot(int,qint64)),
//               Qt::DirectConnection);
    q->connect(plainSocket, SIGNAL(readChannelFinished()),
               q, SLOT(_q_readChannelFinishedSlot()),
               Qt::DirectConnection);
#ifndef QT_NO_NETWORKPROXY
    q->connect(plainSocket, SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)),
               q, SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)));
#endif

    buffer.clear();
    writeBuffer.clear();
    rawReadBuffer.clear();
    rawWriteBuffer.clear();
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
    qCDebug(lcSsl) << "SslUnsafeSocket::bind(" << address << ',' << port << ',' << mode << ')';
#endif
    if (!plainSocket) {
#ifdef SSLUNSAFESOCKET_DEBUG
        qCDebug(lcSsl) << "\tcreating internal plain socket";
#endif
        createPlainSocket(QIODevice::ReadWrite);
    }
    bool ret = plainSocket->bind(address, port, mode);
    setLocalPort(plainSocket->localPort());
    setLocalAddress(plainSocket->localAddress());
    cachedSocketDescriptor = plainSocket->socketDescriptor();
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

#ifdef SSLUNSAFESOCKET_DEBUG
    qCDebug(lcSsl) << "SslUnsafeSocket::_q_connectedSlot()";
    qCDebug(lcSsl) << "\tstate =" << q->state();
    qCDebug(lcSsl) << "\tpeer =" << q->peerName() << q->peerAddress() << q->peerPort();
    qCDebug(lcSsl) << "\tlocal =" << QHostInfo::fromName(q->localAddress().toString()).hostName()
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
    qCDebug(lcSsl) << "SslUnsafeSocket::_q_hostFoundSlot()";
    qCDebug(lcSsl) << "\tstate =" << q->state();
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
    qCDebug(lcSsl) << "SslUnsafeSocket::_q_disconnectedSlot()";
    qCDebug(lcSsl) << "\tstate =" << q->state();
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
    qCDebug(lcSsl) << "SslUnsafeSocket::_q_stateChangedSlot(" << state << ')';
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
    qCDebug(lcSsl) << "SslUnsafeSocket::_q_errorSlot(" << error << ')';
    qCDebug(lcSsl) << "\tstate =" << q->state();
    qCDebug(lcSsl) << "\terrorString =" << q->errorString();
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
    qCDebug(lcSsl) << "SslUnsafeSocket::_q_readyReadSlot() -" << plainSocket->bytesAvailable() << "bytes available";
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
#if 0
void SslUnsafeSocketPrivate::_q_channelReadyReadSlot(int channel)
{
    Q_Q(SslUnsafeSocket);
    if (mode == SslUnsafeSocket::UnencryptedMode)
        emit q->channelReadyRead(channel);
}
#endif

/*!
    \internal
*/
void SslUnsafeSocketPrivate::_q_bytesWrittenSlot(qint64 written)
{
    Q_Q(SslUnsafeSocket);
#ifdef SSLUNSAFESOCKET_DEBUG
    qCDebug(lcSsl) << "SslUnsafeSocket::_q_bytesWrittenSlot(" << written << ')';
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
#if 0
void SslUnsafeSocketPrivate::_q_channelBytesWrittenSlot(int channel, qint64 written)
{
    Q_Q(SslUnsafeSocket);
    if (mode == SslUnsafeSocket::UnencryptedMode)
        emit q->channelBytesWritten(channel, written);
}
#endif

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

    // need to notice if knock-on effects of this flush (e.g. a readReady() via transmit())
    // make another necessary, so clear flag before calling:
    flushTriggered = false;
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
void SslUnsafeSocketPrivate::_q_resumeImplementation()
{
    if (plainSocket)
        plainSocket->resume();
    paused = false;
    if (!connectionEncrypted) {
        if (verifyErrorsHaveBeenIgnored()) {
            continueHandshake();
        } else {
            Q_ASSERT(!sslErrors.isEmpty());
            setErrorAndEmit(QAbstractSocket::SslHandshakeFailedError, sslErrors.first().errorString());
            plainSocket->disconnectFromHost();
            return;
        }
    }
    transmit();
}

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
            rawReadBuffer.append(data, r2);
            return r + r2;
        } else {
            return -1;
        }
    } else {
        //encrypted mode - the socket engine will read and decrypt data into the QIODevice buffer
        qint64 bytes = QTcpSocket::peek(data, maxSize);
        if (bytes > 0)
            rawReadBuffer.append(data, bytes);
        return bytes;
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

#ifndef OLDQT
/*!
    \internal
*/
qint64 SslUnsafeSocketPrivate::skip(qint64 maxSize)
{
    if (mode == SslUnsafeSocket::UnencryptedMode && !autoStartHandshake)
        return plainSocket->skip(maxSize);

    // In encrypted mode, the SSL backend writes decrypted data directly into the
    // QIODevice's read buffer. As this buffer is always emptied by the caller,
    // we need to wait for more incoming data.
    return (state() == QAbstractSocket::ConnectedState) ? Q_INT64_C(0) : Q_INT64_C(-1);
}
#endif

/*!
    \internal
*/
bool SslUnsafeSocketPrivate::flush()
{
#ifdef SSLUNSAFESOCKET_DEBUG
    qCDebug(lcSsl) << "SslUnsafeSocketPrivate::flush()";
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

    foreach (const QString &altName, cert.subjectAlternativeNames().values(SslUnsafe::DnsEntry)) {
        if (isMatchingHostname(altName.toLower(), peerName.toLower())) {
            return true;
        }
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

QT_END_NAMESPACE

#include "moc_sslunsafesocket.cpp"
