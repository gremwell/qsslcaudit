/****************************************************************************
**
** Copyright (C) 2018 The Qt Company Ltd.
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

#include "sslunsafeconfiguration.h"
#include "sslunsafedtls_openssl_p.h"
#include "qudpsocket.h"
#include "sslunsafedtls_p.h"
#include "sslunsafe_p.h"
#include "sslunsafedtls.h"

#include "qglobal.h"

/*!
    \class SslUnsafeDtlsClientVerifier
    \brief This class implements server-side DTLS cookie generation and verification.
    \since 5.12

    \ingroup network
    \ingroup ssl
    \inmodule QtNetwork

    The SslUnsafeDtlsClientVerifier class implements server-side DTLS cookie generation
    and verification. Datagram security protocols are highly susceptible to a
    variety of Denial-of-Service attacks. According to \l {https://tools.ietf.org/html/rfc6347#section-4.2.1}{RFC 6347, section 4.2.1},
    these are two of the more common types of attack:

    \list
    \li An attacker transmits a series of handshake initiation requests, causing
    a server to allocate excessive resources and potentially perform expensive
    cryptographic operations.
    \li An attacker transmits a series of handshake initiation requests with
    a forged source of the victim, making the server act as an amplifier.
    Normally, the server would reply to the victim machine with a Certificate message,
    which can be quite large, thus flooding the victim machine with datagrams.
    \endlist

    As a countermeasure to these attacks, \l {https://tools.ietf.org/html/rfc6347#section-4.2.1}{RFC 6347, section 4.2.1}
    proposes a stateless cookie technique that a server may deploy:

    \list
    \li In response to the initial ClientHello message, the server sends a HelloVerifyRequest,
    which contains a cookie. This cookie is a cryptographic hash and is generated using the
    client's address, port number, and the server's secret (which is a cryptographically strong
    pseudo-random sequence of bytes).
    \li A reachable DTLS client is expected to reply with a new ClientHello message
    containing this cookie.
    \li When the server receives the ClientHello message with a cookie, it
    generates a new cookie as described above. This new cookie is compared to the
    one found in the ClientHello message.
    \li In the cookies are equal, the client is considered to be real, and the
    server can continue with a TLS handshake procedure.
    \endlist

    \note A DTLS server is not required to use DTLS cookies.

    SslUnsafeDtlsClientVerifier is designed to work in pair with QUdpSocket, as shown in
    the following code-excerpt:

    \snippet code/src_network_ssl_qdtlscookie.cpp 0

    SslUnsafeDtlsClientVerifier does not impose any restrictions on how the application uses
    QUdpSocket. For example, it is possible to have a server with a single QUdpSocket
    in state QAbstractSocket::BoundState, handling multiple DTLS clients
    simultaneously:

    \list
    \li Testing if new clients are real DTLS-capable clients.
    \li Completing TLS handshakes with the verified clients (see SslUnsafeDtls).
    \li Decrypting datagrams coming from the connected clients (see SslUnsafeDtls).
    \li Sending encrypted datagrams to the connected clients (see SslUnsafeDtls).
    \endlist

    This implies that SslUnsafeDtlsClientVerifier does not read directly from a socket,
    instead it expects the application to read an incoming datagram, extract the
    sender's address, and port, and then pass this data to verifyClient().
    To send a HelloVerifyRequest message, verifyClient() can write to the QUdpSocket.

    \note SslUnsafeDtlsClientVerifier does not take ownership of the QUdpSocket object.

    By default SslUnsafeDtlsClientVerifier obtains its secret from a cryptographically
    strong pseudorandom number generator.

    \note The default secret is shared by all objects of the classes SslUnsafeDtlsClientVerifier
    and SslUnsafeDtls. Since this can impose security risks, RFC 6347 recommends to change
    the server's secret frequently. Please see \l {https://tools.ietf.org/html/rfc6347}{RFC 6347, section 4.2.1}
    for hints about possible server implementations. Cookie generator parameters
    can be set using the class SslUnsafeDtlsClientVerifier::GeneratorParameters and
    setCookieGeneratorParameters():

    \snippet code/src_network_ssl_qdtlscookie.cpp 1

    The \l{secureudpserver}{DTLS server} example illustrates how to use
    SslUnsafeDtlsClientVerifier in a server application.

    \sa QUdpSocket, QAbstractSocket::BoundState, SslUnsafeDtls, verifyClient(),
    GeneratorParameters, setCookieGeneratorParameters(), cookieGeneratorParameters(),
    SslUnsafeDtls::setCookieGeneratorParameters(),
    SslUnsafeDtls::cookieGeneratorParameters(),
    QCryptographicHash::Algorithm,
    SslUnsafeDtlsError, dtlsError(), dtlsErrorString()
*/

/*!
    \class SslUnsafeDtlsClientVerifier::GeneratorParameters
    \brief This class defines parameters for DTLS cookie generator.
    \since 5.12

    \ingroup network
    \ingroup ssl
    \inmodule QtNetwork

    An object of this class provides the parameters that SslUnsafeDtlsClientVerifier
    will use to generate DTLS cookies. They include a cryptographic hash
    algorithm and a secret.

    \note An empty secret is considered to be invalid by
    SslUnsafeDtlsClientVerifier::setCookieGeneratorParameters().

    \sa SslUnsafeDtlsClientVerifier::setCookieGeneratorParameters(),
    SslUnsafeDtlsClientVerifier::cookieGeneratorParameters(),
    SslUnsafeDtls::setCookieGeneratorParameters(),
    SslUnsafeDtls::cookieGeneratorParameters(),
    QCryptographicHash::Algorithm
*/

/*!
    \enum SslUnsafeDtlsError
    \brief Describes errors that can be found by SslUnsafeDtls and SslUnsafeDtlsClientVerifier.
    \relates SslUnsafeDtls
    \since 5.12

    \ingroup network
    \ingroup ssl
    \inmodule QtNetwork

    This enum describes general and TLS-specific errors that can be encountered
    by objects of the classes SslUnsafeDtlsClientVerifier and SslUnsafeDtls.

    \value NoError No error occurred, the last operation was successful.
    \value InvalidInputParameters Input parameters provided by a caller were
           invalid.
    \value InvalidOperation An operation was attempted in a state that did not
           permit it.
    \value UnderlyingSocketError QUdpSocket::writeDatagram() failed, QUdpSocket::error()
           and QUdpSocket::errorString() can provide more specific information.
    \value RemoteClosedConnectionError TLS shutdown alert message was received.
    \value PeerVerificationError Peer's identity could not be verified during the
           TLS handshake.
    \value TlsInitializationError An error occurred while initializing an underlying
           TLS backend.
    \value TlsFatalError A fatal error occurred during TLS handshake, other
           than peer verification error or TLS initialization error.
    \value TlsNonFatalError A failure to encrypt or decrypt a datagram, non-fatal,
           meaning SslUnsafeDtls can continue working after this error.
*/

/*!
    \class SslUnsafeDtls
    \brief This class provides encryption for UDP sockets.
    \since 5.12

    \ingroup network
    \ingroup ssl
    \inmodule QtNetwork

    The SslUnsafeDtls class can be used to establish a secure connection with a network
    peer using User Datagram Protocol (UDP). DTLS connection over essentially
    connectionless UDP means that two peers first have to successfully complete
    a TLS handshake by calling doHandshake(). After the handshake has completed,
    encrypted datagrams can be sent to the peer using writeDatagramEncrypted().
    Encrypted datagrams coming from the peer can be decrypted by decryptDatagram().

    SslUnsafeDtls is designed to work with QUdpSocket. Since QUdpSocket can receive
    datagrams coming from different peers, an application must implement
    demultiplexing, forwarding datagrams coming from different peers to their
    corresponding instances of SslUnsafeDtls. An association between a network peer
    and its SslUnsafeDtls object can be established using the peer's address and port
    number. Before starting a handshake, the application must set the peer's
    address and port number using setPeer().

    SslUnsafeDtls does not read datagrams from QUdpSocket, this is expected to be done by
    the application, for example, in a slot attached to the QUdpSocket::readyRead()
    signal. Then, these datagrams must be processed by SslUnsafeDtls.

    \note SslUnsafeDtls does \e not take ownership of the QUdpSocket object.

    Normally, several datagrams are to be received and sent by both peers during
    the handshake phase. Upon reading datagrams, server and client must pass these
    datagrams to doHandshake() until some error is found or handshakeState()
    returns HandshakeComplete:

    \snippet code/src_network_ssl_qdtls.cpp 0

    For a server, the first call to doHandshake() requires a non-empty datagram
    containing a ClientHello message. If the server also deploys SslUnsafeDtlsClientVerifier,
    the first ClientHello message is expected to be the one verified by SslUnsafeDtlsClientVerifier.

    In case the peer's identity cannot be validated during the handshake, the application
    must inspect errors returned by peerVerificationErrors() and then either
    ignore errors by calling ignoreVerificationErrors() or abort the handshake
    by calling abortHandshake(). If errors were ignored, the handshake can be
    resumed by calling resumeHandshake().

    After the handshake has been completed, datagrams can be sent to and received
    from the network peer securely:

    \snippet code/src_network_ssl_qdtls.cpp 2

    A DTLS connection may be closed using shutdown().

    \snippet code/src_network_ssl_qdtls.cpp 3

    \warning It's recommended to call shutdown() before destroying the client's SslUnsafeDtls
    object if you are planning to re-use the same port number to connect to the
    server later. Otherwise, the server may drop incoming ClientHello messages,
    see \l{https://tools.ietf.org/html/rfc6347#page-25}{RFC 6347, section 4.2.8}
    for more details and implementation hints.

    If the server does not use SslUnsafeDtlsClientVerifier, it \e must configure its
    SslUnsafeDtls objects to disable the cookie verification procedure:

    \snippet code/src_network_ssl_qdtls.cpp 4

    A server that uses cookie verification with non-default generator parameters
    \e must set the same parameters for its SslUnsafeDtls object before starting the handshake.

    \note The DTLS protocol leaves Path Maximum Transmission Unit (PMTU) discovery
    to the application. The application may provide SslUnsafeDtls with the MTU using
    setMtuHint(). This hint affects only the handshake phase, since only handshake
    messages can be fragmented and reassembled by the DTLS. All other messages sent
    by the application must fit into a single datagram.
    \note DTLS-specific headers add some overhead to application data further
    reducing the possible message size.
    \warning A server configured to reply with HelloVerifyRequest will drop
    all fragmented ClientHello messages, never starting a handshake.

    The \l{secureudpserver}{DTLS server} and \l{secureudpclient}{DTLS client}
    examples illustrate how to use SslUnsafeDtls in applications.

    \sa QUdpSocket, SslUnsafeDtlsClientVerifier, HandshakeState, SslUnsafeDtlsError, SslUnsafeConfiguration
*/

/*!
    \typedef SslUnsafeDtls::GeneratorParameters

    This is a synonym for SslUnsafeDtlsClientVerifier::GeneratorParameters.
*/

/*!
    \fn void SslUnsafeDtls::handshakeTimeout()

    Packet loss can result in timeouts during the handshake phase. In this case
    SslUnsafeDtls emits a handshakeTimeout() signal. Call handleTimeout() to retransmit
    the handshake messages:

    \snippet code/src_network_ssl_qdtls.cpp 1

    \sa handleTimeout()
*/

/*!
    \fn void SslUnsafeDtls::pskRequired(SslUnsafePreSharedKeyAuthenticator *authenticator)

    SslUnsafeDtls emits this signal when it negotiates a PSK ciphersuite, and therefore
    a PSK authentication is then required.

    When using PSK, the client must send to the server a valid identity and a
    valid pre shared key, in order for the TLS handshake to continue.
    Applications can provide this information in a slot connected to this
    signal, by filling in the passed \a authenticator object according to their
    needs.

    \note Ignoring this signal, or failing to provide the required credentials,
    will cause the handshake to fail, and therefore the connection to be aborted.

    \note The \a authenticator object is owned by SslUnsafeDtls and must not be deleted
    by the application.

    \sa SslUnsafePreSharedKeyAuthenticator
*/

/*!
    \enum SslUnsafeDtls::HandshakeState
    \brief Describes the current state of DTLS handshake.
    \since 5.12

    \ingroup network
    \ingroup ssl
    \inmodule QtNetwork

    This enum describes the current state of DTLS handshake for a SslUnsafeDtls
    connection.

    \value HandshakeNotStarted Nothing done yet.
    \value HandshakeInProgress Handshake was initiated and no errors were found so far.
    \value PeerVerificationFailed The identity of the peer can't be established.
    \value HandshakeComplete Handshake completed successfully and encrypted connection
           was established.

    \sa SslUnsafeDtls::doHandshake(), SslUnsafeDtls::handshakeState()
*/


QT_BEGIN_NAMESPACE

SslUnsafeConfiguration SslUnsafeDtlsBasePrivate::configuration() const
{
    auto copyPrivate = new SslUnsafeConfigurationPrivate(dtlsConfiguration);
    copyPrivate->ref.store(0); // the SslUnsafeConfiguration constructor refs up
    SslUnsafeConfiguration copy(copyPrivate);
    copyPrivate->sessionCipher = sessionCipher;
    copyPrivate->sessionProtocol = sessionProtocol;

    return copy;
}

void SslUnsafeDtlsBasePrivate::setConfiguration(const SslUnsafeConfiguration &configuration)
{
    dtlsConfiguration.localCertificateChain = configuration.localCertificateChain();
    dtlsConfiguration.privateKey = configuration.privateKey();
    dtlsConfiguration.ciphers = configuration.ciphers();
    dtlsConfiguration.ellipticCurves = configuration.ellipticCurves();
    dtlsConfiguration.preSharedKeyIdentityHint = configuration.preSharedKeyIdentityHint();
    dtlsConfiguration.dhParams = configuration.diffieHellmanParameters();
    dtlsConfiguration.caCertificates = configuration.caCertificates();
    dtlsConfiguration.peerVerifyDepth = configuration.peerVerifyDepth();
    dtlsConfiguration.peerVerifyMode = configuration.peerVerifyMode();
    dtlsConfiguration.protocol = configuration.protocol();
    dtlsConfiguration.sslOptions = configuration.d->sslOptions;
    dtlsConfiguration.sslSession = configuration.sessionTicket();
    dtlsConfiguration.sslSessionTicketLifeTimeHint = configuration.sessionTicketLifeTimeHint();
    dtlsConfiguration.nextAllowedProtocols = configuration.allowedNextProtocols();
    dtlsConfiguration.nextNegotiatedProtocol = configuration.nextNegotiatedProtocol();
    dtlsConfiguration.nextProtocolNegotiationStatus = configuration.nextProtocolNegotiationStatus();
    dtlsConfiguration.dtlsCookieEnabled = configuration.dtlsCookieVerificationEnabled();
    dtlsConfiguration.allowRootCertOnDemandLoading = configuration.d->allowRootCertOnDemandLoading;
    dtlsConfiguration.backendConfig = configuration.backendConfiguration();

    clearDtlsError();
}

bool SslUnsafeDtlsBasePrivate::setCookieGeneratorParameters(QCryptographicHash::Algorithm alg,
                                                    const QByteArray &key)
{
    if (!key.size()) {
        setDtlsError(SslUnsafeDtlsError::InvalidInputParameters,
                     SslUnsafeDtls::tr("Invalid (empty) secret"));
        return false;
    }

    clearDtlsError();

    hashAlgorithm = alg;
    secret = key;

    return true;
}

bool SslUnsafeDtlsBasePrivate::isDtlsProtocol(SslUnsafe::SslProtocol protocol)
{
    switch (protocol) {
    case SslUnsafe::DtlsV1_0:
    case SslUnsafe::DtlsV1_0OrLater:
    case SslUnsafe::DtlsV1_2:
    case SslUnsafe::DtlsV1_2OrLater:
        return true;
    default:
        return false;
    }
}

static QString msgUnsupportedMulticastAddress()
{
    return SslUnsafeDtls::tr("Multicast and broadcast addresses are not supported");
}

/*!
    Default constructs GeneratorParameters object with QCryptographicHash::Sha1
    as its algorithm and an empty secret.

    \sa SslUnsafeDtlsClientVerifier::setCookieGeneratorParameters(),
    SslUnsafeDtlsClientVerifier::cookieGeneratorParameters(),
    SslUnsafeDtls::setCookieGeneratorParameters(),
    SslUnsafeDtls::cookieGeneratorParameters()
 */
SslUnsafeDtlsClientVerifier::GeneratorParameters::GeneratorParameters()
{
}

/*!
    Constructs GeneratorParameters object from \a algorithm and \a secret.

    \sa SslUnsafeDtlsClientVerifier::setCookieGeneratorParameters(),
    SslUnsafeDtlsClientVerifier::cookieGeneratorParameters(),
    SslUnsafeDtls::setCookieGeneratorParameters(),
    SslUnsafeDtls::cookieGeneratorParameters()
 */
SslUnsafeDtlsClientVerifier::GeneratorParameters::GeneratorParameters(QCryptographicHash::Algorithm algorithm, const QByteArray &secret)
    : hash(algorithm), secret(secret)
{
}

/*!
    Constructs a SslUnsafeDtlsClientVerifier object, \a parent is passed to QObject's
    constructor.
*/
SslUnsafeDtlsClientVerifier::SslUnsafeDtlsClientVerifier(QObject *parent)
    : QObject(parent), d_ptr(new SslUnsafeDtlsClientVerifierOpenSSL)
{
    Q_D(SslUnsafeDtlsClientVerifier);
    d->q_ptr = this;

    d->mode = SslUnsafeSocket::SslServerMode;
    // The default configuration suffices: verifier never does a full
    // handshake and upon verifying a cookie in a client hello message,
    // it reports success.
    auto conf = SslUnsafeConfiguration::defaultDtlsConfiguration();
    conf.setPeerVerifyMode(SslUnsafeSocket::VerifyNone);
    d->setConfiguration(conf);
}

/*!
    Destroys the SslUnsafeDtlsClientVerifier object.
*/
SslUnsafeDtlsClientVerifier::~SslUnsafeDtlsClientVerifier()
{
}

/*!
    Sets the secret and the cryptographic hash algorithm from \a params. This
    SslUnsafeDtlsClientVerifier will use these to generate cookies. If the new secret
    has size zero, this function returns \c false and does not change the
    cookie generator parameters.

    \note The secret is supposed to be a cryptographically secure sequence of bytes.

    \sa SslUnsafeDtlsClientVerifier::GeneratorParameters, cookieGeneratorParameters(),
    QCryptographicHash::Algorithm
*/
bool SslUnsafeDtlsClientVerifier::setCookieGeneratorParameters(const GeneratorParameters &params)
{
    Q_D(SslUnsafeDtlsClientVerifier);

    return d->setCookieGeneratorParameters(params.hash, params.secret);
}

/*!
    Returns the current secret and hash algorithm used to generate cookies.
    The default hash algorithm is QCryptographicHash::Sha256 if Qt was configured
    to support it, QCryptographicHash::Sha1 otherwise. The default secret is
    obtained from the backend-specific cryptographically strong pseudorandom
    number generator.

    \sa QCryptographicHash::Algorithm, SslUnsafeDtlsClientVerifier::GeneratorParameters,
    setCookieGeneratorParameters()
*/
SslUnsafeDtlsClientVerifier::GeneratorParameters SslUnsafeDtlsClientVerifier::cookieGeneratorParameters() const
{
    Q_D(const SslUnsafeDtlsClientVerifier);

    return {d->hashAlgorithm, d->secret};
}

#ifdef OLDQT
static bool isMulticast(const QHostAddress &address)
{
    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        quint32 a = address.toIPv4Address();
        if ((a & 0xf0000000U) == 0xe0000000U)
            return true;
    } else {
        Q_IPV6ADDR a6_64 = address.toIPv6Address();
        if (a6_64.c[0] == 0xff)
            return true;
    }
    return false;
}
#endif

/*!
    \a socket must be a valid pointer, \a dgram must be a non-empty
    datagram, \a address cannot be null, broadcast, or multicast.
    \a port is the remote peer's port. This function returns \c true
    if \a dgram contains a ClientHello message with a valid cookie.
    If no matching cookie is found, verifyClient() will send a
    HelloVerifyRequest message using \a socket and return \c false.

    The following snippet shows how a server application may check for errors:

    \snippet code/src_network_ssl_qdtlscookie.cpp 2

    \sa QHostAddress::isNull(), QHostAddress::isBroadcast(), QHostAddress::isMulticast(),
    setCookieGeneratorParameters(), cookieGeneratorParameters()
*/
bool SslUnsafeDtlsClientVerifier::verifyClient(QUdpSocket *socket, const QByteArray &dgram,
                                       const QHostAddress &address, quint16 port)
{
    Q_D(SslUnsafeDtlsClientVerifier);

    if (!socket || address.isNull() || !dgram.size()) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters,
                        tr("A valid UDP socket, non-empty datagram, valid address/port were expected"));
        return false;
    }

    if ((address == QHostAddress("255.255.255.255")) ||
        #ifndef OLDQT
            address.isMulticast()
        #else
            isMulticast(address)
        #endif
            ) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters,
                        msgUnsupportedMulticastAddress());
        return false;
    }

    return d->verifyClient(socket, dgram, address, port);
}

/*!
    Convenience function. Returns the last ClientHello message that was successfully
    verified, or an empty QByteArray if no verification has completed.

    \sa verifyClient()
*/
QByteArray SslUnsafeDtlsClientVerifier::verifiedHello() const
{
    Q_D(const SslUnsafeDtlsClientVerifier);

    return d->verifiedClientHello;
}

/*!
    Returns the last error that occurred or SslUnsafeDtlsError::NoError.

    \sa SslUnsafeDtlsError, dtlsErrorString()
*/
SslUnsafeDtlsError SslUnsafeDtlsClientVerifier::dtlsError() const
{
    Q_D(const SslUnsafeDtlsClientVerifier);

    return d->errorCode;
}

/*!
    Returns a textual description of the last error, or an empty string.

    \sa dtlsError()
 */
QString SslUnsafeDtlsClientVerifier::dtlsErrorString() const
{
    Q_D(const SslUnsafeDtlsBase);

    return d->errorDescription;
}

/*!
    Creates a SslUnsafeDtls object, \a parent is passed to the QObject constructor.
    \a mode is SslUnsafeSocket::SslServerMode for a server-side DTLS connection or
    SslUnsafeSocket::SslClientMode for a client.

    \sa sslMode(), SslUnsafeSocket::SslMode
*/
SslUnsafeDtls::SslUnsafeDtls(SslUnsafeSocket::SslMode mode, QObject *parent)
    : QObject(parent), d_ptr(new SslUnsafeDtlsPrivateOpenSSL)
{
    Q_D(SslUnsafeDtls);
    d->q_ptr = this;

    d->mode = mode;
    setDtlsConfiguration(SslUnsafeConfiguration::defaultDtlsConfiguration());
}

/*!
    Destroys the SslUnsafeDtls object.
*/
SslUnsafeDtls::~SslUnsafeDtls()
{
}

/*!
    Sets the peer's address, \a port, and host name and returns \c true
    if successful. \a address must not be null, multicast, or broadcast.
    \a verificationName is the host name used for the certificate validation.

    \sa peerAddress(), peerPort(), peerVerificationName()
 */
bool SslUnsafeDtls::setPeer(const QHostAddress &address, quint16 port,
                    const QString &verificationName)
{
    Q_D(SslUnsafeDtls);

    if (d->handshakeState != HandshakeNotStarted) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("Cannot set peer after handshake started"));
        return false;
    }

    if (address.isNull()) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters,
                        tr("Invalid address"));
        return false;
    }


    if ((address == QHostAddress("255.255.255.255")) ||
        #ifndef OLDQT
            address.isMulticast()
        #else
            isMulticast(address)
        #endif
            ) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters,
                        msgUnsupportedMulticastAddress());
        return false;
    }

    d->clearDtlsError();

    d->remoteAddress = address;
    d->remotePort = port;
    d->peerVerificationName = verificationName;

    return true;
}

/*!
    Sets the host \a name that will be used for the certificate validation
    and returns \c true if successful.

    \note This function must be called before the handshake starts.

    \sa peerVerificationName(), setPeer()
*/
bool SslUnsafeDtls::setPeerVerificationName(const QString &name)
{
    Q_D(SslUnsafeDtls);

    if (d->handshakeState != HandshakeNotStarted) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("Cannot set verification name after handshake started"));
        return false;
    }

    d->clearDtlsError();
    d->peerVerificationName = name;

    return true;
}

/*!
    Returns the peer's address, set by setPeer(), or QHostAddress::Null.

    \sa setPeer()
*/
QHostAddress SslUnsafeDtls::peerAddress() const
{
    Q_D(const SslUnsafeDtls);

    return d->remoteAddress;
}

/*!
    Returns the peer's port number, set by setPeer(), or 0.

    \sa setPeer()
*/
quint16 SslUnsafeDtls::peerPort() const
{
    Q_D(const SslUnsafeDtlsBase);

    return d->remotePort;
}

/*!
    Returns the host name set by setPeer() or setPeerVerificationName().
    The default value is an empty string.

    \sa setPeerVerificationName(), setPeer()
*/
QString SslUnsafeDtls::peerVerificationName() const
{
    Q_D(const SslUnsafeDtls);

    return d->peerVerificationName;
}

/*!
    Returns SslUnsafeSocket::SslServerMode for a server-side connection and
    SslUnsafeSocket::SslClientMode for a client.

    \sa SslUnsafeDtls(), SslUnsafeSocket::SslMode
*/
SslUnsafeSocket::SslMode SslUnsafeDtls::sslMode() const
{
    Q_D(const SslUnsafeDtls);

    return d->mode;
}

/*!
    \a mtuHint is the maximum transmission unit (MTU), either discovered or guessed
    by the application. The application is not required to set this value.

    \sa mtuHint(), QAbstractSocket::PathMtuSocketOption
 */
void SslUnsafeDtls::setMtuHint(quint16 mtuHint)
{
    Q_D(SslUnsafeDtls);

    d->mtuHint = mtuHint;
}

/*!
    Returns the value previously set by setMtuHint(). The default value is 0.

    \sa setMtuHint()
 */
quint16 SslUnsafeDtls::mtuHint() const
{
    Q_D(const SslUnsafeDtls);

    return d->mtuHint;
}

/*!
    Sets the cryptographic hash algorithm and the secret from \a params.
    This function is only needed for a server-side SslUnsafeDtls connection.
    Returns \c true if successful.

    \note This function must be called before the handshake starts.

    \sa cookieGeneratorParameters(), doHandshake(), SslUnsafeDtlsClientVerifier,
    SslUnsafeDtlsClientVerifier::cookieGeneratorParameters()
*/
bool SslUnsafeDtls::setCookieGeneratorParameters(const GeneratorParameters &params)
{
    Q_D(SslUnsafeDtls);

    return d->setCookieGeneratorParameters(params.hash, params.secret);
}

/*!
    Returns the current hash algorithm and secret, either default ones or previously
    set by a call to setCookieGeneratorParameters().

    The default hash algorithm is QCryptographicHash::Sha256 if Qt was
    configured to support it, QCryptographicHash::Sha1 otherwise. The default
    secret is obtained from the backend-specific cryptographically strong
    pseudorandom number generator.

    \sa SslUnsafeDtlsClientVerifier, cookieGeneratorParameters()
*/
SslUnsafeDtls::GeneratorParameters SslUnsafeDtls::cookieGeneratorParameters() const
{
    Q_D(const SslUnsafeDtls);

    return {d->hashAlgorithm, d->secret};
}

/*!
    Sets the connection's TLS configuration from \a configuration
    and returns \c true if successful.

    \note This function must be called before the handshake starts.

    \sa dtlsConfiguration(), doHandshake()
*/
bool SslUnsafeDtls::setDtlsConfiguration(const SslUnsafeConfiguration &configuration)
{
    Q_D(SslUnsafeDtls);

    if (d->handshakeState != HandshakeNotStarted) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("Cannot set configuration after handshake started"));
        return false;
    }

    d->setConfiguration(configuration);
    return true;
}

/*!
    Returns either the default DTLS configuration or the configuration set by an
    earlier call to setDtlsConfiguration().

    \sa setDtlsConfiguration(), SslUnsafeConfiguration::defaultDtlsConfiguration()
*/
SslUnsafeConfiguration SslUnsafeDtls::dtlsConfiguration() const
{
    Q_D(const SslUnsafeDtls);

    return d->configuration();
}

/*!
    Returns the current handshake state for this SslUnsafeDtls.

    \sa doHandshake(), SslUnsafeDtls::HandshakeState
 */
SslUnsafeDtls::HandshakeState SslUnsafeDtls::handshakeState()const
{
    Q_D(const SslUnsafeDtls);

    return d->handshakeState;
}

/*!
    Starts or continues a DTLS handshake. \a socket must be a valid pointer.
    When starting a server-side DTLS handshake, \a dgram must contain the initial
    ClientHello message read from QUdpSocket. This function returns \c true if
    no error was found. Handshake state can be tested using handshakeState().
    \c false return means some error occurred, use dtlsError() for more
    detailed information.

    \note If the identity of the peer can't be established, the error is set to
    SslUnsafeDtlsError::PeerVerificationError. If you want to ignore verification errors
    and continue connecting, you must call ignoreVerificationErrors() and then
    resumeHandshake(). If the errors cannot be ignored, you must call
    abortHandshake().

    \snippet code/src_network_ssl_qdtls.cpp 5

    \sa handshakeState(), dtlsError(), ignoreVerificationErrors(), resumeHandshake(),
    abortHandshake()
*/
bool SslUnsafeDtls::doHandshake(QUdpSocket *socket, const QByteArray &dgram)
{
    Q_D(SslUnsafeDtls);

    if (d->handshakeState == HandshakeNotStarted)
        return startHandshake(socket, dgram);
    else if (d->handshakeState == HandshakeInProgress)
        return continueHandshake(socket, dgram);

    d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                    tr("Cannot start/continue handshake, invalid handshake state"));
    return false;
}

/*!
    \internal
*/
bool SslUnsafeDtls::startHandshake(QUdpSocket *socket, const QByteArray &datagram)
{
    Q_D(SslUnsafeDtls);

    if (!socket) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters, tr("Invalid (nullptr) socket"));
        return false;
    }

    if (d->remoteAddress.isNull()) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("To start a handshake you must set peer's address and port first"));
        return false;
    }

    if (sslMode() == SslUnsafeSocket::SslServerMode && !datagram.size()) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters,
                        tr("To start a handshake, DTLS server requires non-empty datagram (client hello)"));
        return false;
    }

    if (d->handshakeState != HandshakeNotStarted) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("Cannot start handshake, already done/in progress"));
        return false;
    }

    return d->startHandshake(socket, datagram);
}

/*!
    If a timeout occures during the handshake, the handshakeTimeout() signal
    is emitted. The application must call handleTimeout() to retransmit handshake
    messages; handleTimeout() returns \c true if a timeout has occurred, false
    otherwise. \a socket must be a valid pointer.

    \sa handshakeTimeout()
*/
bool SslUnsafeDtls::handleTimeout(QUdpSocket *socket)
{
    Q_D(SslUnsafeDtls);

    if (!socket) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters, tr("Invalid (nullptr) socket"));
        return false;
    }

    return d->handleTimeout(socket);
}

/*!
    \internal
*/
bool SslUnsafeDtls::continueHandshake(QUdpSocket *socket, const QByteArray &datagram)
{
    Q_D(SslUnsafeDtls);

    if (!socket || !datagram.size()) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters,
                        tr("A valid QUdpSocket and non-empty datagram are needed to continue the handshake"));
        return false;
    }

    if (d->handshakeState != HandshakeInProgress) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("Cannot continue handshake, not in InProgress state"));
        return false;
    }

    return d->continueHandshake(socket, datagram);
}

/*!
    If peer verification errors were ignored during the handshake,
    resumeHandshake() resumes and completes the handshake and returns
    \c true. \a socket must be a valid pointer. Returns \c false if
    the handshake could not be resumed.

    \sa doHandshake(), abortHandshake() peerVerificationErrors(), ignoreVerificationErrors()
*/
bool SslUnsafeDtls::resumeHandshake(QUdpSocket *socket)
{
    Q_D(SslUnsafeDtls);

    if (!socket) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters, tr("Invalid (nullptr) socket"));
        return false;
    }

    if (d->handshakeState != PeerVerificationFailed) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("Cannot resume, not in VerificationError state"));
        return false;
    }

    return d->resumeHandshake(socket);
}

/*!
    Aborts the ongoing handshake. Returns true if one was on-going on \a socket;
    otherwise, sets a suitable error and returns false.

    \sa doHandshake(), resumeHandshake()
 */
bool SslUnsafeDtls::abortHandshake(QUdpSocket *socket)
{
    Q_D(SslUnsafeDtls);

    if (!socket) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters, tr("Invalid (nullptr) socket"));
        return false;
    }

    if (d->handshakeState != PeerVerificationFailed && d->handshakeState != HandshakeInProgress) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("No handshake in progress, nothing to abort"));
        return false;
    }

    d->abortHandshake(socket);
    return true;
}

/*!
    Sends an encrypted shutdown alert message and closes the DTLS connection.
    Handshake state changes to SslUnsafeDtls::HandshakeNotStarted. \a socket must be a
    valid pointer. This function returns \c true on success.

    \sa doHandshake()
 */
bool SslUnsafeDtls::shutdown(QUdpSocket *socket)
{
    Q_D(SslUnsafeDtls);

    if (!socket) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters,
                        tr("Invalid (nullptr) socket"));
        return false;
    }

    if (!d->connectionEncrypted) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("Cannot send shutdown alert, not encrypted"));
        return false;
    }

    d->sendShutdownAlert(socket);
    return true;
}

/*!
    Returns \c true if DTLS handshake completed successfully.

    \sa doHandshake(), handshakeState()
 */
bool SslUnsafeDtls::isConnectionEncrypted() const
{
    Q_D(const SslUnsafeDtls);

    return d->connectionEncrypted;
}

/*!
    Returns the cryptographic \l {SslUnsafeCipher} {cipher} used by this connection,
    or a null cipher if the connection isn't encrypted. The cipher for the
    session is selected during the handshake phase. The cipher is used to encrypt
    and decrypt data.

    SslUnsafeConfiguration provides functions for setting the ordered list of ciphers
    from which the handshake phase will eventually select the session cipher.
    This ordered list must be in place before the handshake phase begins.

    \sa SslUnsafeConfiguration, setDtlsConfiguration(), dtlsConfiguration()
*/
SslUnsafeCipher SslUnsafeDtls::sessionCipher() const
{
    Q_D(const SslUnsafeDtls);

    return d->sessionCipher;
}

/*!
    Returns the DTLS protocol version used by this connection, or UnknownProtocol
    if the connection isn't encrypted yet. The protocol for the connection is selected
    during the handshake phase.

    setDtlsConfiguration() can set the preferred version before the handshake starts.

    \sa setDtlsConfiguration(), SslUnsafeConfiguration, SslUnsafeConfiguration::defaultDtlsConfiguration(),
    SslUnsafeConfiguration::setProtocol()
*/
SslUnsafe::SslProtocol SslUnsafeDtls::sessionProtocol() const
{
    Q_D(const SslUnsafeDtls);

    return d->sessionProtocol;
}

/*!
    Encrypts \a dgram and writes the encrypted data into \a socket. Returns the
    number of bytes written, or -1 in case of error. The handshake must be completed
    before writing encrypted data. \a socket must be a valid
    pointer.

    \sa doHandshake(), handshakeState(), isConnectionEncrypted(), dtlsError()
*/
qint64 SslUnsafeDtls::writeDatagramEncrypted(QUdpSocket *socket, const QByteArray &dgram)
{
    Q_D(SslUnsafeDtls);

    if (!socket) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters, tr("Invalid (nullptr) socket"));
        return -1;
    }

    if (!isConnectionEncrypted()) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("Cannot write a datagram, not in encrypted state"));
        return -1;
    }

    return d->writeDatagramEncrypted(socket, dgram);
}

/*!
    Decrypts \a dgram and returns its contents as plain text. The handshake must
    be completed before datagrams can be decrypted. Depending on the type of the
    TLS message the connection may write into \a socket, which must be a valid
    pointer.
*/
QByteArray SslUnsafeDtls::decryptDatagram(QUdpSocket *socket, const QByteArray &dgram)
{
    Q_D(SslUnsafeDtls);

    if (!socket) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidInputParameters, tr("Invalid (nullptr) socket"));
        return {};
    }

    if (!isConnectionEncrypted()) {
        d->setDtlsError(SslUnsafeDtlsError::InvalidOperation,
                        tr("Cannot read a datagram, not in encrypted state"));
        return {};
    }

    if (!dgram.size())
        return {};

    return d->decryptDatagram(socket, dgram);
}

/*!
    Returns the last error encountered by the connection or SslUnsafeDtlsError::NoError.

    \sa dtlsErrorString(), SslUnsafeDtlsError
*/
SslUnsafeDtlsError SslUnsafeDtls::dtlsError() const
{
    Q_D(const SslUnsafeDtls);

    return d->errorCode;
}

/*!
    Returns a textual description for the last error encountered by the connection
    or empty string.

    \sa dtlsError()
*/
QString SslUnsafeDtls::dtlsErrorString() const
{
    Q_D(const SslUnsafeDtls);

    return d->errorDescription;
}

/*!
    Returns errors found while establishing the identity of the peer.

    If you want to continue connecting despite the errors that have occurred,
    you must call ignoreVerificationErrors().
*/
QVector<SslUnsafeError> SslUnsafeDtls::peerVerificationErrors() const
{
    Q_D(const SslUnsafeDtls);

    return d->tlsErrors;
}

/*!
    This method tells SslUnsafeDtls to ignore only the errors given in \a errorsToIgnore.

    If, for instance, you want to connect to a server that uses a self-signed
    certificate, consider the following snippet:

    \snippet code/src_network_ssl_qdtls.cpp 6

    You can also call this function after doHandshake() encountered the
    SslUnsafeDtlsError::PeerVerificationError error, and then resume the handshake by
    calling resumeHandshake().

    Later calls to this function will replace the list of errors that were
    passed in previous calls. You can clear the list of errors you want to ignore
    by calling this function with an empty list.

    \sa doHandshake(), resumeHandshake(), SslUnsafeError
*/
void SslUnsafeDtls::ignoreVerificationErrors(const QVector<SslUnsafeError> &errorsToIgnore)
{
    Q_D(SslUnsafeDtls);

    d->tlsErrorsToIgnore = errorsToIgnore;
}

QByteArray SslUnsafeDtls::getRawWrittenData() const
{
    Q_D(const SslUnsafeDtls);

    return d->rawWrittenData;
}

QT_END_NAMESPACE
