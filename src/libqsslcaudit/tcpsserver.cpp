#include "tcpsserver.h"

#include "sslusersettings.h"
#include "starttls.h"

TcpsServer::TcpsServer(const SslUserSettings *settings,
                       QList<XSslCertificate> localCert,
                       XSslKey privateKey,
                       XSsl::SslProtocol sslProtocol,
                       QList<XSslCipher> sslCiphers,
                       QObject *parent) :
    QTcpServer(parent),
    m_sslCertsChain(localCert),
    m_sslPrivateKey(privateKey),
    m_sslProtocol(sslProtocol),
    m_sslCiphers(sslCiphers)
{
    m_startTlsProtocol = settings->getStartTlsProtocol();
    m_forwardHost = settings->getForwardHostAddr();
    m_forwardPort = settings->getForwardHostPort();
    m_waitDataTimeout = settings->getWaitDataTimeout();

    m_isForwarding = false;
}

void TcpsServer::handleStartTls(XSslSocket *const socket)
{
    switch (m_startTlsProtocol) {
    case SslServer::StartTlsFtp:
        handleStartTlsFtp(socket);
        break;
    case SslServer::StartTlsSmtp:
        handleStartTlsSmtp(socket);
        break;
    case SslServer::StartTlsXmpp:
        handleStartTlsXmpp(socket);
        break;
    default:
        break;
    }
}

void TcpsServer::handleSocketError(QAbstractSocket::SocketError socketError)
{
    XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(sender());
    QString errorStr = sslSocket->errorString();

    emit sslSocketErrors(sslSocket->sslErrors(), errorStr, socketError);
}

void TcpsServer::incomingConnection(qintptr socketDescriptor)
{
    XSslSocket *sslSocket = new XSslSocket(this);

    if (!sslSocket->setSocketDescriptor(socketDescriptor)) {
        delete sslSocket;
        return;
    }

    addPendingConnection(sslSocket);

    // set SSL options using QSslConfiguration class
    XSslConfiguration sslConf;
    sslConf.setProtocol(m_sslProtocol);
    sslConf.setPrivateKey(m_sslPrivateKey);
    sslConf.setLocalCertificateChain(m_sslCertsChain);
    if (!m_sslCiphers.isEmpty())
        sslConf.setCiphers(m_sslCiphers);
    /* this is important to set even in server mode to properly verify SSLv3 / SSLv2 support */
    sslConf.setPeerVerifyMode(XSslSocket::VerifyNone);

    sslSocket->setSslConfiguration(sslConf);

    handleStartTls(sslSocket);

    // this is the only place to handle SSL initialization errors (in error slot)
    connect(sslSocket, static_cast<void(XSslSocket::*)(QAbstractSocket::SocketError)>(&XSslSocket::error),
            this, &TcpsServer::handleSocketError);

    sslSocket->startServerEncryption();
}

void TcpsServer::handleSslHandshakeFinished()
{
    XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(sender());
    emit sslHandshakeFinished(sslSocket->peerCertificateChain());
}

void TcpsServer::handleIncomingConnection(XSslSocket *sslSocket)
{
    VERBOSE(QString("connection from: %1:%2").arg(sslSocket->peerAddress().toString()).arg(sslSocket->peerPort()));

    emit newPeer(sslSocket->peerAddress());

    // handling socket errors makes sence only in non-interception mode
    connect(sslSocket, &XSslSocket::encrypted, this, &TcpsServer::handleSslHandshakeFinished);
    connect(sslSocket, &XSslSocket::peerVerifyError, this, &TcpsServer::peerVerifyError);
    connect(sslSocket, static_cast<void(XSslSocket::*)(const QList<XSslError> &)>(&XSslSocket::sslErrors),
            this, &TcpsServer::sslErrors);

    if (!m_forwardHost.isNull()) {
        // this will loop until connection is interrupted
        proxyConnection(sslSocket);
    } else {
        // no 'forward' option -- just read the first packet of unencrypted data and close the connection
        if (sslSocket->waitForReadyRead(m_waitDataTimeout)) {
            QByteArray message = sslSocket->readAll();

            VERBOSE("received data: " + QString(message));

            emit dataIntercepted(message);
        } else {
            VERBOSE("no unencrypted data received (" + sslSocket->errorString() + ")");
        }
    }

#ifdef UNSAFE_QSSL
    emit rawDataCollected(sslSocket->getRawReadData(), sslSocket->getRawWrittenData());
#endif

    sslSocket->disconnectFromHost();
    if (sslSocket->state() != QAbstractSocket::UnconnectedState)
        sslSocket->waitForDisconnected();
    sslSocket->deleteLater();

    VERBOSE("disconnected");

    emit sessionFinished();
}

void TcpsServer::proxyConnection(XSslSocket *sslSocket)
{
    // in case 'forward' option was set, we do the following:
    // - connect to the proxy;
    // - synchronously read data from ssl socket
    // - synchronously send this data to proxy
    QTcpSocket proxy;
    QByteArray data;

    // before connecting to the proxy, collect data from the socket
    // it will make tests decision logic happy
    // we also need waitFor() here. it gives some windows for signal/slots subsystem to
    // process all events from SSL socket
    if (sslSocket->waitForReadyRead(100)) {
        data = sslSocket->readAll();
        emit dataIntercepted(data);
    }

    proxy.connectToHost(m_forwardHost, m_forwardPort);

    if (!proxy.waitForConnected(2000)) {
        RED("can't connect to the forward proxy");
    } else {
        WHITE("forwarding incoming data to the provided proxy");
        WHITE("to get test results, relauch this app without 'forward' option");

        // disconnect socket errors slot, otherwise it will flood us with 'timeout' errors
        disconnect(sslSocket, static_cast<void(XSslSocket::*)(QAbstractSocket::SocketError)>(&XSslSocket::error),
                   this, &TcpsServer::handleSocketError);

        // start with sending previously read data
        proxy.write(data);

        // we wait until one of the communicating parties disconnect the socket
        // or SIGINT is sent
        m_stopForwarding = false;
        m_isForwarding = true;

        while (!m_stopForwarding) {
            if (sslSocket->state() == QAbstractSocket::UnconnectedState)
                break;
            if (proxy.state() == QAbstractSocket::UnconnectedState)
                break;

            if (sslSocket->waitForReadyRead(100)) {
                data = sslSocket->readAll();

                emit dataIntercepted(data);

                proxy.write(data);
            }

            if (proxy.waitForReadyRead(100)) {
                data = proxy.readAll();

                emit dataIntercepted(data);

                sslSocket->write(data);
            }
        }

        // return socket errors handling
        connect(sslSocket, static_cast<void(XSslSocket::*)(QAbstractSocket::SocketError)>(&XSslSocket::error),
                this, &TcpsServer::handleSocketError);
    }
}

bool TcpsServer::isForwarding()
{
    return m_isForwarding;
}

void TcpsServer::handleSigInt()
{
    m_stopForwarding = true;
}
