#include "tcpsserver.h"

#include "ssltest.h"
#include "starttls.h"

TcpsServer::TcpsServer(const SslUserSettings &settings, const SslTest *test, QObject *parent) : QTcpServer(parent)
{
    m_sslCertsChain = test->localCert();
    m_sslPrivateKey = test->privateKey();
    m_sslProtocol = test->sslProtocol();
    m_sslCiphers = test->sslCiphers();

    m_startTlsProtocol = settings.getStartTlsProtocol();
    m_forwardHost = settings.getForwardHostAddr();
    m_forwardPort = settings.getForwardHostPort();
    m_waitDataTimeout = settings.getWaitDataTimeout();
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

    if (!m_forwardHost.isNull()) {
        // this will loop until connection is interrupted
        proxyConnection(sslSocket);
    } else {
        // handling socket errors makes sence only in non-interception mode

        connect(sslSocket, &XSslSocket::encrypted, this, &TcpsServer::handleSslHandshakeFinished);
        connect(sslSocket, &XSslSocket::peerVerifyError, this, &TcpsServer::peerVerifyError);
        connect(sslSocket, static_cast<void(XSslSocket::*)(const QList<XSslError> &)>(&XSslSocket::sslErrors),
                this, &TcpsServer::sslErrors);

        // no 'forward' option -- just read the first packet of unencrypted data and close the connection
        if (sslSocket->waitForReadyRead(m_waitDataTimeout)) {
            QByteArray message = sslSocket->readAll();

            VERBOSE("received data: " + QString(message));

            emit dataIntercepted(message);
        } else {
            VERBOSE("no unencrypted data received (" + sslSocket->errorString() + ")");
        }

#ifdef UNSAFE_QSSL
        emit rawDataCollected(sslSocket->getRawReadData(), sslSocket->getRawWrittenData());
#endif

        sslSocket->disconnectFromHost();
        if (sslSocket->state() != QAbstractSocket::UnconnectedState)
            sslSocket->waitForDisconnected();
        VERBOSE("disconnected");
    }
}

void TcpsServer::proxyConnection(XSslSocket *sslSocket)
{
    // in case 'forward' option was set, we do the following:
    // - connect to the proxy;
    // - synchronously read data from ssl socket
    // - synchronously send this data to proxy
    QTcpSocket proxy;

    proxy.connectToHost(m_forwardHost, m_forwardPort);

    if (!proxy.waitForConnected(2000)) {
        RED("can't connect to the forward proxy");
    } else {
        WHITE("forwarding incoming data to the provided proxy");
        WHITE("to get test results, relauch this app without 'forward' option");

        while (1) {
            if (sslSocket->state() == QAbstractSocket::UnconnectedState)
                break;
            if (proxy.state() == QAbstractSocket::UnconnectedState)
                break;

            if (sslSocket->waitForReadyRead(100)) {
                QByteArray data = sslSocket->readAll();

                emit dataIntercepted(data);

                proxy.write(data);
            }

            if (proxy.waitForReadyRead(100)) {
                sslSocket->write(proxy.readAll());
            }
        }
    }
}
