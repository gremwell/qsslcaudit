#include "sslserver.h"
#include "debug.h"
#include "starttls.h"
#include "ssltest.h"

#include <QTcpServer>

#ifdef UNSAFE_QSSL
#include "sslunsafeconfiguration.h"
#else
#include <QSslConfiguration>
#endif


class TcpsServer : public QTcpServer
{
    Q_OBJECT

public:
    TcpsServer(const SslUserSettings &settings, const SslTest *test, QObject *parent = nullptr);

    void handleIncomingConnection(XSslSocket *sslSocket);

protected:
    void incomingConnection(qintptr socketDescriptor) override final;

signals:
    void sslSocketErrors(const QList<XSslError> &sslErrors,
                         const QString &errorStr, QAbstractSocket::SocketError socketError);
    void dataIntercepted(const QByteArray &data);
    void rawDataCollected(const QByteArray &rdData, const QByteArray &wrData);
    void sslHandshakeFinished(const QList<XSslCertificate> &clientCerts);
    void peerVerifyError(const XSslError &error);
    void sslErrors(const QList<XSslError> &errors);
    void newPeer(const QHostAddress &peerAddress);

private:
    void handleStartTls(XSslSocket *const socket);
    void handleSocketError(QAbstractSocket::SocketError socketError);
    void handleSslHandshakeFinished();
    void proxyConnection(XSslSocket *sslSocket);

    QList<XSslCertificate> m_sslCertsChain;
    XSslKey m_sslPrivateKey;
    XSsl::SslProtocol m_sslProtocol;
    QList<XSslCipher> m_sslCiphers;
    SslServer::StartTlsProtocol m_startTlsProtocol;
    QHostAddress m_forwardHost;
    quint16 m_forwardPort;
    quint32 m_waitDataTimeout;

    friend class SslServer;
};

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


SslServer::SslServer(const SslUserSettings &settings, const SslTest *test, QObject *parent) : QObject(parent)
{
    m_listenAddress = settings.getListenAddress();
    m_listenPort = settings.getListenPort();
    m_dtlsMode = settings.getUseDtls();

    if (!m_dtlsMode) {
        tcpsServer = new TcpsServer(settings, test, this);

        connect(tcpsServer, &TcpsServer::sslSocketErrors, this, &SslServer::sslSocketErrors);
        connect(tcpsServer, &TcpsServer::sslErrors, this, &SslServer::sslErrors);
        connect(tcpsServer, &TcpsServer::dataIntercepted, this, &SslServer::dataIntercepted);
        connect(tcpsServer, &TcpsServer::rawDataCollected, this, &SslServer::rawDataCollected);
        connect(tcpsServer, &TcpsServer::sslHandshakeFinished, this, &SslServer::sslHandshakeFinished);
        connect(tcpsServer, &TcpsServer::peerVerifyError, this, &SslServer::peerVerifyError);
        connect(tcpsServer, &TcpsServer::newPeer, this, &SslServer::newPeer);
    }
}

SslServer::~SslServer()
{
    if (tcpsServer) {
        tcpsServer->close();
        delete tcpsServer;
    }
}

bool SslServer::listen()
{
    if (!m_dtlsMode) {
        if (!tcpsServer->listen(m_listenAddress, m_listenPort)) {
            RED(QString("can not bind to %1:%2").arg(m_listenAddress.toString()).arg(m_listenPort));
            return false;
        }
    } else {
        return false;
    }

    VERBOSE(QString("listening on %1:%2").arg(m_listenAddress.toString()).arg(m_listenPort));
    return true;
}

bool SslServer::waitForClient()
{
    if (!m_dtlsMode) {
        return tcpsServer->waitForNewConnection(-1);
    } else {
        return false;
    }
}

void SslServer::handleIncomingConnection()
{
    if (!m_dtlsMode) {
        XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(tcpsServer->nextPendingConnection());
        tcpsServer->handleIncomingConnection(sslSocket);
    }
}

#include "sslserver.moc"
