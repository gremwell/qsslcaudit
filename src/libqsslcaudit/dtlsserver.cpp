#include "dtlsserver.h"

#include "ssltest.h"

#include <QTimer>

/*
 * DtlsServerWorker keeps all related to actual UDP socket, including DTLS stuff.
 * it is running in dedicated QThread created in DtlsServer class. Thus, DtlsServer
 * is just a controller of DtlsServerWorker.
 * The idea is to keep QUdpSocket, readyRead() signal-slot and bind() in the same thread.
 * Otherwise, readyRead() will never be emitted.
 */

class DtlsServerWorker : public QObject
{
    Q_OBJECT

    bool waitForSocketReady() {
        while (!isReadyToAccept) {
            QThread::msleep(5);
        }
        return bindResult;
    }

    bool waitForNewClient() {
        while (!clientConnected) {
            QThread::msleep(50);
        }
        return true;
    }

    void waitForClientFinished();

public slots:
    void close() {
        if (!currentConnection.isNull()) {
            // this sends a valid DTLS alert to close the connection
            currentConnection->shutdown(serverSocket);
        }
        serverSocket->close();
        serverSocket->deleteLater();
    }

    void initUdpSocket() {
        isReadyToAccept = false;
        bindResult = false;
        clientFinished = false;

        serverSocket = new QUdpSocket(this);

        connect(serverSocket, &QAbstractSocket::readyRead, this, &DtlsServerWorker::readyRead);
        connect(serverSocket, static_cast<void(QUdpSocket::*)(QAbstractSocket::SocketError)>(&QUdpSocket::error),
                this, &DtlsServerWorker::handleSocketError);

        bindResult = serverSocket->bind(m_listenAddress, m_listenPort);
        isReadyToAccept = true;
    }

    void handleClient();

signals:
    void udpSocketErrors(const QList<XSslError> &sslErrors,
                         const QString &errorStr, QAbstractSocket::SocketError socketError);
    void dtlsHandshakeError(const XDtlsError, const QString &);
    void dataIntercepted(const QByteArray &data);
    void sslHandshakeFinished(const QList<XSslCertificate> &clientCerts);
    void newPeer(const QHostAddress &peerAddress);
    void rawDataCollected(const QByteArray &rdData, const QByteArray &wrData);

private slots:
    void handleSocketError(QAbstractSocket::SocketError socketError);
    void readyRead();

private:
    using DtlsConnection = QSharedPointer<XDtls>;

    void verifyClient(const QByteArray &clientHello);
    void doHandshake(const QByteArray &clientHello);
    void decryptDatagram(DtlsConnection connection, const QByteArray &clientMessage);

    QUdpSocket *serverSocket;
    // handling only one client
    bool clientConnected;
    bool clientVerified;
    bool clientFinished;
    QByteArray collectedDgram;
    DtlsConnection currentConnection;

    XDtlsClientVerifier cookieSender;

    QHostAddress m_listenAddress;
    quint16 m_listenPort;
    bool isReadyToAccept;
    bool bindResult;

    QHostAddress peerAddress;
    quint16 peerPort;

    QList<XSslCertificate> m_sslCertsChain;
    XSslKey m_sslPrivateKey;
    XSsl::SslProtocol m_sslProtocol;
    QList<XSslCipher> m_sslCiphers;

    SslServer::StartTlsProtocol m_startTlsProtocol;
    QHostAddress m_forwardHost;
    quint16 m_forwardPort;
    quint32 m_waitDataTimeout;

    friend class DtlsServer;
};

void DtlsServerWorker::readyRead()
{
    const qint64 bytesToRead = serverSocket->pendingDatagramSize();
    if (bytesToRead <= 0) {
        return;
    }

    QByteArray dgram(bytesToRead, Qt::Uninitialized);
    const qint64 bytesRead = serverSocket->readDatagram(dgram.data(), dgram.size(),
                                                        &peerAddress, &peerPort);
    if (bytesRead <= 0) {
        return;
    }
    if (peerAddress.isNull() || !peerPort) {
        return;
    }

    dgram.resize(bytesRead);

    // explicitly disable client cookie-based verification as it does not work for now
    clientVerified = true;

    if (!clientVerified) {
        verifyClient(dgram);
    } else if (!clientConnected) {
        VERBOSE(QString("connection from: %1:%2").arg(peerAddress.toString()).arg(peerPort));
        emit newPeer(peerAddress);

        collectedDgram = dgram;
        clientConnected = true;
    } else if (!currentConnection.isNull()) {
        if (currentConnection->isConnectionEncrypted()) {
            decryptDatagram(currentConnection, dgram);
        } else {
            doHandshake(dgram);
        }
    }
}

void DtlsServerWorker::verifyClient(const QByteArray &clientHello) {
    if (cookieSender.verifyClient(serverSocket, clientHello,
                                  peerAddress, peerPort)) {
        clientVerified = true;
    } else if (cookieSender.dtlsError() != XDtlsError::NoError) {
        qDebug() << cookieSender.dtlsErrorString();
    } else {
        qDebug() << "not verified yet";
    }
}

void DtlsServerWorker::handleClient() {
    currentConnection = DtlsConnection(new XDtls(XSslSocket::SslServerMode));

    // set SSL options using QSslConfiguration class
    XSslConfiguration sslConf;
    sslConf.setProtocol(m_sslProtocol);
    sslConf.setPrivateKey(m_sslPrivateKey);
    sslConf.setLocalCertificateChain(m_sslCertsChain);
    if (!m_sslCiphers.isEmpty())
        sslConf.setCiphers(m_sslCiphers);
    sslConf.setPeerVerifyMode(XSslSocket::VerifyNone);
    // explicitly turn off DTLS cookies support
    sslConf.setDtlsCookieVerificationEnabled(false);

    currentConnection->setDtlsConfiguration(sslConf);

    currentConnection->setPeer(peerAddress, peerPort);

    doHandshake(collectedDgram);
}

void DtlsServerWorker::doHandshake(const QByteArray &clientHello)
{
    const bool result = currentConnection->doHandshake(serverSocket, clientHello);
    if (!result) {
        emit dtlsHandshakeError(currentConnection->dtlsError(), currentConnection->dtlsErrorString());
        clientFinished = true;
        return;
    }

    switch (currentConnection->handshakeState()) {
    case XDtls::HandshakeInProgress:
        //VERBOSE("handshake is in progress");
        break;
    case XDtls::HandshakeComplete:
        //VERBOSE("handshake is finished");
        emit sslHandshakeFinished(QList<XSslCertificate>());
        break;
    default:
        Q_UNREACHABLE();
    }
}

void DtlsServerWorker::decryptDatagram(DtlsConnection connection, const QByteArray &clientMessage)
{
    const QByteArray dgram = connection->decryptDatagram(serverSocket, clientMessage);
    if (dgram.size()) {
        VERBOSE("received data: " + QString(dgram));
        emit dataIntercepted(dgram);
    } else if (connection->dtlsError() == XDtlsError::NoError) {
        VERBOSE("received empty data");
        emit dataIntercepted(dgram);
    } else if (connection->dtlsError() == XDtlsError::RemoteClosedConnectionError) {
        emit dtlsHandshakeError(connection->dtlsError(), connection->dtlsErrorString());
        clientFinished = true;
    } else {
        VERBOSE("data decryption error");
        emit dtlsHandshakeError(connection->dtlsError(), connection->dtlsErrorString());
    }
}

void DtlsServerWorker::handleSocketError(QAbstractSocket::SocketError socketError)
{
    QUdpSocket *udpSocket = dynamic_cast<QUdpSocket*>(sender());
    emit udpSocketErrors(QList<XSslError>(), udpSocket->errorString(), socketError);
}

void DtlsServerWorker::waitForClientFinished()
{
    quint32 left = m_waitDataTimeout;
    quint32 step = 50;
    while (left -= step) {
        if (clientFinished)
            return;
        QThread::msleep(step);
    }
}


// queued connections between different threads, registering the corresponding types
Q_DECLARE_METATYPE(QHostAddress)
Q_DECLARE_METATYPE(QList<SslUnsafeCertificate>)
Q_DECLARE_METATYPE(SslUnsafeDtlsError)

DtlsServer::DtlsServer(const SslUserSettings &settings, const SslTest *test, QObject *parent) : QObject(parent)
{
    qRegisterMetaType<QHostAddress>("QHostAddress");
    qRegisterMetaType<QList<SslUnsafeCertificate>>("QList<SslUnsafeCertificate>");
    qRegisterMetaType<SslUnsafeDtlsError>("SslUnsafeDtlsError");

    dtlsWorker = new DtlsServerWorker;
    dtlsWorker->moveToThread(&dtlsThread);

    connect(&dtlsThread, &QThread::finished, dtlsWorker, &QObject::deleteLater);

    connect(dtlsWorker, &DtlsServerWorker::udpSocketErrors, [=](const QList<XSslError> &sslErrors,
            const QString &errorStr, QAbstractSocket::SocketError socketError) {
        emit udpSocketErrors(sslErrors, errorStr, socketError);
    });
    connect(dtlsWorker, &DtlsServerWorker::dtlsHandshakeError, [=](const XDtlsError err, const QString &str) {
        emit dtlsHandshakeError(err, str);
    });
    connect(dtlsWorker, &DtlsServerWorker::dataIntercepted, [=](const QByteArray &data) {
        emit dataIntercepted(data);
    });
    connect(dtlsWorker, &DtlsServerWorker::sslHandshakeFinished, [=](const QList<XSslCertificate> &clientCerts) {
        emit sslHandshakeFinished(clientCerts);
    });
    connect(dtlsWorker, &DtlsServerWorker::newPeer, [=](const QHostAddress &peer) {
        emit newPeer(peer);
    });

    connect(dtlsWorker, &DtlsServerWorker::rawDataCollected, this, &DtlsServer::rawDataCollected);

    dtlsThread.start();

    dtlsWorker->m_sslCertsChain = test->localCert();
    dtlsWorker->m_sslPrivateKey = test->privateKey();
    dtlsWorker->m_sslProtocol = test->sslProtocol();
    dtlsWorker->m_sslCiphers = test->sslCiphers();

    dtlsWorker->m_startTlsProtocol = settings.getStartTlsProtocol();
    dtlsWorker->m_forwardHost = settings.getForwardHostAddr();
    dtlsWorker->m_forwardPort = settings.getForwardHostPort();
    dtlsWorker->m_waitDataTimeout = settings.getWaitDataTimeout();

    dtlsWorker->clientConnected = false;
}

DtlsServer::~DtlsServer() {
    dtlsThread.quit();
    if (dtlsThread.isRunning())
        dtlsThread.wait();
}

bool DtlsServer::listen(const QHostAddress &address, quint16 port)
{
    dtlsWorker->m_listenAddress = address;
    dtlsWorker->m_listenPort = port;

    QTimer::singleShot(0, dtlsWorker, SLOT(initUdpSocket()));
    return dtlsWorker->waitForSocketReady();
}

void DtlsServer::close()
{
    QTimer::singleShot(0, dtlsWorker, SLOT(close()));
}

bool DtlsServer::waitForNewClient()
{
    return dtlsWorker->waitForNewClient();
}

void DtlsServer::handleClient()
{
    QTimer::singleShot(0, dtlsWorker, SLOT(handleClient()));
    dtlsWorker->waitForClientFinished();
}

#include "dtlsserver.moc"
