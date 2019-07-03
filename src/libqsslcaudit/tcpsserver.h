#ifndef TCPSSERVER_H
#define TCPSSERVER_H

#include "debug.h"

#include <QTcpServer>

#include "sslserver.h"

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

#endif // TCPSSERVER_H
