#ifndef DTLSSERVER_H
#define DTLSSERVER_H

#include "debug.h"

#include <QUdpSocket>
#include <QThread>

#include "sslserver.h"

class DtlsServerWorker;

class DtlsServer : public QObject
{
    Q_OBJECT

public:
    DtlsServer(const SslUserSettings &settings,
               QList<XSslCertificate> localCert,
               XSslKey privateKey,
               XSsl::SslProtocol sslProtocol,
               QList<XSslCipher> sslCiphers,
               QObject *parent = nullptr);
    ~DtlsServer();

    bool listen(const QHostAddress &address, quint16 port);
    void close();
    bool waitForNewClient();
    void handleClient();

signals:
    void udpSocketErrors(const QList<XSslError> &sslErrors,
                         const QString &errorStr, QAbstractSocket::SocketError socketError);
    void dtlsHandshakeError(const XDtlsError, const QString &);
    void dataIntercepted(const QByteArray &data);
    void sslHandshakeFinished(const QList<XSslCertificate> &clientCerts);
    void newPeer(const QHostAddress &peerAddress);
    void rawDataCollected(const QByteArray &rdData, const QByteArray &wrData);

private:
    QThread dtlsThread;
    DtlsServerWorker *dtlsWorker;
};

#endif // DTLSSERVER_H
