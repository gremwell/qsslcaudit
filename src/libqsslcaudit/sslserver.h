#ifndef SSLSERVER_H
#define SSLSERVER_H

#include <QAbstractSocket>
#include <QHostAddress>

#ifdef UNSAFE_QSSL
#include "sslunsafecertificate.h"
#include "sslunsafekey.h"
#include "sslunsafeellipticcurve.h"
#include "sslunsafecipher.h"
#include "sslunsafedtls.h"
#else
#include <QSslCertificate>
#include <QSslKey>
#include <QSslEllipticCurve>
#include <QSslCipher>
#include <QDtls>
#endif


class XSslSocket;
class SslUserSettings;
class SslTest;

class TcpsServer;
class DtlsServer;

class SslServer : public QObject
{
    Q_OBJECT

public:
    enum StartTlsProtocol {
        StartTlsFtp,
        StartTlsSmtp,
        StartTlsXmpp,
        StartTlsUnknownProtocol = -1
    };

    SslServer(const SslUserSettings &settings, const SslTest *test, QObject *parent = nullptr);
    ~SslServer();

    bool listen();
    bool waitForClient();
    void handleIncomingConnection();

    static QString dtlsErrorToString(XDtlsError error);

signals:
    void sslSocketErrors(const QList<XSslError> &sslErrors,
                         const QString &errorStr, QAbstractSocket::SocketError socketError);
    void sslErrors(const QList<XSslError> &errors);
    void dataIntercepted(const QByteArray &data);
    void rawDataCollected(const QByteArray &rdData, const QByteArray &wrData);
    void sslHandshakeFinished(const QList<XSslCertificate> &clientCerts);
    void peerVerifyError(const XSslError &error);
    void newPeer(const QHostAddress &peerAddress);

    void dtlsHandshakeError(const XDtlsError, const QString &);

private:
    QHostAddress m_listenAddress;
    quint16 m_listenPort;
    bool m_dtlsMode;

    TcpsServer *tcpsServer;
    DtlsServer *dtlsServer;
};

#endif // SSLSERVER_H
