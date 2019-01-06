
#ifndef SSLCAUDIT_H
#define SSLCAUDIT_H

#include <QObject>
#include <QAbstractSocket>

#ifdef UNSAFE_QSSL
#include "sslunsafeerror.h"
#else
#include <QSslError>
#endif

#include "sslusersettings.h"
#include "ssltest.h"


class SslCAudit : public QObject
{
    Q_OBJECT

public:
    SslCAudit(const SslUserSettings settings, QObject *parent = 0);

    void setSslTests(const QList<SslTest *> &tests);

    static void showCiphers();
    void printSummary();
    void writeXmlSummary(const QString &filename);

public slots:
    void run();

signals:
    void sslTestReady();
    void sslTestsFinished();

private slots:
    void handleSocketError(QAbstractSocket::SocketError socketError);
    void handleSslErrors(const QList<XSslError> &errors);
    void handlePeerVerifyError(const XSslError &error);
    void sslHandshakeFinished();

private:
    void runTest(SslTest *test);
    SslServer *prepareSslServer(const SslTest *test);
    void proxyConnection(XSslSocket *sslSocket, SslTest *test);
    void handleIncomingConnection(XSslSocket *sslSocket, SslTest *test);

    SslUserSettings settings;
    QList<SslTest *> sslTests;
    SslTest *currentTest;

};

#endif // SSLCAUDIT_H
