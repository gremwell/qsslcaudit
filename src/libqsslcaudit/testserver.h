#ifndef TESTSERVER_H
#define TESTSERVER_H

#include <QObject>
#include <QAbstractSocket>

#ifdef UNSAFE_QSSL
#include "sslunsafeerror.h"
#else
#include <QSslError>
#endif


class SslUserSettings;
class SslTest;
class SslServer;
class ClientInfo;

class TestServer : public QObject
{
    Q_OBJECT

public:
    TestServer(SslTest *sslTest, const SslUserSettings *settings,
               QObject *parent = nullptr);
    ~TestServer();

    const SslTest *getSslTest() {
        return sslTest;
    }

    const ClientInfo *getClientInfo() {
        return clientInfo;
    }

public slots:
    void runTest();

signals:
    void sslTestReady();
    void sslTestFinished();
    void sigIntHandled();

private:
    void handleSslSocketErrors(const QList<XSslError> &sslErrors,
                               const QString &errorStr, QAbstractSocket::SocketError socketError);
    void handleSessionFinished();

    const SslUserSettings *sslSettings;
    SslTest *sslTest;
    SslServer *sslServer;
    ClientInfo *clientInfo;

};

#endif // TESTSERVER_H
