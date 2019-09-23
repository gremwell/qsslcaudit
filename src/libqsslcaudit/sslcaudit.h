
#ifndef SSLCAUDIT_H
#define SSLCAUDIT_H

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
    SslCAudit(const SslUserSettings settings, QObject *parent = nullptr);

    void setSslTests(const QList<SslTest *> &tests);

    static void showCiphers();
    void printSummary();
    void writeXmlSummary(const QString &filename);
    bool isSameClient(bool doPrint);
    ClientInfo getClientInfo(int num) {
        if (num < clientsInfo.size())
            return *clientsInfo.at(num);
        return ClientInfo();
    }

public slots:
    void run();

signals:
    void sslTestReady();
    void sslTestFinished();
    void sslTestsFinished();

private:
    void runTest();
    void handleSslSocketErrors(const QList<XSslError> &sslErrors,
                               const QString &errorStr, QAbstractSocket::SocketError socketError);
    static void showCiphersGroup(const QString &groupName, const QString &ciphersStr);

    SslUserSettings settings;

    QList<SslTest *> sslTests;
    SslTest *currentTest;

    QVector<ClientInfo *> clientsInfo;
    ClientInfo *currentClientInfo;

};

#endif // SSLCAUDIT_H
