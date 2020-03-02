#ifndef SSLCAUDIT_H
#define SSLCAUDIT_H

#include <QObject>

class SslUserSettings;
class TestServer;
class SslTest;
class ClientInfo;

class SslCAudit : public QObject
{
    Q_OBJECT

public:
    SslCAudit(const SslUserSettings *settings, QObject *parent = nullptr);

    void setSslTests(const QList<SslTest *> &tests);

    void printSummary();
    void writeXmlSummary(const QString &filename);

    bool isSameClient(bool doPrint);

    const ClientInfo *getClientInfo(int num);

public slots:
    void handleSigInt();
    void run();

signals:
    void sslTestReady();
    void sslTestFinished();
    void sslTestsFinished();
    void sigIntHandled();

private:
    void handleServerFinished();

    const SslUserSettings *settings;

    QList<SslTest *> sslTests;
    QList<TestServer *> testServers;

};

#endif // SSLCAUDIT_H
