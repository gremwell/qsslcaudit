#ifndef QSSLCAUDITTEST_H
#define QSSLCAUDITTEST_H

#include "debug.h"
#include "sslcaudit.h"

#include <QThread>
#include <QTimer>
#include <QEventLoop>


class Test : public QObject
{
    Q_OBJECT
public:
    Test(int id, QString testBaseName,
         QList<SslTest *>sslTests, QObject *parent = nullptr) :
        QObject(parent),
        sslTests(sslTests),
        id(id),
        testBaseName(testBaseName)
    {
        testResult = -1;
    }

    ~Test() {
        sslCAuditThread.quit();
        sslCAuditThread.wait();
        delete caudit;
    }

    QList<SslTest *> sslTests;

    int getId() { return id; }

    virtual void setTestSettings() = 0;

    void prepare() {
        setTestSettings();

        for (int i = 0; i < sslTests.size(); i++) {
            if (!sslTests.at(i)->prepare(testSettings)) {
                RED("failed to prepare test " + sslTests.at(i)->name());
                return;
            }
        }

        caudit = new SslCAudit(testSettings);

        caudit->setSslTests(sslTests);
        caudit->moveToThread(&sslCAuditThread);

        connect(caudit, &SslCAudit::sslTestsFinished, [=](){
            testIsFinished = true;
        });

        connect(caudit, &SslCAudit::sslTestReady, [=](){
            testIsReady = true;
        });

        connect(&sslCAuditThread, &QThread::started, caudit, &SslCAudit::run, Qt::QueuedConnection);

        if (!launchSslCAudit()) {
            RED("failed to launch sslcaudit instance");
            return;
        }
    }

    bool launchSslCAudit() {
        testIsReady = false;
        testIsFinished = false;

        sslCAuditThread.quit();
        sslCAuditThread.wait();

        sslCAuditThread.start();

        int count = 0;
        int to = 5000;
        while (!testIsReady && ++count < to/10)
            QThread::msleep(10);

        return testIsReady;
    }

    void printTestFailed() {
        RED(QString("autotest #%1 for %2 failed").arg(getId()).arg(testName()));
    }

    void printTestFailed(const QString &details) {
        RED(QString("autotest #%1 for %2 failed: %3").arg(getId()).arg(testName()).arg(details));
    }

    void printTestSucceeded() {
        GREEN(QString("autotest #%1 for %2 succeeded").arg(getId()).arg(testName()));
    }

    int getResult() { return testResult; }

    bool waitForSslTestFinished() {
        int count = 0;
        // we have to wait more than the test will be executed
        int to = static_cast<int>(2 * testSettings.getWaitDataTimeout());
        while (!testIsFinished && ++count < to/10)
            QThread::msleep(10);

        return testIsFinished;
    }

    QString testName() { return QString("%1_%2").arg(testBaseName).arg(id); }
    SslUserSettings testSettings;

protected:
    void setResult(int result) {
        testResult = result;
    }

private:
    int id;
    QString testBaseName;
    int testResult;
    bool testIsReady;
    bool testIsFinished;
    QThread sslCAuditThread;
    SslCAudit *caudit;

};

#endif
