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
    Test(QObject *parent = nullptr) : QObject(parent) {
        testResult = -1;
    }

    ~Test() {
        sslCAuditThread.quit();
        sslCAuditThread.wait();
        delete caudit;
    }

    virtual int getId() = 0;

    virtual void setTestSettings() = 0;

    virtual void setSslTest() = 0;

    void prepare() {
        setTestSettings();

        setSslTest();

        if (!sslTest->prepare(testSettings)) {
            RED("failed to prepare test " + sslTest->name());
            return;
        }

        caudit = new SslCAudit(testSettings);

        caudit->setSslTests(QList<SslTest *>() << sslTest);
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
        RED(QString("autotest #%1 for %2 failed").arg(getId()).arg(targetTest));
    }

    void printTestFailed(const QString &details) {
        RED(QString("autotest #%1 for %2 failed: %3").arg(getId()).arg(targetTest).arg(details));
    }

    void printTestSucceeded() {
        GREEN(QString("autotest #%1 for %2 succeeded").arg(getId()).arg(targetTest));
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

    QString targetTest;
    SslTest *sslTest;
    SslUserSettings testSettings;

protected:
    void setResult(int result) {
        testResult = result;
    }

private:
    int testResult;
    bool testIsReady;
    bool testIsFinished;
    QThread sslCAuditThread;
    SslCAudit *caudit;

};

#endif
