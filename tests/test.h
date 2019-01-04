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

        if (!launchSslCAudit()) {
            RED("failed to launch sslcaudit instance");
            return;
        }
    }

    bool launchSslCAudit() {
        QThread *sslCAuditThread = new QThread;
        SslCAudit *caudit = new SslCAudit(testSettings);

        caudit->setSslTests(QList<SslTest *>() << sslTest);
        caudit->moveToThread(sslCAuditThread);
        QObject::connect(sslCAuditThread, SIGNAL(started()), caudit, SLOT(run()));
        QObject::connect(sslCAuditThread, SIGNAL(finished()), sslCAuditThread, SLOT(deleteLater()));

        sslCAuditThread->start();

        // setup test finished signal so the actual verify result procedure can start synchronously
        connect(caudit, &SslCAudit::sslTestsFinished, this, &Test::sslTestsFinished);

        // we have to wait until listener is ready
        QTimer timer;
        timer.setSingleShot(true);
        QEventLoop loop;
        connect(caudit, &SslCAudit::sslTestReady, &loop, &QEventLoop::quit);
        connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        timer.start(2000);
        loop.exec();

        if (!timer.isActive()) {
            return false;
        }
        return true;
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
        if (sslTest->result() != SslTest::SSLTEST_RESULT_NOT_READY)
            return true;

        QTimer timer;
        timer.setSingleShot(true);
        QEventLoop loop;
        connect(this, &Test::sslTestsFinished, &loop, &QEventLoop::quit);
        connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        // we have to wait more than the test will be executed
        timer.start(static_cast<int>(2 * testSettings.getWaitDataTimeout()));
        loop.exec();

        if (!timer.isActive())
            return false;

        return true;
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

signals:
    void sslTestsFinished();

};

#endif
