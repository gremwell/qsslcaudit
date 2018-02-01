#ifndef QSSLCAUDITTEST_H
#define QSSLCAUDITTEST_H

#include "debug.h"
#include "sslcaudit.h"

#include <QThread>


class Test : public QObject
{
    Q_OBJECT
public:
    Test(QObject *parent = 0) : QObject(parent) {}

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

        launchSslCAudit();
    }

    void launchSslCAudit() {
        QThread *sslCAuditThread = new QThread;
        SslCAudit *caudit = new SslCAudit(testSettings);

        caudit->setSslTests(QList<SslTest *>() << sslTest);
        caudit->moveToThread(sslCAuditThread);
        QObject::connect(sslCAuditThread, SIGNAL(started()), caudit, SLOT(run()));
        QObject::connect(sslCAuditThread, SIGNAL(finished()), sslCAuditThread, SLOT(deleteLater()));

        sslCAuditThread->start();

        // wait a bit until it is fully operational
        // (technically, corresponding signal can be used...)
        QThread::msleep(200);
    }

    void printTestFailed() {
        RED(QString("autotest #%1 for %2 failed").arg(getId()).arg(targetTest));
    }

    void printTestSucceeded() {
        GREEN(QString("autotest #%1 for %2 succeeded").arg(getId()).arg(targetTest));
    }

    QString targetTest;
    SslTest *sslTest;
    SslUserSettings testSettings;

};

#endif
