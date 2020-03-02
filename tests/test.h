#ifndef QSSLCAUDITTEST_H
#define QSSLCAUDITTEST_H

#include "debug.h"
#include "sslcaudit.h"
#include "ssltest.h"
#include "ssltestresult.h"
#include "sslusersettings.h"

#include <QThread>
#include <QTimer>

class Test : public QObject
{
    Q_OBJECT
public:
    Test(int id, QString testBaseName, QList<SslTest *>sslTests, QObject *parent = nullptr) :
        QObject(parent),
        id(id),
        testBaseName(testBaseName),
        sslTests(sslTests)
    {
        testResults.resize(sslTests.size());
        testResults.fill(-1);
        currentTestNum = 0;
    }

    ~Test() {
        sslCAuditThread.quit();
        sslCAuditThread.wait();
        caudit->deleteLater();
    }

    int getId() { return id; }

    bool isFailed() {
        for (int i = 0; i < sslTests.size(); i++) {
            if (testResults.at(i) != 0)
                return true;
        }
        return false;
    }

    int getResult() { return testResults.at(currentTestNum); }

    SslUserSettings testSettings;

    SslTest * currentSslTest() {
        return sslTests.at(currentTestNum);
    }

    const ClientInfo *currentClient() {
        return caudit->getClientInfo(currentTestNum);
    }

    // required for "recurrentRequests" test
    const ClientInfo *getClient(int testNum) {
        return caudit->getClientInfo(testNum);
    }

    int currentSslTestNum() {
        return currentTestNum;
    }

    QList<SslTest *> allSslTests() {
        return sslTests;
    }

    // used as an entry point by TestsLauncher, can be reimplemented
    virtual void startTests() {
        prepareTests();
        launchSslCAudit();
    }

    // called by Test class in prepareTests() method
    // testSettings member is expected to be filled there
    virtual void setTestsSettings() = 0;

    // this is called when the current test is ready
    // it is expected that subclass will initiate test there, i.e. creating socket and connecting to listener
    virtual void executeNextSslTest() = 0;

    // this called when the current test is finished
    // the subclass is expected to verify current test results
    virtual void verifySslTestResult() = 0;

    // creates SslCAudit instance, configures tests and applies them to this instance
    // this should be the starting call of autotest
    void prepareTests() {
        setTestsSettings();

        for (int i = 0; i < sslTests.size(); i++) {
            if (!sslTests.at(i)->prepare(&testSettings)) {
                RED("failed to prepare test " + sslTests.at(i)->name());
                return;
            }
        }

        caudit = new SslCAudit(&testSettings);

        caudit->moveToThread(&sslCAuditThread);
        sslCAuditThread.start();

        connect(caudit, &SslCAudit::sslTestReady, this, &Test::launchClientTest);
        connect(caudit, &SslCAudit::sslTestFinished, this, &Test::handleTestFinished);
        connect(caudit, &SslCAudit::sslTestsFinished, this, &Test::handleAllTestsFinished);

        caudit->setSslTests(sslTests);
    }

    // asynchronously launches SslCAudit thread. this ends up with the first test becoming ready
    // this is supposed to be called by autotest
    void launchSslCAudit() {
        QTimer::singleShot(0, caudit, &SslCAudit::run);
    }

    // print helpers
    void printTestFailed() {
        RED(QString("autotest #%1 for %2 failed").arg(getId()).arg(testName()));
    }
    void printTestFailed(const QString &details) {
        RED(QString("autotest #%1 for %2 failed: %3").arg(getId()).arg(testName()).arg(details));
    }
    void printTestSucceeded() {
        GREEN(QString("autotest #%1 for %2 succeeded").arg(getId()).arg(testName()));
    }
    QString testName() { return QString("%1_%2").arg(testBaseName).arg(id); }

    // just API wrapper, we don't want to expose caudit member
    bool isSameClient(bool doPrint) {
        return caudit->isSameClient(doPrint);
    }

protected:
    void setResult(int result) {
        testResults[currentTestNum] = result;
    }

signals:
    void autotestFinished();

private slots:
    void launchClientTest() {
        setResult(-1);
        executeNextSslTest();
    }

    void handleAllTestsFinished() {
        sslCAuditThread.quit();
        sslCAuditThread.wait();
    }

    void handleTestFinished() {
        verifySslTestResult();

        if (currentTestNum == sslTests.size()-1) {
            emit autotestFinished();
        } else {
            currentTestNum++;
        }
    }

private:
    int id;
    QString testBaseName;
    QVector<int> testResults;

    QThread sslCAuditThread;
    SslCAudit *caudit;

    int currentTestNum;
    QList<SslTest *> sslTests;

};

class TestsLauncher : public QObject
{
    Q_OBJECT

public:
    TestsLauncher(QList<Test *> sslTests, QObject *parent = nullptr) :
        QObject(parent),
        sslTests(sslTests)
    {
        retCode = 0;

        // re-parenting tests as they will belong to the main()'s thread
        for (int i = 0; i < sslTests.size(); i++) {
            sslTests.at(i)->setParent(this);
        }
    }

    ~TestsLauncher() {}

    void launchNextTest()
    {
        if (sslTests.size() > 0) {
            Test *test = sslTests.takeFirst();
            launchSingleTest(test);
        } else {
            emit autotestsFinished();
        }
    }

    void launchSingleTest(Test *autotest)
    {
        WHITE(QString("launching autotest #%1").arg(autotest->getId()));

        connect(autotest, &Test::autotestFinished, this, &TestsLauncher::handleAutotestFinished);

        autotest->startTests();
    }

    int testsResult()
    {
        return retCode;
    }

signals:
    void autotestsFinished();

private:
    void handleAutotestFinished()
    {
        Test *autotest = qobject_cast<Test *>(sender());
        if (autotest->getResult() != 0) {
            retCode = -1;
        }
        autotest->deleteLater();

        launchNextTest();
    }

    QList<Test *> sslTests;
    int retCode;

};

#endif
