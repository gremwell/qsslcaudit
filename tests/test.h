#ifndef QSSLCAUDITTEST_H
#define QSSLCAUDITTEST_H

#include "debug.h"
#include "sslcaudit.h"

#include <QThread>


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
        delete caudit;
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
        if (!waitForSslTestsFinished()) {
            setResult(-1);
            printTestFailed("tests are not finished in time");
        }
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
            if (!sslTests.at(i)->prepare(testSettings)) {
                RED("failed to prepare test " + sslTests.at(i)->name());
                return;
            }
        }

        caudit = new SslCAudit(testSettings);

        connect(caudit, &SslCAudit::sslTestsFinished, this, &Test::handleAllTestsFinished);

        connect(caudit, &SslCAudit::sslTestReady, this, &Test::handleTestReady);

        connect(caudit, &SslCAudit::sslTestFinished, this, &Test::handleTestFinished);

        connect(&sslCAuditThread, &QThread::started, caudit, &SslCAudit::run);

        caudit->setSslTests(sslTests);
        caudit->moveToThread(&sslCAuditThread);
    }

    // asynchronously launches SslCAudit thread. this ends up with the first test becoming ready
    // this is supposed to be called by autotest
    void launchSslCAudit() {
        // flush all the statuses
        testIsReady = false;
        testIsFinished = false;
        testsAreFinished = false;

        sslCAuditThread.quit();
        sslCAuditThread.wait();

        sslCAuditThread.start();
    }

    // synchronously waits for the current test to become ready
    bool waitforSslTestReady() {
        int count = 0;
        int to = 5000;
        while (!testIsReady && ++count < to/10)
            QThread::msleep(10);

        return testIsReady;
    }

    // synchronously waits for all the tests to finish
    bool waitForSslTestsFinished() {
        int count = 0;
        // we have to wait more than the test will be executed
        int to = static_cast<int>(2 * testSettings.getWaitDataTimeout()) * sslTests.size();
        while (!testsAreFinished && ++count < to/10)
            QThread::msleep(10);

        return testsAreFinished;
    }

    // synchronously waits for the current test to finish
    bool waitForSslTestFinished() {
        int count = 0;
        // we have to wait more than the test will be executed
        int to = static_cast<int>(2 * testSettings.getWaitDataTimeout());
        while (!testIsFinished && ++count < to/10)
            QThread::msleep(10);

        return testIsFinished;
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

private slots:
    void handleAllTestsFinished() {
        testsAreFinished = true;
    }

    void handleTestReady() {
        testIsReady = true;
        testIsFinished = false;

        // executeNextSslTest() must set current test result to '0' if this stage succeeded
        setResult(-1);
        executeNextSslTest();
    }

    void handleTestFinished() {
        testIsFinished = true;

        // if test failed during execution, do not even run results
        // verification because it could produce false-positives
        if (getResult() != 0) {
            printTestFailed("test failed on execution");
        } else {
            verifySslTestResult();
        }

        currentTestNum++;
        if (currentTestNum >= sslTests.size()) {
            currentTestNum = sslTests.size()-1;
        }
    }

private:
    int id;
    QString testBaseName;
    QVector<int> testResults;
    bool testIsReady;
    bool testIsFinished;
    bool testsAreFinished;
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
    {}

    ~TestsLauncher() {}

    void launchTests()
    {
        retCode = 0;

        while (sslTests.size() > 0) {
            Test *test = sslTests.takeFirst();
            launchSingleTest(test);
            if (test->getResult() != 0) {
                retCode = -1;
            }
            test->deleteLater();
        }

        emit autotestsFinished();
    }

    void launchSingleTest(Test *autotest)
    {
        WHITE(QString("launching autotest #%1").arg(autotest->getId()));
        autotest->startTests();
    }

    int testsResult()
    {
        return retCode;
    }

signals:
    void autotestsFinished();

private:
    QList<Test *> sslTests;
    int retCode;

};

#endif
