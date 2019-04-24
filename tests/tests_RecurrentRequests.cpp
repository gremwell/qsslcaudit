#include "test.h"
#include "ssltests.h"
#include "ciphers.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// This verifies how sslcaudit handles requests sent repeatedly


// do not verify peer certificate, use TLSv1.1 and stronger protocols
// check for proper test result code each time
class Test01 : public Test
{
    Q_OBJECT
public:
    Test01(int times, int id, QString testBaseName, QList<SslTest *> sslTests) :
        Test(id, testBaseName, sslTests), times(times) {
        socket = nullptr;
        currentAttempt = 1;
        isRunning = true;
        data = QByteArray("GET / HTTP/1.0\r\n\r\n");
    }

    ~Test01() {
        delete socket;
    }

    void setTestsSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void startTests() {
        prepareTests();
        launchSslCAudit();

        int count = 0;
        // we have to wait more than the test will be executed
        int to = 2 * times * 100;
        while (isRunning && ++count < to/100)
            QThread::msleep(100);

        if (isRunning) {
            setResult(-1);
            printTestFailed(QString("tests are not finished in time, attempt %1").arg(currentAttempt));
        }
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->setProtocol(XSsl::TlsV1_1OrLater);

        setResult(0);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed(QString("can not establish encrypted connection, attempt %1").arg(currentAttempt));
            isRunning = false;
        } else {
            socket->write(data);
            socket->flush();
            setResult(0);
        }
    }

    void verifySslTestResult()
    {
        // we can't use currentSslTest as it becomes broken due to manual relaunch of SslCAudit
        if ((allSslTests().first()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED)
                && (allSslTests().first()->interceptedData() == data)) {
            ;
        } else {
            socket->close();
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1), attempt %2")
                            .arg(allSslTests().first()->result())
                            .arg(currentAttempt));
            isRunning = false;
        }

        socket->close();
        if (socket->state() != QAbstractSocket::UnconnectedState)
            socket->waitForDisconnected();

        if (currentAttempt++ >= times) {
            setResult(0);
            printTestSucceeded();
            isRunning = false;
        } else {
            launchSslCAudit();
        }
    }

private:
    XSslSocket *socket;
    QByteArray data;
    int times;
    int currentAttempt;
    bool isRunning;

};

// do verify peer certificate, use TLSv1.1 and stronger protocols
// check for proper test result code each time
class Test02 : public Test
{
    Q_OBJECT
public:
    Test02(int times, int id, QString testBaseName, QList<SslTest *> sslTests) :
        Test(id, testBaseName, sslTests), times(times) {
        socket = nullptr;
        currentAttempt = 1;
        isRunning = true;
    }

    ~Test02() {
        delete socket;
    }

    void setTestsSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void startTests() {
        prepareTests();
        launchSslCAudit();

        int count = 0;
        // we have to wait more than the test will be executed
        int to = 2 * times * 100;
        while (isRunning && ++count < to/100)
            QThread::msleep(100);

        if (isRunning) {
            setResult(-1);
            printTestFailed(QString("tests are not finished in time, attempt %1").arg(currentAttempt));
        }
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::TlsV1_1OrLater);

        setResult(0);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed(QString("encrypted connection established but shouldnot, attempt %1").arg(currentAttempt));
            isRunning = false;
        }
    }

    void verifySslTestResult()
    {
        // we can't use currentSslTest as it becomes broken due to manual relaunch of SslCAudit
        if ((allSslTests().first()->result() == SslTest::SSLTEST_RESULT_SUCCESS)
                && (QString::compare(socket->errorString(),
                                     "The host name did not match any of the valid hosts for this certificate") == 0)) {
            ;
        } else {
            socket->close();
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1), attempt %2")
                            .arg(allSslTests().first()->result())
                            .arg(currentAttempt));
            isRunning = false;
        }

        socket->close();
        if (socket->state() != QAbstractSocket::UnconnectedState)
            socket->waitForDisconnected();

        if (currentAttempt++ >= times) {
            setResult(0);
            printTestSucceeded();
            isRunning = false;
        } else {
            launchSslCAudit();
        }
    }

private:
    XSslSocket *socket;
    int times;
    int currentAttempt;
    bool isRunning;

};


QList<Test *> createAutotests(int times)
{
    return QList<Test *>()
            << new Test01(times, 1, "RecurrentRequests", QList<SslTest *>() << new SslTest02)
            << new Test02(times, 2, "RecurrentRequests", QList<SslTest *>() << new SslTest02)
               ;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QThread thread;
    TestsLauncher *testsLauncher;

    int times = 20;
    bool ok;

    if (argc == 2) {
        times = QString(argv[1]).toInt(&ok);
        if (!ok)
            times = 20;
    }

    testsLauncher = new TestsLauncher(createAutotests(times));
    testsLauncher->moveToThread(&thread);
    QObject::connect(&thread, &QThread::finished, testsLauncher, &QObject::deleteLater);
    QObject::connect(&thread, &QThread::started, testsLauncher, &TestsLauncher::launchTests);
    QObject::connect(testsLauncher, &TestsLauncher::autotestsFinished, [=](){
        qApp->exit(testsLauncher->testsResult());
    });

    thread.start();

    int ret = a.exec();

    thread.quit();
    thread.wait();

    return ret;
}

#include "tests_RecurrentRequests.moc"
