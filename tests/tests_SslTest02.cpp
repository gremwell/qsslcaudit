#include "test.h"
#include "ssltests.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// Target SslTest is SslTest02:
// "certificate trust test with self-signed certificate for user-supplied common name"

// do not verify peer certificate, send data to socket
// check for proper test result code and intercepted data
class Test01 : public Test
{
    Q_OBJECT
public:
    Test01(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests) {
        socket = nullptr;
    }

    ~Test01() {
        delete socket;
    }

    void setTestsSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new XSslSocket;

        data = QByteArray("GET / HTTP/1.0\r\n\r\n");

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("can not establish encrypted connection");
        } else {
            socket->write(data);
            socket->flush();
            setResult(0);
        }
    }

    void verifySslTestResult()
    {
        if ((currentSslTest()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED)
                && (currentSslTest()->interceptedData() == data)) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    XSslSocket *socket;
    QByteArray data;

};

// do not verify peer certificate, disconnect after timeout
// check for proper test result code
class Test02 : public Test
{
    Q_OBJECT
public:
    Test02(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests) {
        socket = nullptr;
    }

    ~Test02() {
        delete socket;
    }

    void setTestsSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("can not establish encrypted connection");
        } else {
            QThread::msleep(5500);
            setResult(0);
        }
    }

    void verifySslTestResult()
    {
        if (currentSslTest()->result() == SslTest::SSLTEST_RESULT_CERT_ACCEPTED) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    XSslSocket *socket;

};

// do verify peer certificate
// check for proper test result code
class Test03 : public Test
{
    Q_OBJECT
public:
    Test03(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests) {
        socket = nullptr;
    }

    ~Test03() {
        delete socket;
    }

    void setTestsSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed("encrypted session was established, but should not");
        }
    }

    void verifySslTestResult()
    {
        if (currentSslTest()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    XSslSocket *socket;

};

// connect to localhost, but set server name to the same as for ssl server
// do verify peer certificate
// check for proper test result code
class Test04 : public Test
{
    Q_OBJECT
public:
    Test04(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests) {
        socket = nullptr;
    }

    ~Test04() {
        delete socket;
    }

    void setTestsSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);

        socket->connectToHostEncrypted("localhost", 8443, "www.example.com");

        if (!socket->waitForEncrypted()) {
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed("encrypted session was established, but should not");
        }
    }

    void verifySslTestResult()
    {
        if (currentSslTest()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    XSslSocket *socket;

};


QList<Test *> createAutotests()
{
    return QList<Test *>()
            << new Test01(1, "SslTest02", QList<SslTest *>() << new SslTest02)
            << new Test02(2, "SslTest02", QList<SslTest *>() << new SslTest02)
            << new Test03(3, "SslTest02", QList<SslTest *>() << new SslTest02)
            << new Test04(4, "SslTest02", QList<SslTest *>() << new SslTest02)
               ;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QThread thread;
    TestsLauncher *testsLauncher;

    testsLauncher = new TestsLauncher(createAutotests());
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

#include "tests_SslTest02.moc"
