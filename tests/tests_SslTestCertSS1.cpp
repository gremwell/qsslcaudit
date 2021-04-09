#include "test.h"
#include "ssltests.h"
#include "clientinfo.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// Target SslTest is SslTestCertSS1:
// "certificate trust test with self-signed certificate for user-supplied common name"

// do not verify peer certificate, send data to socket
// check for proper test result code and intercepted data
class Test01 : public Test
{
    Q_OBJECT
public:
    Test01(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests) {
        socket = nullptr;
        data = QByteArray("GET / HTTP/1.0\r\n\r\n");
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
        if (!socket) {
            socket = new XSslSocket;

            socket->setPeerVerifyMode(XSslSocket::VerifyNone);

            connect(socket, &XSslSocket::encrypted, [=]() {
                socket->write(data);
                socket->flush();
            });
        }

        socket->connectToHostEncrypted("localhost", 8443);
    }

    void verifySslTestResult()
    {
        if ((currentSslTest()->result() == SslTestResult::DataIntercepted)
                && (currentClient()->interceptedData() == data)) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)")
                            .arg(sslTestResultToString(currentSslTest()->result())));
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
        if (!socket) {
            socket = new XSslSocket;

            socket->setPeerVerifyMode(XSslSocket::VerifyNone);

            connect(socket, &XSslSocket::encrypted, [=]() {
                QThread::msleep(5500);
            });
        }

        socket->connectToHostEncrypted("localhost", 8443);
    }

    void verifySslTestResult()
    {
        if (currentSslTest()->result() == SslTestResult::CertAccepted) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)")
                            .arg(sslTestResultToString(currentSslTest()->result())));
        }
    }

private:
    XSslSocket *socket;

};

// do verify peer certificate, do not specify application protocol, result should be undefined
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
        if (!socket) {
            socket = new XSslSocket;

            socket->setPeerVerifyMode(XSslSocket::VerifyPeer);

            connect(socket, &XSslSocket::encrypted, [=]() {
                printTestFailed("encrypted session was established, but should not");
            });
        }

        socket->connectToHostEncrypted("localhost", 8443);
    }

    void verifySslTestResult()
    {
        if (currentSslTest()->result() == SslTestResult::Undefined) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)")
                            .arg(sslTestResultToString(currentSslTest()->result())));
        }
    }

private:
    XSslSocket *socket;

};

// do verify peer certificate, do specify application protocol (HTTP), result should be failed
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
        if (!socket) {
            socket = new XSslSocket;

            SslUnsafeConfiguration c;
            c.setPeerVerifyMode(XSslSocket::VerifyPeer);
            c.setAllowedNextProtocols(QList<QByteArray>() << SslUnsafeConfiguration::ALPNProtocolHTTP2);
            socket->setSslConfiguration(c);

            connect(socket, &XSslSocket::encrypted, [=]() {
                printTestFailed("encrypted session was established, but should not");
            });
        }

        socket->connectToHostEncrypted("localhost", 8443);
    }

    void verifySslTestResult()
    {
        if (currentSslTest()->result() == SslTestResult::Success) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)")
                            .arg(sslTestResultToString(currentSslTest()->result())));
        }
    }

private:
    XSslSocket *socket;

};

// connect to localhost, but set server name to the same as for ssl server
// do verify peer certificate
// check for proper test result code
class Test05 : public Test
{
    Q_OBJECT
public:
    Test05(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests) {
        socket = nullptr;
    }

    ~Test05() {
        delete socket;
    }

    void setTestsSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void executeNextSslTest()
    {
        if (!socket) {
            socket = new XSslSocket;

            socket->setPeerVerifyMode(XSslSocket::VerifyPeer);

            connect(socket, &XSslSocket::encrypted, [=]() {
                printTestFailed("encrypted session was established, but should not");
            });
        }


        socket->connectToHostEncrypted("localhost", 8443, "www.example.com");
    }

    void verifySslTestResult()
    {
        if (currentSslTest()->result() == SslTestResult::Undefined) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)")
                            .arg(sslTestResultToString(currentSslTest()->result())));
        }
    }

private:
    XSslSocket *socket;

};


QList<Test *> createAutotests()
{
    return QList<Test *>()
            << new Test01(1, "SslTestCertSS1", QList<SslTest *>() << new SslTestCertSS1)
            << new Test02(2, "SslTestCertSS1", QList<SslTest *>() << new SslTestCertSS1)
            << new Test03(3, "SslTestCertSS1", QList<SslTest *>() << new SslTestCertSS1)
            << new Test04(4, "SslTestCertSS1", QList<SslTest *>() << new SslTestCertSS1)
            << new Test05(5, "SslTestCertSS1", QList<SslTest *>() << new SslTestCertSS1)
               ;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    TestsLauncher *testsLauncher;

    testsLauncher = new TestsLauncher(createAutotests());

    QObject::connect(testsLauncher, &TestsLauncher::autotestsFinished, [=](){
        qApp->exit(testsLauncher->testsResult());
    });

    testsLauncher->launchNextTest();

    return a.exec();
}

#include "tests_SslTestCertSS1.moc"
