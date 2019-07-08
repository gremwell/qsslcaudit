#include "test.h"
#include "ssltests.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// Target SslTest is SslTestProtoSsl2:
// "test for SSLv2 protocol support"
// should be launched with unsafe openssl library


// do verify peer certificate, use secure protocols/ciphers
// check for proper test result code
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

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::TlsV1_1OrLater);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed("encrypted session was established, but should not");
        }
        socket->disconnectFromHost();
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

// do verify peer certificate, use SSLv2 protocol
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

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::SslV2);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed("encrypted session was established, but should not");
        }
        socket->disconnectFromHost();
    }

    void verifySslTestResult()
    {
        if (currentSslTest()->result() == SslTestResult::ProtoAccepted) {
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

// do not verify peer certificate, use secure protocols/ciphers
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

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->setProtocol(XSsl::TlsV1_1OrLater);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed("encrypted session was established, but should not");
        }
        socket->disconnectFromHost();
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

// do not verify peer certificate, support SSLv2
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

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        // AnyProtocol does not include SSLv2
        socket->setProtocol(XSsl::SslV2);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("can not establish encrypted connection");
        } else {
            setResult(0);
        }
        socket->disconnectFromHost();
    }

    void verifySslTestResult()
    {
        if (currentSslTest()->result() == SslTestResult::ProtoAccepted) {
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
            << new Test01(1, "SslTestProtoSsl2", QList<SslTest *>() << new SslTestProtoSsl2)
            << new Test02(2, "SslTestProtoSsl2", QList<SslTest *>() << new SslTestProtoSsl2)
            << new Test03(3, "SslTestProtoSsl2", QList<SslTest *>() << new SslTestProtoSsl2)
            << new Test04(4, "SslTestProtoSsl2", QList<SslTest *>() << new SslTestProtoSsl2)
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

#include "tests_SslTest08.moc"
