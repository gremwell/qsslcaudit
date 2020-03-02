#include "test.h"
#include "ssltests.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// Target SslTest is SslTestProtoSsl3:
// "test for SSLv3 protocol support"
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
        if (!socket) {
            socket = new XSslSocket;

            socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
            socket->setProtocol(XSsl::TlsV1_1OrLater);

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

// do verify peer certificate, use SSLv3 protocol
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

            socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
            socket->setProtocol(XSsl::SslV3);

            connect(socket, &XSslSocket::encrypted, [=]() {
                printTestFailed("encrypted session was established, but should not");
            });
        }

        socket->connectToHostEncrypted("localhost", 8443);
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
        if (!socket) {
            socket = new XSslSocket;

            socket->setPeerVerifyMode(XSslSocket::VerifyNone);
            socket->setProtocol(XSsl::TlsV1_1OrLater);

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

// do not verify peer certificate, support SSLv3
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

            socket->setPeerVerifyMode(XSslSocket::VerifyNone);
            socket->setProtocol(XSsl::SslV3);

            connect(socket, &XSslSocket::encrypted, [=]() {
            });
        }

        socket->connectToHostEncrypted("localhost", 8443);
    }

    void verifySslTestResult()
    {
        if ((currentSslTest()->result() == SslTestResult::ProtoAccepted)
                || (currentSslTest()->result() == SslTestResult::CertAccepted)) {
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
            << new Test01(1, "SslTestProtoSsl3", QList<SslTest *>() << new SslTestProtoSsl3)
            << new Test02(2, "SslTestProtoSsl3", QList<SslTest *>() << new SslTestProtoSsl3)
            << new Test03(3, "SslTestProtoSsl3", QList<SslTest *>() << new SslTestProtoSsl3)
            << new Test04(4, "SslTestProtoSsl3", QList<SslTest *>() << new SslTestProtoSsl3)
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

#include "tests_SslTestProtoSsl3.moc"
