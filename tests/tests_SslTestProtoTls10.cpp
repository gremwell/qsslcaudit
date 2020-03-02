#include "test.h"
#include "ssltests.h"
#include "ciphers.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// Target SslTest is SslTest13:
// "test for TLS 1.0 protocol support"


// do verify peer certificate, use TLSv1.1 and stronger protocols
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
                            .arg(static_cast<int>(currentSslTest()->result())));
        }
    }

private:
    XSslSocket *socket;

};

// do verify peer certificate, use TlsV1_0 protocol
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
            socket->setProtocol(XSsl::TlsV1_0);

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
                            .arg(static_cast<int>(currentSslTest()->result())));
        }
    }

private:
    XSslSocket *socket;

};


QList<Test *> createAutotests()
{
    return QList<Test *>()
            << new Test01(1, "SslTestProtoTls10", QList<SslTest *>() << new SslTestProtoTls10)
            << new Test02(2, "SslTestProtoTls10", QList<SslTest *>() << new SslTestProtoTls10)
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

#include "tests_SslTestProtoTls10.moc"
