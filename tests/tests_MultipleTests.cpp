#include "test.h"
#include "ssltests.h"
#include "ciphers.h"
#include "clientinfo.h"

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
    Test01(int id, QString testBaseName, QList<SslTest *> sslTests) :
        Test(id, testBaseName, sslTests) {
        socket = nullptr;
        times = sslTests.size();
        currentAttempt = 1;
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
            socket->setProtocol(XSsl::TlsV1_1OrLater);

            connect(socket, &XSslSocket::encrypted, [=]() {
                socket->write(data);
                socket->flush();
            });

            connect(socket, QOverload<const QList<XSslError> &>::of(&XSslSocket::sslErrors), [=](const QList<XSslError> &errors) {
                socket->ignoreSslErrors();
            });
        }

        socket->connectToHostEncrypted("localhost", 8443);
    }

    void verifySslTestResult()
    {
        // we can't use currentSslTest as it becomes broken due to manual relaunch of SslCAudit
        if ((allSslTests().first()->result() == SslTestResult::DataIntercepted)
                && (getClient(0)->interceptedData() == data)) {
            ;
        } else {
            socket->close();
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1), attempt %2")
                            .arg(sslTestResultToString(allSslTests().first()->result()))
                            .arg(currentAttempt));
        }

        socket->close();
        if (socket->state() != QAbstractSocket::UnconnectedState)
            socket->waitForDisconnected();

        if (currentAttempt++ >= times) {
            setResult(0);
            printTestSucceeded();
        }
    }

private:
    XSslSocket *socket;
    QByteArray data;
    int times;
    int currentAttempt;

};

// do verify peer certificate, use TLSv1.1 and stronger protocols
// check for proper test result code each time
class Test02 : public Test
{
    Q_OBJECT
public:
    Test02(int id, QString testBaseName, QList<SslTest *> sslTests) :
        Test(id, testBaseName, sslTests) {
        socket = nullptr;
        currentAttempt = 1;
        times = sslTests.size();
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
        socket->setProtocol(XSsl::TlsV1_1OrLater);

        connect(socket, &XSslSocket::encrypted, [=]() {
            setResult(-1);
            printTestFailed(QString("encrypted connection established but should not, attempt %1").arg(currentAttempt));
        });

        socket->connectToHostEncrypted("localhost", 8443);
    }

    void verifySslTestResult()
    {
        // we can't use currentSslTest as it becomes broken due to manual relaunch of SslCAudit
        if ((allSslTests().first()->result() == SslTestResult::Undefined)
                && (QString::compare(socket->errorString(),
                                     "The host name did not match any of the valid hosts for this certificate") == 0)) {
            ;
        } else {
            socket->close();
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1), attempt %2")
                            .arg(sslTestResultToString(allSslTests().first()->result()))
                            .arg(currentAttempt));
        }

        socket->close();
        if (socket->state() != QAbstractSocket::UnconnectedState)
            socket->waitForDisconnected();

        if (currentAttempt++ >= times) {
            setResult(0);
            printTestSucceeded();
        }
    }

private:
    XSslSocket *socket;
    int times;
    int currentAttempt;

};


QList<Test *> createAutotests(int times)
{
    QList<SslTest *> sslTests;
    for (int i = 0; i < times; i++) {
        sslTests << new SslTestCertSS1;
    }
    return QList<Test *>()
            << new Test01(1, "MultipleTests", sslTests)
            << new Test02(2, "MultipleTests", sslTests)
               ;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    TestsLauncher *testsLauncher;

    int times = 20;
    bool ok;

    if (argc == 2) {
        times = QString(argv[1]).toInt(&ok);
        if (!ok)
            times = 20;
    }

    testsLauncher = new TestsLauncher(createAutotests(times));

    QObject::connect(testsLauncher, &TestsLauncher::autotestsFinished, [=](){
        qApp->exit(testsLauncher->testsResult());
    });

    testsLauncher->launchNextTest();

    return a.exec();
}

#include "tests_MultipleTests.moc"
