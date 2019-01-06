#include "test.h"
#include "ssltests.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// Target SslTest is SslTest08:
// "test for SSLv2 protocol support"
// should be launched with unsafe openssl library


// do verify peer certificate, use secure protocols/ciphers
// check for proper test result code
class Test01 : public Test
{
    Q_OBJECT
public:
    int getId() { return 1; }

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void setSslTest() { targetTest = QString("SslTest08"); sslTest = new SslTest08; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::TlsV1_1OrLater);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed();
            } else if (sslTest->result() == SslTest::SSLTEST_RESULT_SUCCESS) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed();
            }

        } else {
            setResult(-1);
            printTestFailed();
        }
        socket->disconnectFromHost();

        QThread::currentThread()->quit();
    }

};

// do verify peer certificate, use SSLv2 protocol
// check for proper test result code
class Test02 : public Test
{
    Q_OBJECT
public:
    int getId() { return 2; }

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void setSslTest() { targetTest = QString("SslTest08"); sslTest = new SslTest08; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::SslV2);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed();
            } else if (sslTest->result() == SslTest::SSLTEST_RESULT_PROTO_ACCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed();
            }

        } else {
            setResult(-1);
            printTestFailed();
        }
        socket->disconnectFromHost();

        QThread::currentThread()->quit();
    }

};

// do not verify peer certificate, use secure protocols/ciphers
// check for proper test result code
class Test03 : public Test
{
    Q_OBJECT
public:
    int getId() { return 3; }

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void setSslTest() { targetTest = QString("SslTest08"); sslTest = new SslTest08; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->setProtocol(XSsl::TlsV1_1OrLater);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed();
            } else if (sslTest->result() == SslTest::SSLTEST_RESULT_SUCCESS) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed();
            }

        } else {
            setResult(-1);
            printTestFailed();
        }
        socket->disconnectFromHost();

        QThread::currentThread()->quit();
    }

};

// do not verify peer certificate, support SSLv2
// check for proper test result code
class Test04 : public Test
{
    Q_OBJECT
public:
    int getId() { return 4; }

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void setSslTest() { targetTest = QString("SslTest08"); sslTest = new SslTest08; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        // AnyProtocol does not include SSLv2
        socket->setProtocol(XSsl::SslV2);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            socket->disconnectFromHost();

            setResult(-1);
            printTestFailed();
        } else {
            socket->disconnectFromHost();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed();
            } else if (sslTest->result() == SslTest::SSLTEST_RESULT_CERT_ACCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed();
            }
        }

        QThread::currentThread()->quit();
    }

};


void launchTest(Test *autotest)
{
    WHITE(QString("launching autotest #%1").arg(autotest->getId()));

    // we should call it outside of its own thread
    autotest->prepare();

    QThread *autotestThread = new QThread;
    autotest->moveToThread(autotestThread);
    QObject::connect(autotestThread, SIGNAL(started()), autotest, SLOT(run()));
    QObject::connect(autotestThread, SIGNAL(finished()), autotestThread, SLOT(deleteLater()));

    autotestThread->start();

    autotestThread->wait();
}

int main(int argc, char *argv[])
{
    // we need QCoreApplication instance to initialize Qt internals
    QCoreApplication a(argc, argv);
    int ret = 0;

    QList<Test *> autotests = QList<Test *>()
            << new Test01
            << new Test02
            << new Test03
            << new Test04
               ;

    while (autotests.size() > 0) {
        Test *test = autotests.takeFirst();
        launchTest(test);
        if (test->getResult() != 0) {
            ret = -1;
        }
        test->deleteLater();
    }

    return ret;
}

#include "tests_SslTest08.moc"
