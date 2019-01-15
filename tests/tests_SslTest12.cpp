#include "test.h"
#include "ssltests.h"
#include "ciphers.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// Target SslTest is SslTest12:
// "test for SSLv3 protocol and MEDIUM grade ciphers support"
// should be launched with unsafe openssl library


// do verify peer certificate, use TLSv1.1 and stronger protocols
// check for proper test result code
class Test01 : public Test
{
    Q_OBJECT
public:
    Test01(int id, QString testBaseName, SslTest *sslTest) : Test(id, testBaseName, sslTest){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

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

// do verify peer certificate, use SSLv3 protocol with medium ciphers
// check for proper test result code
class Test02 : public Test
{
    Q_OBJECT
public:
    Test02(int id, QString testBaseName, SslTest *sslTest) : Test(id, testBaseName, sslTest){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::SslV3);
        QList<XSslCipher> mediumCiphers;
        QStringList opensslCiphers = ciphers_medium_str.split(":");

        for (int i = 0; i < opensslCiphers.size(); i++) {
            XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

            if (!cipher.isNull())
                mediumCiphers << cipher;
        }
        if (mediumCiphers.size() == 0) {
            setResult(-1);
            printTestFailed();
            QThread::currentThread()->quit();
            return;
        }
        socket->setCiphers(mediumCiphers);

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

// do verify peer certificate, use SSLv3 protocol with high ciphers
// check for proper test result code
class Test03 : public Test
{
    Q_OBJECT
public:
    Test03(int id, QString testBaseName, SslTest *sslTest) : Test(id, testBaseName, sslTest){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::SslV3);
        QList<XSslCipher> highCiphers;
        QStringList opensslCiphers = ciphers_high_str.split(":");

        for (int i = 0; i < opensslCiphers.size(); i++) {
            XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

            if (!cipher.isNull())
                highCiphers << cipher;
        }
        if (highCiphers.size() == 0) {
            setResult(-1);
            printTestFailed();
            QThread::currentThread()->quit();
            return;
        }
        socket->setCiphers(highCiphers);

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

// do not verify peer certificate, use SSLv3 protocol with medium ciphers
// check for proper test result code
class Test04 : public Test
{
    Q_OBJECT
public:
    Test04(int id, QString testBaseName, SslTest *sslTest) : Test(id, testBaseName, sslTest){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->setProtocol(XSsl::SslV3);
        QList<XSslCipher> mediumCiphers;
        QStringList opensslCiphers = ciphers_medium_str.split(":");

        for (int i = 0; i < opensslCiphers.size(); i++) {
            XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

            if (!cipher.isNull())
                mediumCiphers << cipher;
        }
        if (mediumCiphers.size() == 0) {
            setResult(-1);
            printTestFailed();
            QThread::currentThread()->quit();
            return;
        }
        socket->setCiphers(mediumCiphers);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed();
        } else {
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
        socket->disconnectFromHost();

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
            << new Test01(1, "SslTest12", new SslTest12)
            << new Test02(2, "SslTest12", new SslTest12)
            << new Test03(3, "SslTest12", new SslTest12)
            << new Test04(4, "SslTest12", new SslTest12)
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

#include "tests_SslTest12.moc"
