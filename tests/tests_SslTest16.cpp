#include "test.h"
#include "ssltests.h"
#include "ciphers.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// Target SslTest is SslTest16:
// "test for TLS 1.0 protocol and MEDIUM grade ciphers support"


// do verify peer certificate, use TLSv1.1 and stronger protocols
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

    void setSslTest() { targetTest = QString("SslTest16"); sslTest = new SslTest16; }

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

// do verify peer certificate, use TlsV1_0 protocol with medium ciphers
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

    void setSslTest() { targetTest = QString("SslTest16"); sslTest = new SslTest16; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::TlsV1_0);
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

// do verify peer certificate, use TlsV1_0 protocol with high ciphers
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

    void setSslTest() { targetTest = QString("SslTest16"); sslTest = new SslTest16; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::TlsV1_0);
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

// do not verify peer certificate, use TlsV1_0 protocol with medium ciphers
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

    void setSslTest() { targetTest = QString("SslTest16"); sslTest = new SslTest16; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->setProtocol(XSsl::TlsV1_0);
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

// do verify peer certificate, use TlsV1_2 protocol with medium ciphers
// check for proper test result code
class Test05 : public Test
{
    Q_OBJECT
public:
    int getId() { return 5; }

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

    void setSslTest() { targetTest = QString("SslTest16"); sslTest = new SslTest16; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->setProtocol(XSsl::TlsV1_2);
        QList<XSslCipher> mediumCiphers;
        QStringList opensslCiphers = ciphers_medium_str.split(":");
        opensslCiphers.append(ciphers_low_str.split(":"));
        opensslCiphers.append(ciphers_export_str.split(":"));
        opensslCiphers.append(ciphers_high_str.split(":"));

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
            << new Test05
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

#include "tests_SslTest16.moc"
