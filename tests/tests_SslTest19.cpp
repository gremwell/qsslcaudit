#include "test.h"
#include "ssltests.h"
#include "ciphers.h"

#include <QCoreApplication>

#ifdef UNSAFE
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// Target SslTest is SslTest19:
// "test for TLS 1.1 protocol and MEDIUM grade ciphers support"


// do verify peer certificate, use TLSv1.2 and stronger protocols
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

    void setSslTest() { targetTest = QString("SslTest19"); sslTest = new SslTest19; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::TlsV1_2);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            // we should wait until test finishes prior to querying for test results
            while (sslTest->result() == SslTest::SSLTEST_RESULT_UNDEFINED)
                QThread::msleep(50);

            if (sslTest->result() == SslTest::SSLTEST_RESULT_SUCCESS) {
                printTestSucceeded();
            } else {
                printTestFailed();
            }

        } else {
            printTestFailed();
        }
        socket->disconnectFromHost();

        this->deleteLater();
        QThread::currentThread()->quit();
    }

};

// do verify peer certificate, use TlsV1_1 protocol with medium ciphers
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

    void setSslTest() { targetTest = QString("SslTest19"); sslTest = new SslTest19; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::TlsV1_1);
        QList<XSslCipher> mediumCiphers;
        QStringList opensslCiphers = ciphers_medium_str.split(":");

        for (int i = 0; i < opensslCiphers.size(); i++) {
            XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

            if (!cipher.isNull())
                mediumCiphers << cipher;
        }
        if (mediumCiphers.size() == 0) {
            printTestFailed();
            this->deleteLater();
            QThread::currentThread()->quit();
            return;
        }
        socket->setCiphers(mediumCiphers);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            // we should wait until test finishes prior to querying for test results
            while (sslTest->result() == SslTest::SSLTEST_RESULT_UNDEFINED)
                QThread::msleep(50);

            if (sslTest->result() == SslTest::SSLTEST_RESULT_PROTO_ACCEPTED) {
                printTestSucceeded();
            } else {
                printTestFailed();
            }

        } else {
            printTestFailed();
        }
        socket->disconnectFromHost();

        this->deleteLater();
        QThread::currentThread()->quit();
    }

};

// do verify peer certificate, use TlsV1_1 protocol with high ciphers
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

    void setSslTest() { targetTest = QString("SslTest19"); sslTest = new SslTest19; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->setProtocol(XSsl::TlsV1_1);
        QList<XSslCipher> highCiphers;
        QStringList opensslCiphers = ciphers_high_str.split(":");

        for (int i = 0; i < opensslCiphers.size(); i++) {
            XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

            if (!cipher.isNull())
                highCiphers << cipher;
        }
        if (highCiphers.size() == 0) {
            printTestFailed();
            this->deleteLater();
            QThread::currentThread()->quit();
            return;
        }
        socket->setCiphers(highCiphers);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            // we should wait until test finishes prior to querying for test results
            while (sslTest->result() == SslTest::SSLTEST_RESULT_UNDEFINED)
                QThread::msleep(50);

            if (sslTest->result() == SslTest::SSLTEST_RESULT_SUCCESS) {
                printTestSucceeded();
            } else {
                printTestFailed();
            }

        } else {
            printTestFailed();
        }
        socket->disconnectFromHost();

        this->deleteLater();
        QThread::currentThread()->quit();
    }

};

// do not verify peer certificate, use TlsV1_1 protocol with medium ciphers
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

    void setSslTest() { targetTest = QString("SslTest19"); sslTest = new SslTest19; }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->setProtocol(XSsl::TlsV1_1);
        QList<XSslCipher> mediumCiphers;
        QStringList opensslCiphers = ciphers_medium_str.split(":");

        for (int i = 0; i < opensslCiphers.size(); i++) {
            XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

            if (!cipher.isNull())
                mediumCiphers << cipher;
        }
        if (mediumCiphers.size() == 0) {
            printTestFailed();
            this->deleteLater();
            QThread::currentThread()->quit();
            return;
        }
        socket->setCiphers(mediumCiphers);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            printTestFailed();
        } else {
            // we should wait until test finishes prior to querying for test results
            while (sslTest->result() == SslTest::SSLTEST_RESULT_UNDEFINED)
                QThread::msleep(50);

            if (sslTest->result() == SslTest::SSLTEST_RESULT_CERT_ACCEPTED) {
                printTestSucceeded();
            } else {
                printTestFailed();
            }
        }
        socket->disconnectFromHost();

        this->deleteLater();
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

    QList<Test *> autotests = QList<Test *>()
            << new Test01
            << new Test02
            << new Test03
            << new Test04
               ;

    while (autotests.size() > 0) {
        launchTest(autotests.takeFirst());
    }

    return 0; //a.exec();
}

#include "tests_SslTest19.moc"
