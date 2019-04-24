#include "test.h"
#include "ssltests.h"
#include "ciphers.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// This test verifies SslCAudit behaviour when multiple tests are conducted and different
// or the same clients connect to the listeners
// 1. the same non-SSL clients, no data transmission, disconnect after short timeout
// 2. the same non-SSL clients, data transmission, disconnect after short timeout
// 3. different non-SSL clients, data transmission, disconnect after short timeout
// 4. the same SSL clients, certificate validation
// 5. different SSL clients (protocol), certificate validation
// 6. different SSL clients (ciphers), certificate validation
// 7. the same SSL clients, no certificate validation, data transmission (different)
// 8. different SSL clients, no certificate validation, data transmission (the same)
//
// As a reference SslTest02 is used:
// "certificate trust test with self-signed certificate for user-supplied common name"

// the same non-SSL clients, no data transmission, disconnect after short timeout
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
            socket = new QTcpSocket;

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can not establish connection");
        } else {
            QThread::msleep(10);
            socket->disconnectFromHost();
            if (socket->state() != QAbstractSocket::UnconnectedState)
                socket->waitForDisconnected();
            setResult(0);
        }
    }

    void verifySslTestResult()
    {
        setResult(-1);

        if (currentSslTest()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
            if (currentSslTestNum() == 1) {
                if (!isSameClient(false)) {
                    setResult(-1);
                    printTestFailed("clients incorrectly considered as not the same");
                } else {
                    setResult(0);
                    printTestSucceeded();
                }
            }
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    QTcpSocket *socket;

};

// the same non-SSL clients, data transmission, disconnect after short timeout
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
            socket = new QTcpSocket;

        data = QByteArray("ABCDEF");

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can not establish connection");
        } else {
            socket->write(data);
            socket->flush();
            QThread::msleep(10);
            socket->disconnectFromHost();
            if (socket->state() != QAbstractSocket::UnconnectedState)
                socket->waitForDisconnected();
            setResult(0);
        }
    }

    void verifySslTestResult()
    {
        setResult(-1);

        if (currentSslTest()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
            if (currentSslTestNum() == 1) {
                if (!isSameClient(false)) {
                    setResult(-1);
                    printTestFailed("clients incorrectly considered as not the same");
                } else {
                    setResult(0);
                    printTestSucceeded();
                }
            }
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    QTcpSocket *socket;
    QByteArray data;

};

// different non-SSL clients, data transmission, disconnect after short timeout
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
            socket = new QTcpSocket;

        data = QString("ABCDEF%1").arg(currentSslTestNum()).toLocal8Bit();

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can not establish connection");
        } else {
            socket->write(data);
            socket->flush();
            QThread::msleep(10);
            socket->disconnectFromHost();
            if (socket->state() != QAbstractSocket::UnconnectedState)
                socket->waitForDisconnected();
            setResult(0);
        }
    }

    void verifySslTestResult()
    {
        setResult(-1);

        if (currentSslTest()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
            if (currentSslTestNum() == 1) {
                if (isSameClient(false)) {
                    setResult(-1);
                    printTestFailed("clients incorrectly considered as the same");
                } else {
                    setResult(0);
                    printTestSucceeded();
                }
            }
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    QTcpSocket *socket;
    QByteArray data;

};

// the same SSL clients, certificate validation
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

        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);

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
        setResult(-1);

        if (currentSslTest()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
            if (currentSslTestNum() == 1) {
                if (!isSameClient(false)) {
                    setResult(-1);
                    printTestFailed("clients incorrectly considered as not the same");
                } else {
                    setResult(0);
                    printTestSucceeded();
                }
            }
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    XSslSocket *socket;

};

// different SSL clients (proto), certificate validation
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
        if (!socket)
            socket = new XSslSocket;

        if (currentSslTestNum() == 0) {
            socket->setProtocol(XSsl::TlsV1_1);
        } else {
            socket->setProtocol(XSsl::TlsV1_2);
        }
        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);

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
        setResult(-1);

        if (currentSslTest()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
            if (currentSslTestNum() == 1) {
                if (isSameClient(false)) {
                    setResult(-1);
                    printTestFailed("clients incorrectly considered as the same");
                } else {
                    setResult(0);
                    printTestSucceeded();
                }
            }
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    XSslSocket *socket;

};

// different SSL clients (ciphers), certificate validation
class Test06 : public Test
{
    Q_OBJECT
public:
    Test06(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests) {
        socket = nullptr;
    }

    ~Test06() {
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

        socket->setProtocol(XSsl::TlsV1_2);
        if (currentSslTestNum() == 1) {
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
        }
        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);

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
        setResult(-1);

        if (currentSslTest()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
            if (currentSslTestNum() == 1) {
                if (isSameClient(false)) {
                    setResult(-1);
                    printTestFailed("clients incorrectly considered as the same");
                } else {
                    setResult(0);
                    printTestSucceeded();
                }
            }
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    XSslSocket *socket;

};

// the same SSL clients, no certificate validation, data transmission (different)
class Test07 : public Test
{
    Q_OBJECT
public:
    Test07(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests) {
        socket = nullptr;
    }

    ~Test07() {
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

        data = QString("ABCDEF%1").arg(currentSslTestNum()).toLocal8Bit();

        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("can not establish encrypted connection");
        } else {
            setResult(0);
            socket->write(data);
            socket->flush();
        }
        socket->disconnectFromHost();
    }

    void verifySslTestResult()
    {
        setResult(-1);

        if ((currentSslTest()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED)
                && (currentSslTest()->interceptedData() == data)) {
            if (currentSslTestNum() == 1) {
                if (!isSameClient(false)) {
                    setResult(-1);
                    printTestFailed("clients incorrectly considered as not the same");
                } else {
                    setResult(0);
                    printTestSucceeded();
                }
            }
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    XSslSocket *socket;
    QByteArray data;

};

// different SSL clients, no certificate validation, data transmission (the same)
class Test08 : public Test
{
    Q_OBJECT
public:
    Test08(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests) {
        socket = nullptr;
    }

    ~Test08() {
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

        data = QByteArray("ABCDEF");

        if (currentSslTestNum() == 0) {
            socket->setProtocol(XSsl::TlsV1_1);
        } else {
            socket->setProtocol(XSsl::TlsV1_2);
        }
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);

        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("can not establish encrypted connection");
        } else {
            setResult(0);
            socket->write(data);
            socket->flush();
        }
        socket->disconnectFromHost();
    }

    void verifySslTestResult()
    {
        setResult(-1);

        if ((currentSslTest()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED)
                && (currentSslTest()->interceptedData() == data)) {
            if (currentSslTestNum() == 1) {
                if (isSameClient(false)) {
                    setResult(-1);
                    printTestFailed("clients incorrectly considered as the same");
                } else {
                    setResult(0);
                    printTestSucceeded();
                }
            }
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)").arg(currentSslTest()->result()));
        }
    }

private:
    XSslSocket *socket;
    QByteArray data;

};

QList<Test *> createAutotests()
{
    return QList<Test *>()
            << new Test01(1, "MultipleClients", QList<SslTest *>() << new SslTest02 << new SslTest02)
            << new Test02(2, "MultipleClients", QList<SslTest *>() << new SslTest02 << new SslTest02)
            << new Test03(3, "MultipleClients", QList<SslTest *>() << new SslTest02 << new SslTest02)
            << new Test04(4, "MultipleClients", QList<SslTest *>() << new SslTest02 << new SslTest02)
            << new Test05(5, "MultipleClients", QList<SslTest *>() << new SslTest02 << new SslTest02)
            << new Test06(6, "MultipleClients", QList<SslTest *>() << new SslTest02 << new SslTest02)
            << new Test07(7, "MultipleClients", QList<SslTest *>() << new SslTest02 << new SslTest02)
            << new Test08(8, "MultipleClients", QList<SslTest *>() << new SslTest02 << new SslTest02)
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


#include "tests_MultipleClients.moc"
