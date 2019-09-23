#include "test.h"
#include "ssltests.h"
#include "ciphers.h"

#include <QCoreApplication>
#include <QUdpSocket>

#ifdef UNSAFE_QSSL
#include "sslunsafedtls.h"
#else
#include <QDtls>
#endif

// Target SslTest is SslTest02 in DTLS mode:
// "certificate trust test with self-signed certificate for user-supplied common name"


// do not verify peer certificate, send data to socket
// check for proper test result code and intercepted data
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
        testSettings.setUseDtls(true);
        testSettings.setUserCN("www.example.com");
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new QUdpSocket;

        data = QByteArray("GET / HTTP/1.0\r\n\r\n");

        XSslConfiguration conf;
        conf.setDtlsCookieVerificationEnabled(false);
        conf.setProtocol(XSsl::DtlsV1_0OrLater);
        conf.setPeerVerifyMode(XSslSocket::VerifyNone);

        XDtls dtls(XSslSocket::SslClientMode);
        dtls.setPeer(QHostAddress("127.0.0.1"), 8443);
        dtls.setDtlsConfiguration(conf);

        socket->connectToHost(QHostAddress("127.0.0.1"), 8443);

        bool ret = dtls.doHandshake(socket);
        if (!ret) {
            setResult(-1);
            printTestFailed("handshake failed too early");
            dtls.shutdown(socket);
            return;
        }

        while (socket->waitForReadyRead(200)) {
            qint64 bytesToRead = socket->pendingDatagramSize();
            QByteArray dgram(bytesToRead, Qt::Uninitialized);
            qint64 bytesRead = socket->readDatagram(dgram.data(), dgram.size());
            dgram.resize(bytesRead);
            dtls.doHandshake(socket, dgram);
        }

        if ((dtls.handshakeState() == XDtls::HandshakeComplete)
                && (dtls.dtlsError() == XDtlsError::NoError)) {
            dtls.writeDatagramEncrypted(socket, data);
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed("encrypted session was not established, but should");
        }

        dtls.shutdown(socket);
    }

    void verifySslTestResult()
    {
        if ((currentSslTest()->result() == SslTestResult::DataIntercepted)
                && (currentClient().interceptedData() == data)) {
            setResult(0);
            printTestSucceeded();
        } else {
            setResult(-1);
            printTestFailed(QString("unexpected test result (%1)")
                            .arg(sslTestResultToString(currentSslTest()->result())));
        }
    }

private:
    QUdpSocket *socket;
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
        testSettings.setUseDtls(true);
        testSettings.setUserCN("www.example.com");
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new QUdpSocket;

        XSslConfiguration conf;
        conf.setDtlsCookieVerificationEnabled(false);
        conf.setProtocol(XSsl::DtlsV1_0OrLater);
        conf.setPeerVerifyMode(XSslSocket::VerifyNone);

        XDtls dtls(XSslSocket::SslClientMode);
        dtls.setPeer(QHostAddress("127.0.0.1"), 8443);
        dtls.setDtlsConfiguration(conf);

        socket->connectToHost(QHostAddress("127.0.0.1"), 8443);

        bool ret = dtls.doHandshake(socket);
        if (!ret) {
            setResult(-1);
            printTestFailed("handshake failed too early");
            dtls.shutdown(socket);
            return;
        }

        while (socket->waitForReadyRead(200)) {
            qint64 bytesToRead = socket->pendingDatagramSize();
            QByteArray dgram(bytesToRead, Qt::Uninitialized);
            qint64 bytesRead = socket->readDatagram(dgram.data(), dgram.size());
            dgram.resize(bytesRead);
            dtls.doHandshake(socket, dgram);
        }

        if ((dtls.handshakeState() == XDtls::HandshakeComplete)
                && (dtls.dtlsError() == XDtlsError::NoError)) {
            QThread::msleep(5500);
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed("encrypted session was not established, but should");
        }

        dtls.shutdown(socket);
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
    QUdpSocket *socket;

};

// do verify peer certificate
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
        testSettings.setUseDtls(true);
        testSettings.setUserCN("www.example.com");
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new QUdpSocket;

        XSslConfiguration conf;
        conf.setDtlsCookieVerificationEnabled(false);
        conf.setProtocol(XSsl::DtlsV1_0OrLater);
        conf.setPeerVerifyMode(XSslSocket::VerifyPeer);

        XDtls dtls(XSslSocket::SslClientMode);
        dtls.setPeer(QHostAddress("127.0.0.1"), 8443);
        dtls.setDtlsConfiguration(conf);

        socket->connectToHost(QHostAddress("127.0.0.1"), 8443);

        bool ret = dtls.doHandshake(socket);
        if (!ret) {
            setResult(-1);
            printTestFailed("handshake failed too early");
            dtls.shutdown(socket);
            return;
        }

        while (socket->waitForReadyRead(200)) {
            qint64 bytesToRead = socket->pendingDatagramSize();
            QByteArray dgram(bytesToRead, Qt::Uninitialized);
            qint64 bytesRead = socket->readDatagram(dgram.data(), dgram.size());
            dgram.resize(bytesRead);
            dtls.doHandshake(socket, dgram);
        }

        bool verifyError = false;
        if (dtls.peerVerificationErrors().size() > 0) {
            verifyError = true;
            dtls.abortHandshake(socket); // this clears DTLS errors too
        }

        if (verifyError) {
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed("encrypted session was established, but should not");
        }
        dtls.shutdown(socket);
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
    QUdpSocket *socket;

};

// connect to localhost, but set server name to the same as for ssl server
// do verify peer certificate
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
        testSettings.setUseDtls(true);
        testSettings.setUserCN("www.example.com");
    }

    void executeNextSslTest()
    {
        if (!socket)
            socket = new QUdpSocket;

        XSslConfiguration conf;
        conf.setDtlsCookieVerificationEnabled(false);
        conf.setProtocol(XSsl::DtlsV1_0OrLater);
        conf.setPeerVerifyMode(XSslSocket::VerifyPeer);

        XDtls dtls(XSslSocket::SslClientMode);
        dtls.setPeer(QHostAddress("127.0.0.1"), 8443, "www.example.com");
        dtls.setDtlsConfiguration(conf);

        socket->connectToHost(QHostAddress("127.0.0.1"), 8443);

        bool ret = dtls.doHandshake(socket);
        if (!ret) {
            setResult(-1);
            printTestFailed("handshake failed too early");
            dtls.shutdown(socket);
            return;
        }

        while (socket->waitForReadyRead(200)) {
            qint64 bytesToRead = socket->pendingDatagramSize();
            QByteArray dgram(bytesToRead, Qt::Uninitialized);
            qint64 bytesRead = socket->readDatagram(dgram.data(), dgram.size());
            dgram.resize(bytesRead);
            dtls.doHandshake(socket, dgram);
        }

        bool verifyError = false;
        if (dtls.peerVerificationErrors().size() > 0) {
            verifyError = true;
            dtls.abortHandshake(socket); // this clears DTLS errors too
        }

        if (verifyError) {
            setResult(0);
        } else {
            setResult(-1);
            printTestFailed("encrypted session was established, but should not");
        }
        dtls.shutdown(socket);
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
    QUdpSocket *socket;

};


QList<Test *> createAutotests()
{
    return QList<Test *>()
            << new Test01(1, "SslTest02dtls", QList<SslTest *>() << new SslTestCertSS1)
            << new Test02(2, "SslTest02dtls", QList<SslTest *>() << new SslTestCertSS1)
            << new Test03(3, "SslTest02dtls", QList<SslTest *>() << new SslTestCertSS1)
            << new Test04(4, "SslTest02dtls", QList<SslTest *>() << new SslTestCertSS1)
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

#include "tests_SslTestCertSS1dtls.moc"
