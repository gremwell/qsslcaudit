#include "test.h"
#include "ssltests.h"

#include <QCoreApplication>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif

// This test verifies SslCAudit behaviour for various types of clients
// or connection states:
// 1. connection without data transmition, disconnect after short timeout
// 2. connection without data transmition, disconnect after long timeout (more than test waiting timeout)
// 3. connection with clear-text transmition of known (to OpenSSL) protocol, disconnect after short timeout
// 4. connection with clear-text transmition of known (to OpenSSL) protocol, disconnect after long timeout (more than test waiting timeout)
// 5. connection with clear-text transmition of small chunk of unknown (to OpenSSL) protocol, disconnect after short timeout
// 6. connection with clear-text transmition of small chunk of unknown (to OpenSSL) protocol, disconnect after long timeout (more than test waiting timeout)
// 7. connection with clear-text transmition of larger chunk of unknown (to OpenSSL) protocol, disconnect after short timeout
// 8. connection with clear-text transmition of larger chunk of unknown (to OpenSSL) protocol, disconnect after long timeout (more than test waiting timeout)
// 9. SSLv3 connection with certificate validation
// 10. SSLv3 connection without certificate validation, no data transmition, disconnect after long timeout
// 11. SSLv3 connection without certificate validation, no data transmition, disconnect after short timeout  !!!
// 12. SSLv3 connection without certificate validation, data transmition, disconnect after long timeout
// 13. SSLv3 connection without certificate validation, data transmition, disconnect after short timeout
// 14. TLSv1.1 connection with certificate validation
// 15. TLSv1.1 connection without certificate validation, no data transmition, disconnect after long timeout
// 16. TLSv1.1 connection without certificate validation, no data transmition, disconnect after short timeout  !!!
// 17. TLSv1.1 connection without certificate validation, data transmition, disconnect after long timeout
// 18. TLSv1.1 connection without certificate validation, data transmition, disconnect after short timeout
// 19. FTP STARTTLS, with certificate validation
// 20. FTP STARTTLS, without certificate validation, no data transmition, disconnect after long timeout
// 21. FTP STARTTLS, without certificate validation, no data transmition, disconnect after short timeout  !!!
// 22. FTP STARTTLS, without certificate validation, data transmition, disconnect after long timeout
// 23. FTP STARTTLS, without certificate validation, data transmition, disconnect after short timeout
// 24. transmit only SSLv3 HELLO message and disconnect after long timeout
// 25. transmit only SSLv3 HELLO message and disconnect after short timeout !!!
// 26. transmit only part of SSLv3 HELLO message and disconnect after long timeout
// 27. transmit only part of SSLv3 HELLO message and disconnect after short timeout !!!
//
// As a reference SslTest02 is used:
// "certificate trust test with self-signed certificate for user-supplied common name"

// connection without data transmition, disconnect after short timeout
class Test01 : public Test
{
    Q_OBJECT
public:
    Test01(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QTcpSocket *socket = new QTcpSocket;

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            QThread::msleep(10);
            socket->disconnectFromHost();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }

        QThread::currentThread()->quit();
    }
};

// connection without data transmition, disconnect after long timeout (more than test waiting timeout)
class Test02 : public Test
{
    Q_OBJECT
public:
    Test02(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QTcpSocket *socket = new QTcpSocket;

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }

        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// connection with clear-text transmition of known (to OpenSSL) protocol, disconnect after short timeout
class Test03 : public Test
{
    Q_OBJECT
public:
    Test03(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QTcpSocket *socket = new QTcpSocket;
        QByteArray data = QByteArray("GET / HTTP/1.0\r\n\r\n");

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->waitForReadyRead();
            QThread::msleep(10);
            socket->disconnectFromHost();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }

        QThread::currentThread()->quit();
    }
};

// connection with clear-text transmition of known (to OpenSSL) protocol, disconnect after long timeout
class Test04 : public Test
{
    Q_OBJECT
public:
    Test04(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QTcpSocket *socket = new QTcpSocket;
        QByteArray data = QByteArray("GET / HTTP/1.0\r\n\r\n");

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->waitForReadyRead();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }

        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// connection with clear-text transmition of small chunk of unknown (to OpenSSL) protocol, disconnect after short timeout
class Test05 : public Test
{
    Q_OBJECT
public:
    Test05(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QTcpSocket *socket = new QTcpSocket;
        QByteArray data = QByteArray("ABCDEF");

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->flush();
            QThread::msleep(10);
            socket->disconnectFromHost();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }

        QThread::currentThread()->quit();
    }
};

// connection with clear-text transmition of small chunk of unknown (to OpenSSL) protocol, disconnect after long timeout
class Test06 : public Test
{
    Q_OBJECT
public:
    Test06(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QTcpSocket *socket = new QTcpSocket;
        QByteArray data = QByteArray("ABCDEF");

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->flush();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }

        socket->disconnectFromHost();

        QThread::currentThread()->quit();
    }
};

// connection with clear-text transmition of larger chunk of unknown (to OpenSSL) protocol, disconnect after short timeout
class Test07 : public Test
{
    Q_OBJECT
public:
    Test07(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QTcpSocket *socket = new QTcpSocket;
        QByteArray data = QByteArray("ABCDEFGHIJKLMNOP\n");

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->flush();
            QThread::msleep(10);
            socket->disconnectFromHost();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }

        QThread::currentThread()->quit();
    }
};

// connection with clear-text transmition of larger chunk of unknown (to OpenSSL) protocol, disconnect after long timeout
class Test08 : public Test
{
    Q_OBJECT
public:
    Test08(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QTcpSocket *socket = new QTcpSocket;
        QByteArray data = QByteArray("ABCDEFGHIJKLMNOP\n");

        socket->connectToHost("localhost", 8443);

        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->flush();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }

        socket->disconnectFromHost();

        QThread::currentThread()->quit();
    }
};

#ifdef UNSAFE
// SSLv3 connection with certificate validation
class Test09 : public Test
{
    Q_OBJECT
public:
    Test09(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::SslV3);
        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if ((QString::compare(socket->errorString(),
                                         "The host name did not match any of the valid hosts for this certificate") == 0)
                       && (sslTests.first()->result() == SslTest::SSLTEST_RESULT_SUCCESS)) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }

        } else {
            setResult(-1);
            printTestFailed("can't establish encrypted session");
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }

};

// SSLv3 connection without certificate validation, no data transmition, disconnect after long timeout
class Test10 : public Test
{
    Q_OBJECT
public:
    Test10(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::SslV3);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_CERT_ACCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }

};

// SSLv3 connection without certificate validation, no data transmition, disconnect after short timeout
class Test11 : public Test
{
    Q_OBJECT
public:
    Test11(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::SslV3);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            QThread::msleep(10);
            socket->close();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }

};

// SSLv3 connection without certificate validation, data transmition, disconnect after long timeout
class Test12 : public Test
{
    Q_OBJECT
public:
    Test12(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QByteArray data = QByteArray("GET / HTTP/1.0\r\n\r\n");
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::SslV3);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            socket->write(data);
            socket->flush();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// SSLv3 connection without certificate validation, data transmition, disconnect after short timeout
class Test13 : public Test
{
    Q_OBJECT
public:
    Test13(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QByteArray data = QByteArray("GET / HTTP/1.0\r\n\r\n");
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::SslV3);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            socket->write(data);
            socket->flush();
            QThread::msleep(10);
            socket->close();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};
#endif

// TLSv1.1 connection with certificate validation
class Test14 : public Test
{
    Q_OBJECT
public:
    Test14(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if ((QString::compare(socket->errorString(),
                                         "The host name did not match any of the valid hosts for this certificate") == 0)
                       && (sslTests.first()->result() == SslTest::SSLTEST_RESULT_SUCCESS)) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }

        } else {
            setResult(-1);
            printTestFailed("can't establish encrypted session");
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }

};

// TLSv1.1 connection without certificate validation, no data transmition, disconnect after long timeout
class Test15 : public Test
{
    Q_OBJECT
public:
    Test15(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_CERT_ACCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }

};

// TLSv1.1 connection without certificate validation, no data transmition, disconnect after short timeout
class Test16 : public Test
{
    Q_OBJECT
public:
    Test16(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            QThread::msleep(10);
            socket->close();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }

};

// TLSv1.1 connection without certificate validation, data transmition, disconnect after long timeout
class Test17 : public Test
{
    Q_OBJECT
public:
    Test17(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QByteArray data = QByteArray("GET / HTTP/1.0\r\n\r\n");
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            socket->write(data);
            socket->flush();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// TLSv1.1 connection without certificate validation, data transmition, disconnect after short timeout
class Test18 : public Test
{
    Q_OBJECT
public:
    Test18(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QByteArray data = QByteArray("GET / HTTP/1.0\r\n\r\n");
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->connectToHostEncrypted("localhost", 8443);

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            socket->write(data);
            socket->flush();
            QThread::msleep(10);
            socket->close();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// FTP STARTTLS, with certificate validation
class Test19 : public Test
{
    Q_OBJECT
public:
    Test19(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
        testSettings.setStartTlsProtocol("ftp");
    }

public slots:

    void run()
    {
        QByteArray data = QByteArray("AUTH TLS\r\n");
        QByteArray buf;
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyPeer);

        socket->connectToHost("localhost", 8443);
        socket->waitForReadyRead();

        buf = socket->readAll();
        if (buf != QByteArray("220 ready.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->write(data);
        socket->flush();
        socket->waitForReadyRead();
        buf = socket->readAll();
        if (buf != QByteArray("234 AUTH TLS successful.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->startClientEncryption();

        if (!socket->waitForEncrypted()) {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if ((QString::compare(socket->errorString(),
                                         "The host name did not match any of the valid hosts for this certificate") == 0)
                       && (sslTests.first()->result() == SslTest::SSLTEST_RESULT_SUCCESS)) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }

        } else {
            setResult(-1);
            printTestFailed("session was encrypted but should not");
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// FTP STARTTLS, without certificate validation, no data transmition, disconnect after long timeout
class Test20 : public Test
{
    Q_OBJECT
public:
    Test20(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
        testSettings.setStartTlsProtocol("ftp");
    }

public slots:

    void run()
    {
        QByteArray data = QByteArray("AUTH TLS\r\n");
        QByteArray buf;
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);

        socket->connectToHost("localhost", 8443);
        socket->waitForReadyRead();

        buf = socket->readAll();
        if (buf != QByteArray("220 ready.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->write(data);
        socket->flush();
        socket->waitForReadyRead();
        buf = socket->readAll();
        if (buf != QByteArray("234 AUTH TLS successful.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->startClientEncryption();

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_CERT_ACCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// FTP STARTTLS, without certificate validation, no data transmition, disconnect after short timeout
class Test21 : public Test
{
    Q_OBJECT
public:
    Test21(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
        testSettings.setStartTlsProtocol("ftp");
    }

public slots:

    void run()
    {
        QByteArray data = QByteArray("AUTH TLS\r\n");
        QByteArray buf;
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);

        socket->connectToHost("localhost", 8443);
        socket->waitForReadyRead();

        buf = socket->readAll();
        if (buf != QByteArray("220 ready.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->write(data);
        socket->flush();
        socket->waitForReadyRead();
        buf = socket->readAll();
        if (buf != QByteArray("234 AUTH TLS successful.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->startClientEncryption();

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            QThread::msleep(10);
            socket->close();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_CERT_ACCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// FTP STARTTLS, without certificate validation, data transmition, disconnect after long timeout
class Test22 : public Test
{
    Q_OBJECT
public:
    Test22(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
        testSettings.setStartTlsProtocol("ftp");
    }

public slots:

    void run()
    {
        QByteArray data = QByteArray("AUTH TLS\r\n");
        QByteArray userData = QByteArray("CWD /root\r\n");
        QByteArray buf;
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);

        socket->connectToHost("localhost", 8443);
        socket->waitForReadyRead();

        buf = socket->readAll();
        if (buf != QByteArray("220 ready.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->write(data);
        socket->flush();
        socket->waitForReadyRead();
        buf = socket->readAll();
        if (buf != QByteArray("234 AUTH TLS successful.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->startClientEncryption();

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            socket->write(userData);
            socket->flush();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// FTP STARTTLS, without certificate validation, data transmition, disconnect after short timeout
class Test23 : public Test
{
    Q_OBJECT
public:
    Test23(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
        testSettings.setStartTlsProtocol("ftp");
    }

public slots:

    void run()
    {
        QByteArray data = QByteArray("AUTH TLS\r\n");
        QByteArray userData = QByteArray("CWD /root\r\n");
        QByteArray buf;
        XSslSocket *socket = new XSslSocket;
        socket->setProtocol(XSsl::TlsV1_1);
        socket->setPeerVerifyMode(XSslSocket::VerifyNone);

        socket->connectToHost("localhost", 8443);
        socket->waitForReadyRead();

        buf = socket->readAll();
        if (buf != QByteArray("220 ready.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->write(data);
        socket->flush();
        socket->waitForReadyRead();
        buf = socket->readAll();
        if (buf != QByteArray("234 AUTH TLS successful.\r\n")) {
            setResult(-1);
            printTestFailed("invalid STARTTLS sequence");
            socket->disconnectFromHost();
            QThread::currentThread()->quit();
            return;
        }

        socket->startClientEncryption();

        if (!socket->waitForEncrypted()) {
            setResult(-1);
            printTestFailed("encrypted session not established");
        } else {
            socket->write(userData);
            socket->flush();
            QThread::msleep(10);
            socket->close();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// transmit only SSLv3 HELLO message and disconnect after long timeout
class Test24 : public Test
{
    Q_OBJECT
public:
    Test24(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QByteArray data(QByteArray::fromRawData("\x16\x03\x00\x00\x95\x01\x00\x00\x91\x03\x00\xf5\xe7\xaf\xcc\x96" \
                                                "\x2b\x74\x42\x2f\x75\x12\x4f\xb3\x6c\x69\xae\x8c\x54\xfa\xc3\x19" \
                                                "\x9a\xea\xee\xb6\x81\xb8\xb6\xe6\xa2\x6c\xf0\x00\x00\x6a\xc0\x14" \
                                                "\xc0\x0a\x00\x39\x00\x38\x00\x37\x00\x36\x00\x88\x00\x87\x00\x86" \
                                                "\x00\x85\xc0\x19\x00\x3a\x00\x89\xc0\x0f\xc0\x05\x00\x35\x00\x84" \
                                                "\x00\x8d\xc0\x13\xc0\x09\x00\x33\x00\x32\x00\x31\x00\x30\x00\x9a" \
                                                "\x00\x99\x00\x98\x00\x97\x00\x45\x00\x44\x00\x43\x00\x42\xc0\x18" \
                                                "\x00\x34\x00\x9b\x00\x46\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41" \
                                                "\x00\x07\x00\x8c\xc0\x11\xc0\x07\xc0\x16\x00\x18\xc0\x0c\xc0\x02" \
                                                "\x00\x05\x00\x04\x00\x8a\x00\xff\x01\x00", 154));
        QTcpSocket *socket = new QTcpSocket;

        socket->connectToHost("localhost", 8443);
        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->flush();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// transmit only SSLv3 HELLO message and disconnect after short timeout
class Test25 : public Test
{
    Q_OBJECT
public:
    Test25(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QByteArray data(QByteArray::fromRawData("\x16\x03\x00\x00\x95\x01\x00\x00\x91\x03\x00\xf5\xe7\xaf\xcc\x96" \
                                                "\x2b\x74\x42\x2f\x75\x12\x4f\xb3\x6c\x69\xae\x8c\x54\xfa\xc3\x19" \
                                                "\x9a\xea\xee\xb6\x81\xb8\xb6\xe6\xa2\x6c\xf0\x00\x00\x6a\xc0\x14" \
                                                "\xc0\x0a\x00\x39\x00\x38\x00\x37\x00\x36\x00\x88\x00\x87\x00\x86" \
                                                "\x00\x85\xc0\x19\x00\x3a\x00\x89\xc0\x0f\xc0\x05\x00\x35\x00\x84" \
                                                "\x00\x8d\xc0\x13\xc0\x09\x00\x33\x00\x32\x00\x31\x00\x30\x00\x9a" \
                                                "\x00\x99\x00\x98\x00\x97\x00\x45\x00\x44\x00\x43\x00\x42\xc0\x18" \
                                                "\x00\x34\x00\x9b\x00\x46\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41" \
                                                "\x00\x07\x00\x8c\xc0\x11\xc0\x07\xc0\x16\x00\x18\xc0\x0c\xc0\x02" \
                                                "\x00\x05\x00\x04\x00\x8a\x00\xff\x01\x00", 154));
        QTcpSocket *socket = new QTcpSocket;

        socket->connectToHost("localhost", 8443);
        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->flush();
            QThread::msleep(500);
            socket->close();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// transmit only part of SSLv3 HELLO message and disconnect after long timeout
class Test26 : public Test
{
    Q_OBJECT
public:
    Test26(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QByteArray data(QByteArray::fromRawData("\x16\x03\x00\x00\x95\x01\x00\x00\x91\x03\x00\xf5\xe7\xaf\xcc\x96" \
                                                "\x2b\x74\x42\x2f\x75\x12\x4f\xb3\x6c\x69\xae\x8c\x54\xfa\xc3\x19" \
                                                "\x9a\xea\xee\xb6\x81\xb8\xb6\xe6\xa2\x6c\xf0\x00\x00\x6a\xc0\x14" \
                                                "\xc0\x0a\x00\x39\x00\x38\x00\x37\x00\x36\x00\x88\x00\x87\x00\x86" \
                                                "\x00\x85\xc0\x19\x00\x3a\x00\x89\xc0\x0f\xc0\x05\x00\x35\x00\x84" \
                                                "\x00\x8d\xc0\x13\xc0\x09\x00\x33\x00\x32\x00\x31\x00\x30\x00\x9a" \
                                                "\x00\x99\x00\x98\x00\x97\x00\x45\x00\x44\x00\x43\x00\x42\xc0\x18" \
                                                "\x00\x34\x00\x9b\x00\x46\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41" \
                                                "\x00\x07\x00\x8c\xc0\x11\xc0\x07\xc0\x16\x00\x18\xc0\x0c\xc0\x02" \
                                                "\x00\x05\x00\x04\x00\x8a\x00\xff\x01\x00", 100));
        QTcpSocket *socket = new QTcpSocket;

        socket->connectToHost("localhost", 8443);
        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->flush();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
            }
        }
        socket->disconnectFromHost();
        QThread::currentThread()->quit();
    }
};

// transmit only part of SSLv3 HELLO message and disconnect after short timeout
class Test27 : public Test
{
    Q_OBJECT
public:
    Test27(int id, QString testBaseName, QList<SslTest *> sslTests) : Test(id, testBaseName, sslTests){}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        QByteArray data(QByteArray::fromRawData("\x16\x03\x00\x00\x95\x01\x00\x00\x91\x03\x00\xf5\xe7\xaf\xcc\x96" \
                                                "\x2b\x74\x42\x2f\x75\x12\x4f\xb3\x6c\x69\xae\x8c\x54\xfa\xc3\x19" \
                                                "\x9a\xea\xee\xb6\x81\xb8\xb6\xe6\xa2\x6c\xf0\x00\x00\x6a\xc0\x14" \
                                                "\xc0\x0a\x00\x39\x00\x38\x00\x37\x00\x36\x00\x88\x00\x87\x00\x86" \
                                                "\x00\x85\xc0\x19\x00\x3a\x00\x89\xc0\x0f\xc0\x05\x00\x35\x00\x84" \
                                                "\x00\x8d\xc0\x13\xc0\x09\x00\x33\x00\x32\x00\x31\x00\x30\x00\x9a" \
                                                "\x00\x99\x00\x98\x00\x97\x00\x45\x00\x44\x00\x43\x00\x42\xc0\x18" \
                                                "\x00\x34\x00\x9b\x00\x46\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41" \
                                                "\x00\x07\x00\x8c\xc0\x11\xc0\x07\xc0\x16\x00\x18\xc0\x0c\xc0\x02" \
                                                "\x00\x05\x00\x04\x00\x8a\x00\xff\x01\x00", 100));
        QTcpSocket *socket = new QTcpSocket;

        socket->connectToHost("localhost", 8443);
        if (!socket->waitForConnected()) {
            setResult(-1);
            printTestFailed("can't connect to qsslcaudit");
        } else {
            socket->write(data);
            socket->flush();
            QThread::msleep(500);
            socket->close();

            if (!waitForSslTestFinished()) {
                setResult(-1);
                printTestFailed("test was not finished in time");
            } else if (sslTests.first()->result() == SslTest::SSLTEST_RESULT_UNDEFINED) {
                setResult(0);
                printTestSucceeded();
            } else {
                setResult(-1);
                printTestFailed(QString("unexpected test result (%1)").arg(sslTests.first()->result()));
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
            << new Test01(1, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test02(2, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test03(3, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test04(4, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test05(5, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test06(6, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test07(7, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test08(8, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
           #ifdef UNSAFE
            << new Test09(9, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test10(10, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
//            << new Test11(11, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test12(12, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test13(13, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
           #endif
            << new Test14(14, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test15(15, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
//            << new Test16(16, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test17(17, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test18(18, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test19(19, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test20(20, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
//            << new Test21(21, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test22(22, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test23(23, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test24(24, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
//            << new Test25(25, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
            << new Test26(26, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
//            << new Test27(27, "DifferentClientTypes", QList<SslTest *>() << new SslTest02)
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

#include "tests_DifferentClientTypes.moc"
