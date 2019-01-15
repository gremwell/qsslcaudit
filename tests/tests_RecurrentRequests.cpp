#include "test.h"
#include "ssltests.h"
#include "ciphers.h"

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
    Test01(int times, int id, QString testBaseName, SslTest *sslTest) :
        Test(id, testBaseName, sslTest), times(times) {}

    void setTestSettings()
    {
        testSettings.setUserCN("www.example.com");
    }

public slots:

    void run()
    {
        XSslSocket *socket = new XSslSocket;
        QByteArray data = QByteArray("GET / HTTP/1.0\r\n\r\n");

        socket->setPeerVerifyMode(XSslSocket::VerifyNone);
        socket->setProtocol(XSsl::TlsV1_1OrLater);

        setResult(0);

        for (int i = 0; i < times; i++) {
            socket->connectToHostEncrypted("localhost", 8443);

            if (!socket->waitForEncrypted()) {
                qDebug() << socket->error();
                qDebug() << socket->errorString();

                setResult(-1);
                printTestFailed(QString("%1 attempts failed").arg(i));
                break;
            } else {
                socket->write(data);
                socket->waitForReadyRead();

                if (!waitForSslTestFinished()) {
                    socket->disconnectFromHost();
                    setResult(-1);
                    printTestFailed(QString("%1 attempts failed").arg(i));
                    break;
                }

                if ((sslTest->result() == SslTest::SSLTEST_RESULT_DATA_INTERCEPTED)
                        && (sslTest->interceptedData() == data)) {
                    ;
                } else {
                    socket->disconnectFromHost();
                    setResult(-1);
                    printTestFailed(QString("%1 attempts failed").arg(i));
                    break;
                }
            }

            socket->disconnectFromHost();

            // skip the listener launch for the last time
            if ((i != (times - 1)) && !launchSslCAudit()) {
                setResult(-1);
                printTestFailed(QString("%1 attempts failed").arg(i));
            }
        }

        if (getResult() == 0)
            printTestSucceeded();

        QThread::currentThread()->quit();
    }

private:
    int times;
};

// do verify peer certificate, use TLSv1.1 and stronger protocols
// check for proper test result code each time
class Test02 : public Test
{
    Q_OBJECT
public:
    Test02(int times, int id, QString testBaseName, SslTest *sslTest) :
        Test(id, testBaseName, sslTest), times(times) {}

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

        setResult(0);

        for (int i = 0; i < times; i++) {
            socket->connectToHostEncrypted("localhost", 8443);

            if (!socket->waitForEncrypted()) {
                if (!waitForSslTestFinished()) {
                    socket->disconnectFromHost();
                    setResult(-1);
                    printTestFailed(QString("%1 attempts failed").arg(i));
                    break;
                } else if ((sslTest->result() == SslTest::SSLTEST_RESULT_SUCCESS)
                           && (QString::compare(socket->errorString(),
                                                "The host name did not match any of the valid hosts for this certificate") == 0)) {
                    ;
                } else {
                    socket->disconnectFromHost();
                    setResult(-1);
                    printTestFailed(QString("%1 attempts failed, incorrect test result").arg(i));
                    break;
                }
            } else {
                socket->disconnectFromHost();
                setResult(-1);
                printTestFailed(QString("%1 attempts failed").arg(i));
                break;
            }

            socket->disconnectFromHost();

            // skip the listener launch for the last time
            if ((i != (times - 1)) && !launchSslCAudit()) {
                setResult(-1);
                printTestFailed(QString("%1 attempts failed").arg(i));
                break;
            }
        }

        if (getResult() == 0)
            printTestSucceeded();

        QThread::currentThread()->quit();
    }

private:
    int times;
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
    int times = 20;

    if (argc > 1) {
        QString arg(argv[1]);
        bool ok;
        int t = arg.toInt(&ok);
        if (ok)
            times = t;
    }

    QList<Test *> autotests = QList<Test *>()
            << new Test01(times, 1, "RecurrentRequests", new SslTest02)
            << new Test02(times, 2, "RecurrentRequests", new SslTest02)
               ;

    while (autotests.size() > 0) {
        Test *test = autotests.takeFirst();
        launchTest(test);
        if (test->getResult() != 0) {
            ret = -1;
        }
        test->deleteLater();
        // in this case, exit immideately
        if (ret != 0)
            break;
    }

    return ret;
}

#include "tests_RecurrentRequests.moc"
