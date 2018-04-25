
#include "sslcaudit.h"
#include "sslserver.h"
#include "debug.h"

#include <QCoreApplication>
#include <QThread>
#include <QFile>

#ifdef UNSAFE
#include "sslunsafesocket.h"
#include "sslunsafeconfiguration.h"
#else
#include <QSslSocket>
#include <QSslConfiguration>
#endif


SslCAudit::SslCAudit(const SslUserSettings settings, QObject *parent) :
    QObject(parent),
    settings(settings),
    sslTests(QList<SslTest *>())
{
    VERBOSE("SSL library used: " + XSslSocket::sslLibraryVersionString());
}

void SslCAudit::showCiphers()
{
    VERBOSE("supported ciphers:");
    QList<XSslCipher> ciphers = XSslConfiguration::supportedCiphers();
    QString ciphersString = "\t";
    for (int i = 0; i < ciphers.size(); i++) {
        ciphersString += ciphers.at(i).name() + " ";
        if (((i + 1) % 4) == 0) {
            VERBOSE(ciphersString);
            ciphersString = "\t";
        }
    }
}

void SslCAudit::setSslTests(const QList<SslTest *> &tests)
{
    sslTests = tests;
}

SslServer *SslCAudit::prepareSslServer(const SslTest *test)
{
    QHostAddress listenAddress = settings.getListenAddress();
    quint16 listenPort = settings.getListenPort();
    SslServer *sslServer = new SslServer;

    sslServer->setSslLocalCertificateChain(test->localCert());

    sslServer->setSslPrivateKey(test->privateKey());

    sslServer->setSslProtocol(test->sslProtocol());

    sslServer->setSslCiphers(test->sslCiphers());

    sslServer->setStartTlsProto(settings.getStartTlsProtocol());

    if (!sslServer->listen(listenAddress, listenPort)) {
        RED(QString("can not bind to %1:%2").arg(listenAddress.toString()).arg(listenPort));
        sslServer->deleteLater();
        return nullptr;
    }

    VERBOSE(QString("listening on %1:%2").arg(listenAddress.toString()).arg(listenPort));
    return sslServer;
}

void SslCAudit::proxyConnection(XSslSocket *sslSocket, SslTest *test)
{
    // in case 'forward' option was set, we do the following:
    // - connect to the proxy;
    // - synchronously read data from ssl socket
    // - synchronously send this data to proxy
    QTcpSocket proxy;

    proxy.connectToHost(settings.getForwardHostAddr(), settings.getForwardHostPort());

    if (!proxy.waitForConnected(2000)) {
        RED("can't connect to the forward proxy");
    } else {
        WHITE("forwarding incoming data to the provided proxy");
        WHITE("to get test results, relauch this app without 'forward' option");

        while (1) {
            if (sslSocket->state() == QAbstractSocket::UnconnectedState)
                break;
            if (proxy.state() == QAbstractSocket::UnconnectedState)
                break;

            if (sslSocket->waitForReadyRead(100)) {
                QByteArray data = sslSocket->readAll();

                test->addInterceptedData(data);

                proxy.write(data);
            }

            if (proxy.waitForReadyRead(100)) {
                sslSocket->write(proxy.readAll());
            }
        }
    }
}

void SslCAudit::handleIncomingConnection(XSslSocket *sslSocket, SslTest *test)
{
    VERBOSE(QString("connection from: %1:%2").arg(sslSocket->peerAddress().toString()).arg(sslSocket->peerPort()));

    if (!settings.getForwardHostAddr().isNull()) {
        // this will loop until connection is interrupted
        proxyConnection(sslSocket, test);
    } else {
        // handling socket errors makes sence only in non-interception mode

        connect(sslSocket, static_cast<void(XSslSocket::*)(QAbstractSocket::SocketError)>(&XSslSocket::error),
                this, &SslCAudit::handleSocketError);
        connect(sslSocket, &XSslSocket::encrypted, this, &SslCAudit::sslHandshakeFinished);
        connect(sslSocket, static_cast<void(XSslSocket::*)(const QList<XSslError> &)>(&XSslSocket::sslErrors),
                this, &SslCAudit::handleSslErrors);
        connect(sslSocket, &XSslSocket::peerVerifyError, this, &SslCAudit::handlePeerVerifyError);

        // no 'forward' option -- just read the first packet of unencrypted data and close the connection
        if (sslSocket->waitForReadyRead(5000)) {
            QByteArray message = sslSocket->readAll();

            VERBOSE("received data: " + QString(message));

            test->addInterceptedData(message);

            sslSocket->disconnectFromHost();
            sslSocket->waitForDisconnected();
            VERBOSE("disconnected");
        } else {
            VERBOSE("no data received (" + sslSocket->errorString() + ")");
        }
    }
}

void SslCAudit::runTest(SslTest *test)
{
    SslServer *sslServer;

    WHITE("running test: " + test->description());

    sslServer = prepareSslServer(test);
    if (!sslServer) {
        return;
    }

    emit sslTestReady();

    if (sslServer->waitForNewConnection(-1)) {
        // check if *server* was not able to setup SSL connection
        QStringList sslInitErrors = sslServer->getSslInitErrorsStr();

        if (sslInitErrors.size() > 0) {
            RED("failure during SSL initialization, test will not continue");

            for (int i = 0; i < sslInitErrors.size(); i++) {
                VERBOSE("\t" + sslInitErrors.at(i));
            }

            test->addSocketErrors(sslServer->getSslInitErrors());
            test->calcResults();

            sslServer->close();
            sslServer->deleteLater();
            return;
        }

        // now we can hanle client side
        XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(sslServer->nextPendingConnection());
        // this call will loop until connection close if 'forward' option is set
        handleIncomingConnection(sslSocket, test);
    } else {
        VERBOSE("could not establish encrypted connection (" + sslServer->errorString() + ")");
    }

    sslServer->close();
    sslServer->deleteLater();

    test->calcResults();

    WHITE("report:");

    test->printReport();

    WHITE("test finished");
}

void SslCAudit::run()
{
    do {
        for (int i = 0; i < sslTests.size(); i++) {
            VERBOSE("");
            currentTest = sslTests.at(i);
            currentTest->clear();
            runTest(currentTest);
            VERBOSE("");
        }
    } while (settings.getLoopTests());

    emit sslTestsFinished();

    this->deleteLater();
    QThread::currentThread()->quit();
}

void SslCAudit::handleSocketError(QAbstractSocket::SocketError socketError)
{
    XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(sender());

    VERBOSE(QString("ssl error: %1 (%2)")
            .arg(sslSocket->errorString())
            .arg(sslSocket->error()));

    currentTest->addSslErrors(sslSocket->sslErrors());
    currentTest->addSslErrorString(sslSocket->errorString());
    currentTest->addSocketErrors(QList<QAbstractSocket::SocketError>() << socketError);

    switch (socketError) {
    case QAbstractSocket::SslInvalidUserDataError:
        VERBOSE("\tInvalid data (certificate, key, cypher, etc.) was provided and its use resulted in an error in the SSL library.");
        break;
    case QAbstractSocket::SslInternalError:
        VERBOSE("\tThe SSL library being used reported an internal error. This is probably the result of a bad installation or misconfiguration of the library.");
        break;
    case QAbstractSocket::SslHandshakeFailedError:
        VERBOSE("\tThe SSL/TLS handshake failed, so the connection was closed.");
        break;
    default:
        // just ignore all other errors
        break;
    }
}

void SslCAudit::handleSslErrors(const QList<XSslError> &errors)
{
    XSslError error;

    VERBOSE("SSL errors detected:");

    foreach (error, errors) {
        VERBOSE("\t" + error.errorString());
        currentTest->addSslErrorString(error.errorString());
    }

    currentTest->addSslErrors(errors);
}

void SslCAudit::sslHandshakeFinished()
{
    XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(sender());

    VERBOSE("SSL connection established");

    QList<XSslCertificate> clientCerts = sslSocket->peerCertificateChain();

    if (clientCerts.size() > 0) {
        VERBOSE(QString("\tclient supplied chain of %1 certificates").arg(clientCerts.size()));
        for (int i = 0; i < clientCerts.size(); i++) {
            VERBOSE(clientCerts.at(i).toPem());
        }
    }

    currentTest->setSslConnectionStatus(true);
}

void SslCAudit::handlePeerVerifyError(const XSslError &error)
{
    VERBOSE("peer verify error:");
    VERBOSE("\t" + error.errorString());
}

static const int testColumnWidth = 64;
static const int resultColumnWidth = 12;

static void printTableHSeparator()
{
    QTextStream out(stdout);

    out << "+";
    for (int i = 0; i < testColumnWidth + 2; i++) {
        out << "-";
    }
    out << "+";
    for (int i = 0; i < resultColumnWidth + 2; i++) {
        out << "-";
    }
    out << "+";
    out << endl;
}

static void printTableHeaderLine(const QString &c1String, const QString &c2String)
{
    QTextStream out(stdout);

    out.setFieldAlignment(QTextStream::AlignCenter);

    out << "| ";
    out << qSetFieldWidth(testColumnWidth);
    out << c1String;
    out << qSetFieldWidth(0);
    out << " | ";
    out << qSetFieldWidth(resultColumnWidth);
    out << c2String;
    out << qSetFieldWidth(0);
    out << " |";
    out << endl;
}

static void printTableLine(const QString &c1String, const QString &c2String)
{
    QTextStream out(stdout);

    out << "| ";
    out << qSetFieldWidth(testColumnWidth);
    out.setFieldAlignment(QTextStream::AlignLeft);
    out << c1String;
    out << qSetFieldWidth(0);
    out << " | ";
    out << qSetFieldWidth(resultColumnWidth);
    out.setFieldAlignment(QTextStream::AlignCenter);
    out << c2String;
    out << qSetFieldWidth(0);
    out << " |";
    out << endl;
}

void SslCAudit::printSummary()
{
    WHITE("tests results summary table:");

    printTableHSeparator();
    printTableHeaderLine("Test Name", "Result");
    printTableHSeparator();

    for (int i = 0; i < sslTests.size(); i++) {
        QString testName = sslTests.at(i)->name();
        QString result;

        while (testName.length() > testColumnWidth) {
            printTableLine(testName.left(testColumnWidth - 2), "");
            testName = "  " + testName.mid(testColumnWidth - 2);
        }

        switch (sslTests.at(i)->result()) {
        case SslTest::SSLTEST_RESULT_SUCCESS:
            result = "PASSED";
            break;
        case SslTest::SSLTEST_RESULT_UNDEFINED:
        case SslTest::SSLTEST_RESULT_INIT_FAILED:
            result = "UNDEFINED";
            break;
        default:
            result = "FAILED";
        }

        printTableLine(testName, result);
    }

    printTableHSeparator();
}
