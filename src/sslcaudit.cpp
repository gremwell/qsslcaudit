
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
    sslTests(QList<SslTest *>()),
    settings(settings)
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

void SslCAudit::runTest(SslTest *test)
{
    QHostAddress listenAddress = settings.getListenAddress();
    quint16 listenPort = settings.getListenPort();
    SslServer sslServer;

    WHITE("running test: " + test->description());

    sslServer.setSslLocalCertificateChain(test->localCert());

    sslServer.setSslPrivateKey(test->privateKey());

    sslServer.setSslProtocol(test->sslProtocol());

    sslServer.setSslCiphers(test->sslCiphers());

    sslServer.setStartTlsProto(settings.getStartTlsProtocol());

    if (sslServer.listen(listenAddress, listenPort)) {
        VERBOSE(QString("listening on %1:%2").arg(listenAddress.toString()).arg(listenPort));
    } else {
        RED(QString("can not bind to %1:%2").arg(listenAddress.toString()).arg(listenPort));
        return;
    }

    testSslErrors.clear();
    testSocketErrors.clear();
    testSslConnectionEstablished = false;
    testDataReceived = false;

    if (sslServer.waitForNewConnection(-1)) {
        XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(sslServer.nextPendingConnection());

        VERBOSE(QString("connection from: %1:%2").arg(sslSocket->peerAddress().toString()).arg(sslSocket->peerPort()));

        if (!settings.getForwardHostAddr().isNull()) {
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
                        testDataReceived = true;

                        proxy.write(sslSocket->readAll());
                    }

                    if (proxy.waitForReadyRead(100)) {
                        sslSocket->write(proxy.readAll());
                    }
                }
            }
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

                testDataReceived = true;

                sslSocket->disconnectFromHost();
                sslSocket->waitForDisconnected();
                VERBOSE("disconnected");
            } else {
                VERBOSE("no data received (" + sslSocket->errorString() + ")");
            }
        }
    } else {
        VERBOSE("could not establish encrypted connection (" + sslServer.errorString() + ")");
    }

    WHITE("report:");

    test->report(testSslErrors, testSocketErrors, testSslConnectionEstablished, testDataReceived);

    WHITE("test finished");
}

void SslCAudit::run()
{
    for (int i = 0; i < sslTests.size(); i++) {
        VERBOSE("");
        runTest(sslTests.at(i));
        VERBOSE("");
    }

    printSummary();

    this->deleteLater();
    QThread::currentThread()->quit();
    qApp->exit();
}

void SslCAudit::handleSocketError(QAbstractSocket::SocketError socketError)
{
    XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(sender());

    VERBOSE(QString("ssl error: %1 (%2)")
            .arg(sslSocket->errorString())
            .arg(sslSocket->error()));

    testSslErrors << sslSocket->sslErrors();
    testSocketErrors << socketError;

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
    }
}

void SslCAudit::handleSslErrors(const QList<XSslError> &errors)
{
    XSslError error;

    VERBOSE("SSL errors detected:");

    foreach (error, errors) {
        VERBOSE("\t" + error.errorString());
    }

    testSslErrors << errors;
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

    testSslConnectionEstablished = true;
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
        QString result = "FAILED";

        while (testName.length() > testColumnWidth) {
            printTableLine(testName.left(testColumnWidth - 2), "");
            testName = "  " + testName.mid(testColumnWidth - 2);
        }

        if (sslTests.at(i)->result() == 0) {
            result = "PASSED";
        }

        printTableLine(testName, result);
    }

    printTableHSeparator();
}
