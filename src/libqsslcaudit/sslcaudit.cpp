
#include "sslcaudit.h"
#include "sslserver.h"
#include "debug.h"

#include <QCoreApplication>
#include <QThread>
#include <QFile>
#include <QXmlStreamWriter>

#ifdef UNSAFE_QSSL
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

    test->setClientSourceHost(sslSocket->peerAddress().toString());

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
        if (sslSocket->waitForReadyRead(settings.getWaitDataTimeout())) {
            QByteArray message = sslSocket->readAll();

            VERBOSE("received data: " + QString(message));

            test->addInterceptedData(message);
        } else {
            VERBOSE("no unencrypted data received (" + sslSocket->errorString() + ")");
        }

#ifdef UNSAFE_QSSL
        test->addRawDataRecv(sslSocket->getRawReadData());
        test->addRawDataSent(sslSocket->getRawWrittenData());
#endif

        sslSocket->disconnectFromHost();
        if (sslSocket->state() != QAbstractSocket::UnconnectedState)
            sslSocket->waitForDisconnected();
        VERBOSE("disconnected");
    }
}

void SslCAudit::runTest(SslTest *test)
{
    SslServer *sslServer;

    WHITE(QString("running test #%1: %2").arg(test->id()).arg(test->description()));

    sslServer = prepareSslServer(test);
    if (!sslServer) {
        // this place is in the middle of code path and others could expect
        // some return values, signals, etc.
        // however, if we can not setup listener (mostly due to permission/busy errors)
        // for one test, all others will fail.
        // there is no strong reason to attempt to recover from that, thus, exit with
        // non-zero code
        // alternative way -- test availability of socket prior launching SslCaudit
        exit(-1);
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
        // be sure that socket is disconnected
        sslSocket->close();
        sslSocket->deleteLater();
    } else {
        VERBOSE("could not establish encrypted connection (" + sslServer->errorString() + ")");
    }

    sslServer->close();
    sslServer->deleteLater();

    test->calcResults();

    WHITE("report:");

    test->printReport();

    WHITE("test finished");

    emit sslTestFinished();
}

void SslCAudit::run()
{
    clientsInfo.clear();

    do {
        for (int i = 0; i < sslTests.size(); i++) {
            VERBOSE("");
            currentTest = sslTests.at(i);
            currentTest->clear();
            runTest(currentTest);
            clientsInfo << currentTest->clientInfo();
            VERBOSE("");
        }
    } while (settings.getLoopTests());

    emit sslTestsFinished();
}

bool SslCAudit::isSameClient(bool doPrint)
{
    TlsClientInfo client0;
    bool ret = true;

    if (!clientsInfo.size())
        return ret;

    client0 = clientsInfo.at(0);

    for (int i = 1; i < clientsInfo.size(); i++) {
        if (client0 != clientsInfo.at(i)) {
            ret = false;

            if (doPrint) {
                static bool headerPrinted = false;

                if (!headerPrinted) {
                    RED("not all connections were established by the same client, compare the following:");
                    VERBOSE("client #0");
                    VERBOSE(client0.printable());
                    headerPrinted = true;
                }

                VERBOSE(QString("client #%1").arg(i));
                VERBOSE(clientsInfo.at(i).printable());
            } else {
                break;
            }
        }
    }

    if (ret && doPrint) {
        GREEN("most likely all connections were established by the same client, some collected details:");
        VERBOSE(client0.printable());
    }

    return ret;
}

void SslCAudit::handleSocketError(QAbstractSocket::SocketError socketError)
{
    XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(sender());
    QString errorStr = sslSocket->errorString();
    int errorCode = sslSocket->error();

    VERBOSE(QString("ssl error: %1 (%2)").arg(errorStr).arg(errorCode));

    currentTest->addSslErrors(sslSocket->sslErrors());
    currentTest->addSslErrorString(errorStr);
    currentTest->addSocketErrors(QList<QAbstractSocket::SocketError>() << socketError);

    switch (socketError) {
    case QAbstractSocket::SslInvalidUserDataError:
        VERBOSE("\tInvalid data (certificate, key, cypher, etc.) was provided and its use resulted in an error in the SSL library.");
        break;
    case QAbstractSocket::SslInternalError:
        VERBOSE("\tThe SSL library being used reported an internal error. This is probably the result of a bad installation or misconfiguration of the library.");
        break;
    case QAbstractSocket::SslHandshakeFailedError:
        if (errorStr.contains(QString("ssl3_get_client_hello:no shared cipher"))) {
            VERBOSE("\tThe SSL/TLS handshake failed (client did not provide expected ciphers), so the connection was closed.");
        } else if (errorStr.contains(QString("ssl3_read_bytes:tlsv1 alert protocol version"))) {
            VERBOSE("\tThe SSL/TLS handshake failed (client refused the proposed protocol), so the connection was closed.");
        } else {
            VERBOSE("\tThe SSL/TLS handshake failed, so the connection was closed.");
        }
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

static const int testIdWidth = 3;
static const int testColumnWidth = 34;
static const int resultColumnWidth = 10;
static const int commentColumnWidth = 27;

static void printTableHSeparator()
{
    QTextStream out(stdout);

    out << "+";
    for (int i = 0; i < testIdWidth +1; i++) {
        out << "-";
    }
    out << "+";
    for (int i = 0; i < testColumnWidth + 2; i++) {
        out << "-";
    }
    out << "+";
    for (int i = 0; i < resultColumnWidth + 2; i++) {
        out << "-";
    }
    out << "+";
    for (int i = 0; i < commentColumnWidth + 2; i++) {
        out << "-";
    }
    out << "+";
    out << endl;
}

static void printTableHeaderLine(const QString &c0String, const QString &c1String, const QString &c2String, const QString &c3String)
{
    QTextStream out(stdout);

    out.setFieldAlignment(QTextStream::AlignCenter);

    out << "| ";
    out << qSetFieldWidth(testIdWidth);
    out << c0String;
    out << qSetFieldWidth(0);
    out << "| ";
    out << qSetFieldWidth(testColumnWidth);
    out << c1String;
    out << qSetFieldWidth(0);
    out << " | ";
    out << qSetFieldWidth(resultColumnWidth);
    out << c2String;
    out << qSetFieldWidth(0);
    out << " | ";
    out << qSetFieldWidth(commentColumnWidth);
    out << c3String;
    out << qSetFieldWidth(0);
    out << " | ";
    out << endl;
}

static void printTableLineFormatted(int testId, const QString &testName, const QString &testStatus, int statusFormatLen, const QString &testComment)
{
    QString shortenedTestName = testName.left(testColumnWidth);
    QString shortenedTestComment = testComment.left(commentColumnWidth);
    QTextStream out(stdout);

    out << "| ";
    out << qSetFieldWidth(testIdWidth);
    out.setFieldAlignment(QTextStream::AlignCenter);
    (testId >= 0) ? out << testId : out << "";
    out << qSetFieldWidth(0);
    out << "| ";
    out << qSetFieldWidth(testColumnWidth);
    out.setFieldAlignment(QTextStream::AlignLeft);
    out << shortenedTestName;
    out << qSetFieldWidth(0);
    out << " | ";
    out << qSetFieldWidth(resultColumnWidth + statusFormatLen);
    out.setFieldAlignment(QTextStream::AlignCenter);
    out << testStatus;
    out << qSetFieldWidth(0);
    out << " | ";
    out << qSetFieldWidth(commentColumnWidth);
    out.setFieldAlignment(QTextStream::AlignLeft);
    out << shortenedTestComment;
    out << qSetFieldWidth(0);
    out << " | ";
    out << endl;

    if ((testName.length() > testColumnWidth) || (testComment.length() > commentColumnWidth)) {
        printTableLineFormatted(-1, testName.mid(testColumnWidth), "", 0, testComment.mid(commentColumnWidth));
    }
}

static void printTableLineFailed(int testId, const QString &testName, const QString &testComment)
{
    printTableLineFormatted(testId, testName, "\033[1;31mFAILED !!!\033[0m", 11, testComment);
}

static void printTableLinePassed(int testId, const QString &testName, const QString &testComment)
{
    printTableLineFormatted(testId, testName, "\033[1;32mPASSED\033[0m", 11, testComment);
}

static void printTableLineUndefined(int testId, const QString &testName, const QString &testComment)
{
    printTableLineFormatted(testId, testName, "\033[1mUNDEF ???\033[0m", 8, testComment);
}

void SslCAudit::printSummary()
{
    WHITE("tests results summary table:");

    printTableHSeparator();
    printTableHeaderLine("##", "Test Name", "Result", "Comment");
    printTableHSeparator();

    for (int i = 0; i < sslTests.size(); i++) {
        SslTest *test = sslTests.at(i);
        QString testName = test->name();

        switch (test->result()) {
        case SslTest::SSLTEST_RESULT_SUCCESS:
            printTableLinePassed(test->id(), testName, test->resultComment());
            break;
        case SslTest::SSLTEST_RESULT_UNDEFINED:
        case SslTest::SSLTEST_RESULT_INIT_FAILED:
        case SslTest::SSLTEST_RESULT_NOT_READY:
            printTableLineUndefined(test->id(), testName, test->resultComment());
            break;
        case SslTest::SSLTEST_RESULT_DATA_INTERCEPTED:
        case SslTest::SSLTEST_RESULT_CERT_ACCEPTED:
        case SslTest::SSLTEST_RESULT_PROTO_ACCEPTED:
        case SslTest::SSLTEST_RESULT_PROTO_ACCEPTED_WITH_ERR:
            printTableLineFailed(test->id(), testName, test->resultComment());
            break;
        }
    }

    printTableHSeparator();
}

void SslCAudit::writeXmlSummary(const QString &filename)
{
    QFile file(filename);
    file.open(QIODevice::WriteOnly);

    QXmlStreamWriter xmlWriter(&file);
    xmlWriter.setAutoFormatting(true);
    xmlWriter.writeStartDocument();

    xmlWriter.writeStartElement("qsslcaudit");
    for (int i = 0; i < sslTests.size(); i++) {
        SslTest *test = sslTests.at(i);
        QString testId = QString::number(test->id());
        QString testName = test->name();
        QString testResult = SslTest::resultToStatus(test->result());

        xmlWriter.writeStartElement("test");
        xmlWriter.writeTextElement("id", testId);
        xmlWriter.writeTextElement("name", testName);
        xmlWriter.writeTextElement("result", testResult);
        xmlWriter.writeEndElement();
    }

    xmlWriter.writeEndElement();
    file.close();
}
