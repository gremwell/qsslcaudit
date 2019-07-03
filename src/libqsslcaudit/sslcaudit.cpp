
#include "sslcaudit.h"
#include "sslserver.h"
#include "debug.h"
#include "ciphers.h"

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

void SslCAudit::showCiphersGroup(const QString &groupName, const QString &ciphersStr)
{
    QStringList opensslCiphers = ciphersStr.split(":");
    QString supportedCiphersStr;

    VERBOSE("  " + groupName + ":");

    for (int i = 0; i < opensslCiphers.size(); i++) {
        XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

        if (!cipher.isNull())
            supportedCiphersStr += opensslCiphers.at(i) + ":";
    }

    supportedCiphersStr.chop(1);

    VERBOSE("    " + supportedCiphersStr);
}

void SslCAudit::showCiphers()
{
    VERBOSE("supported ciphers:");
    showCiphersGroup("EXPORT", ciphers_export_str);
    showCiphersGroup("LOW", ciphers_low_str);
    showCiphersGroup("MEDIUM", ciphers_medium_str);
    showCiphersGroup("HIGH", ciphers_high_str);
}

void SslCAudit::setSslTests(const QList<SslTest *> &tests)
{
    sslTests = tests;
}

void SslCAudit::runTest(SslTest *test)
{
    WHITE(QString("running test #%1: %2").arg(test->id()).arg(test->description()));

    SslServer *sslServer = new SslServer(settings, test, this);
    if (!sslServer->listen()) {
        // this place is in the middle of code path and others could expect
        // some return values, signals, etc.
        // however, if we can not setup listener (mostly due to permission/busy errors)
        // for one test, all others will fail.
        // there is no strong reason to attempt to recover from that, thus, exit with
        // non-zero code
        // alternative way -- test availability of socket prior launching SslCaudit
        exit(-1);
    }

    m_sslErrorsStr.clear();
    m_sslErrors.clear();

    // can be emitted by both TCP and UDP servers
    connect(sslServer, &SslServer::sslSocketErrors, this, &SslCAudit::handleSslSocketErrors);

    // can be emitted by TCP server only
    connect(sslServer, &SslServer::sslErrors, [=](const QList<XSslError> &errors) {
        VERBOSE("SSL errors detected:");
        XSslError error;
        foreach (error, errors) {
            VERBOSE("\t" + error.errorString());
            currentTest->addSslErrorString(error.errorString());
        }
        currentTest->addSslErrors(errors);
    });

    // can be emitted by UDP server only
    connect(sslServer, &SslServer::dtlsHandshakeError, [=](const XDtlsError error, const QString &errorStr) {
        VERBOSE("DTLS error detected:");
        VERBOSE(QString("\t%1(%2)").arg(errorStr).arg(SslServer::dtlsErrorToString(error)));
        currentTest->addSslErrorString(errorStr);
        currentTest->addDtlsError(error);
    });

    // can be emitted by both TCP and UDP servers
    connect(sslServer, &SslServer::dataIntercepted, [=](const QByteArray &data) {
        currentTest->addInterceptedData(data);
    });

    // can be emitted by both TCP and UDP servers
    // TODO for UDP
    connect(sslServer, &SslServer::rawDataCollected, [=](const QByteArray &rdData, const QByteArray &wrData) {
        currentTest->addRawDataRecv(rdData);
        currentTest->addRawDataSent(wrData);
    });

    // can be emitted by both TCP and UDP servers
    connect(sslServer, &SslServer::sslHandshakeFinished, [=](const QList<XSslCertificate> &clientCerts) {
        VERBOSE("SSL connection established");
        if (clientCerts.size() > 0) {
            VERBOSE(QString("\tclient supplied chain of %1 certificates").arg(clientCerts.size()));
            for (int i = 0; i < clientCerts.size(); i++) {
                VERBOSE(clientCerts.at(i).toPem());
            }
        }

        currentTest->setSslConnectionStatus(true);
    });

    // can be emitted by TCP server only
    // for UDP see QDtls::peerVerificationErrors(), however, it does not make sense anyway
    connect(sslServer, &SslServer::peerVerifyError, [=](const XSslError &error) {
        VERBOSE("peer verify error:");
        VERBOSE("\t" + error.errorString());
    });

    // can be emitted by both TCP and UDP servers
    connect(sslServer, &SslServer::newPeer, [=](const QHostAddress &peerAddress) {
        currentTest->setClientSourceHost(peerAddress.toString());
    });

    emit sslTestReady();

    if (sslServer->waitForClient()) {
        // check if *server* was not able to setup SSL connection
        // to check this we need to see if we already received some SSL errors
        // if this is the case -- then those errors are about SSL initialization
        if ((m_sslErrorsStr.size() > 0) || (m_sslErrors.size() > 0)) {
            RED("failure during SSL initialization, test will not continue");

            for (int i = 0; i < m_sslErrorsStr.size(); i++) {
                VERBOSE("\t" + m_sslErrorsStr.at(i));
            }

            test->calcResults();
            delete sslServer;
            return;
        }

        // now we can handle client side
        // this call will loop until connection close if 'forward' option is set
        sslServer->handleIncomingConnection();
    } else {
        VERBOSE("could not establish encrypted connection (" + m_sslErrorsStr.join(", ") + ")");
    }

    delete sslServer;

    test->calcResults();

    WHITE("report:");

    test->printReport();

    WHITE("test finished");

    emit sslTestFinished();
}

void SslCAudit::handleSslSocketErrors(const QList<XSslError> &sslErrors,
                                      const QString &errorStr, QAbstractSocket::SocketError socketError)
{
    m_sslErrorsStr << errorStr;
    m_sslErrors << socketError;

    VERBOSE(QString("socket error: %1 (#%2)").arg(errorStr).arg(socketError));

    currentTest->addSslErrors(sslErrors);
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
