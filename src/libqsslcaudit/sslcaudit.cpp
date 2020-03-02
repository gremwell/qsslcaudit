
#include "sslcaudit.h"
#include "debug.h"
#include "sslusersettings.h"
#include "clientinfo.h"
#include "testserver.h"
#include "ssltest.h"

#include <QFile>
#include <QXmlStreamWriter>

#include <QThread>

SslCAudit::SslCAudit(const SslUserSettings *settings, QObject *parent) :
    QObject(parent),
    settings(settings)
{
    VERBOSE("SSL library used: " + XSslSocket::sslLibraryVersionString());
}

void SslCAudit::setSslTests(const QList<SslTest *> &tests)
{
    sslTests = tests;
}

void SslCAudit::handleServerFinished()
{
    TestServer *testServer = qobject_cast<TestServer *>(sender());
    TestServer *newTestServer = nullptr;

    emit sslTestFinished();

    for (int i = 0; i < testServers.size(); i++) {
        if (testServers.at(i) == testServer) {
            // the last test finished
            if (i == testServers.size() - 1) {
                // if we asked to loop tests, start again with the first one
                if (settings->getLoopTests()) {
                    newTestServer = testServers.at(0);
                } else {
                    emit sslTestsFinished();
                    return;
                }
            } else {
                // switch to the next test
                newTestServer = testServers.at(i + 1);
            }
        }
    }

    // run the next test
    if (newTestServer)
        newTestServer->runTest();
}

void SslCAudit::run()
{
    for (int i = 0; i < sslTests.size(); i++) {
        TestServer *testServer = new TestServer(sslTests.at(i), settings, this);

        testServers << testServer;

        connect(testServer, &TestServer::sslTestReady, this, &SslCAudit::sslTestReady);
        connect(testServer, &TestServer::sslTestFinished, this, &SslCAudit::handleServerFinished);

        connect(this, &SslCAudit::sigIntHandled, testServer, &TestServer::sigIntHandled);
    }

    if (testServers.size() == 0) {
        emit sslTestsFinished();
        return;
    }

    testServers.at(0)->runTest();
}

const ClientInfo *SslCAudit::getClientInfo(int num) {
    if (num < testServers.size())
        return testServers.at(num)->getClientInfo();
    return nullptr;
}

bool SslCAudit::isSameClient(bool doPrint)
{
    const ClientInfo *client0;
    bool ret = true;

    if (testServers.size() == 0)
        return true;

    // ignore the first client fingerprint if duplication of the first test was requested
    if (!settings->getDoubleFirstTest()) {
        client0 = testServers.at(0)->getClientInfo();
    } else {
        client0 = testServers.at(1)->getClientInfo();
    }

    for (int i = 1; i < testServers.size(); i++) {
        if (!client0->isEqualTo(testServers.at(i)->getClientInfo())) {
            ret = false;

            if (doPrint) {
                static bool headerPrinted = false;

                if (!headerPrinted) {
                    RED("not all connections were established by the same client, compare the following:");
                    VERBOSE("client #0");
                    VERBOSE(client0->printable());
                    headerPrinted = true;
                }

                VERBOSE(QString("client #%1").arg(i));
                VERBOSE(testServers.at(i)->getClientInfo()->printable());
            } else {
                break;
            }
        }
    }

    if (ret && doPrint) {
        GREEN("most likely all connections were established by the same client");
        VERBOSE("the first connection details:");
        VERBOSE(client0->printable());
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

static void printTableLineFormatted(SslTestId testId, const QString &testName, const QString &testStatus,
                                    int statusFormatLen, const QString &testComment)
{
    QString shortenedTestName = testName.left(testColumnWidth);
    QString shortenedTestComment = testComment.left(commentColumnWidth);
    QTextStream out(stdout);
    int id = static_cast<int>(testId) + 1; // keep identifiers aligned with human-readable numbering which starts from 1

    out << "| ";
    out << qSetFieldWidth(testIdWidth);
    out.setFieldAlignment(QTextStream::AlignCenter);
    (testId == SslTestId::SslTestNonexisting) ? (out << "") : (out << id);
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
        printTableLineFormatted(SslTestId::SslTestNonexisting, testName.mid(testColumnWidth),
                                "", 0, testComment.mid(commentColumnWidth));
    }
}

static void printTableLineFailed(SslTestId testId, const QString &testName, const QString &testComment)
{
    printTableLineFormatted(testId, testName, "\033[1;31mFAILED !!!\033[0m", 11, testComment);
}

static void printTableLinePassed(SslTestId testId, const QString &testName, const QString &testComment)
{
    printTableLineFormatted(testId, testName, "\033[1;32mPASSED\033[0m", 11, testComment);
}

static void printTableLineUndefined(SslTestId testId, const QString &testName, const QString &testComment)
{
    printTableLineFormatted(testId, testName, "\033[1mUNDEF ???\033[0m", 8, testComment);
}

void SslCAudit::printSummary()
{
    WHITE("tests results summary table:");

    printTableHSeparator();
    printTableHeaderLine("##", "Test Name", "Result", "Comment");
    printTableHSeparator();

    QString previousComment;

    for (int i = 0; i < testServers.size(); i++) {
        const SslTest *test = testServers.at(i)->getSslTest();
        QString testName = test->name();
        QString comment = test->resultComment();

        if ((previousComment.size() > 0) && (previousComment == comment)) {
            comment = QString("-//-");
        }
        previousComment = test->resultComment();

        switch (test->result()) {
        case SslTestResult::Success:
            printTableLinePassed(test->id(), testName, comment);
            break;
        case SslTestResult::Undefined:
        case SslTestResult::InitFailed:
        case SslTestResult::NotReady:
        case SslTestResult::UnhandledCase:
            printTableLineUndefined(test->id(), testName, comment);
            break;
        case SslTestResult::DataIntercepted:
        case SslTestResult::CertAccepted:
        case SslTestResult::ProtoAccepted:
        case SslTestResult::ProtoAcceptedWithErr:
            printTableLineFailed(test->id(), testName, comment);
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
    for (int i = 0; i < testServers.size(); i++) {
        const SslTest *test = testServers.at(i)->getSslTest();
        QString testId = QString::number(static_cast<int>(test->id()) + 1); // keep numbering in human format
        QString testName = test->name();
        QString testResult = sslTestResultToStatus(test->result());

        xmlWriter.writeStartElement("test");
        xmlWriter.writeTextElement("id", testId);
        xmlWriter.writeTextElement("name", testName);
        xmlWriter.writeTextElement("result", testResult);
        xmlWriter.writeEndElement();
    }

    xmlWriter.writeEndElement();
    file.close();
}

void SslCAudit::handleSigInt()
{
    emit sigIntHandled();
}
