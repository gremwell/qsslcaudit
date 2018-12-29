
#include "debug.h"
#include "sslusersettings.h"
#include "ssltests.h"
#include "sslcaudit.h"

#include <QCoreApplication>
#include <QCommandLineParser>
#include <QThread>
#include <QHostAddress>


static QList<int> selectedTests;


void parseOptions(const QCoreApplication &a, SslUserSettings *settings)
{
    QCommandLineParser parser;
    bool ok;

    QString appDescription = "A tool to test SSL clients behavior\n\n";
    appDescription += "SSL client tests:\n";
    for (int i = 0; i < SSLTESTS_COUNT; i++) {
        SslTest *t = SslTest::createTest(i);

        appDescription += QString("\t%1: %2\n").arg(i + 1).arg(t->name());
        appDescription += QString("\t   %1\n").arg(t->description());

        delete t;
    }

    parser.setApplicationDescription(appDescription);
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption listenAddressOption(QStringList() << "l" << "listen-address",
                                           "listen on <address>", "0.0.0.0");
    parser.addOption(listenAddressOption);
    QCommandLineOption listenPortOption(QStringList() << "p" << "listen-port",
                                        "bind to <port>", "8443");
    parser.addOption(listenPortOption);
    QCommandLineOption userCNOption(QStringList() << "user-cn",
                                    "common name (CN) to suggest to client", "example.com");
    parser.addOption(userCNOption);
    QCommandLineOption serverOption(QStringList() << "server",
                                    "grab certificate information from <server>", "https://example.com");
    parser.addOption(serverOption);
    QCommandLineOption userCertOption(QStringList() << "user-cert",
                                      "path to file containing custom certificate (or chain of certificates)", "~/host.cert");
    parser.addOption(userCertOption);
    QCommandLineOption userKeyOption(QStringList() << "user-key",
                                     "path to file containing custom private key", "~/host.key");
    parser.addOption(userKeyOption);
    QCommandLineOption userCaCertOption(QStringList() << "user-ca-cert",
                                        "path to file containing custom certificate usable as CA", "~/ca.cert");
    parser.addOption(userCaCertOption);
    QCommandLineOption userCaKeyOption(QStringList() << "user-ca-key",
                                       "path to file containing custom private key for CA certificate", "~/ca.key");
    parser.addOption(userCaKeyOption);
    QCommandLineOption selectedTestsOption(QStringList() << "selected-tests",
                                     "comma-separated list of tests (id) to execute", "1,3,5");
    parser.addOption(selectedTestsOption);
    QCommandLineOption forwardOption(QStringList() << "forward",
                                    "forward connection to upstream proxy", "127.0.0.1:6666");
    parser.addOption(forwardOption);
    QCommandLineOption showciphersOption(QStringList() << "show-ciphers",
                                    "show ciphers provided by loaded openssl library");
    parser.addOption(showciphersOption);
    QCommandLineOption starttlsOption(QStringList() << "starttls",
                                    "exchange specific STARTTLS messages before starting secure connection", "ftp|smtp");
    parser.addOption(starttlsOption);
    QCommandLineOption loopTestsOption(QStringList() << "loop-tests",
                                       "infinitely repeat selected tests (use Ctrl-C to kill the tool)");
    parser.addOption(loopTestsOption);
    QCommandLineOption waitDataTimeoutOption(QStringList() << "w" << "wait-data-timeout",
                                        "wait for incoming data <ms> milliseconds before emitting error", "5000");
    parser.addOption(waitDataTimeoutOption);
    QCommandLineOption outputXmlOption(QStringList() << "output-xml",
                                       "save results in XML", "qsslcaudit.xml");
    parser.addOption(outputXmlOption);

    parser.process(a);

    if (parser.isSet(showciphersOption)) {
        SslCAudit::showCiphers();
        exit(0);
    }
    if (parser.isSet(listenAddressOption)) {
        settings->setListenAddress(QHostAddress(parser.value(listenAddressOption)));
    }
    if (parser.isSet(listenPortOption)) {
        int port = parser.value(listenPortOption).toInt(&ok);
        if (!ok || !settings->setListenPort(port)) {
            RED("the provided listening port value is invalid: " + parser.value(listenPortOption));
            exit(-1);
        }
    }
    if (parser.isSet(userCNOption)) {
        settings->setUserCN(parser.value(userCNOption));
    }
    if (parser.isSet(serverOption)) {
        ok = settings->setServerAddr(parser.value(serverOption));
        if (!ok)
            exit(-1);

        if ((settings->getServerAddr().length() > 0)
                && (settings->getUserCN().length() > 0)) {
            VERBOSE("as server address is specified, user-cn value will be ignored");
        }
    }
    if (parser.isSet(userCertOption)) {
        ok = settings->setUserCertPath(parser.value(userCertOption));
        if (!ok)
            exit(-1);

        if (!parser.isSet(userKeyOption)) {
            RED("custom private key is not specified, exiting");
            exit(-1);
        }
    }
    if (parser.isSet(userKeyOption)) {
        ok = settings->setUserKeyPath(parser.value(userKeyOption));
        if (!ok)
            exit(-1);

        if (!parser.isSet(userCertOption)) {
            RED("custom certificate is not specified, exiting");
            exit(-1);
        }
    }
    if (parser.isSet(userCaCertOption)) {
        ok = settings->setUserCaCertPath(parser.value(userCaCertOption));
        if (!ok)
            exit(-1);

        if (!parser.isSet(userCaKeyOption)) {
            RED("custom private key for CA is not specified, exiting");
            exit(-1);
        }
    }
    if (parser.isSet(userCaKeyOption)) {
        ok = settings->setUserCaKeyPath(parser.value(userCaKeyOption));
        if (!ok)
            exit(-1);

        if (!parser.isSet(userCaCertOption)) {
            RED("custom CA certificate is not specified, exiting");
            exit(-1);
        }
    }
    if (parser.isSet(selectedTestsOption)) {
        selectedTests.clear();

        QString testsStr = parser.value(selectedTestsOption);
        QRegExp rx = QRegExp("[\\d?,?\\-?(certs)?(protos)?(ciphers)?]+");

        if (!rx.exactMatch(testsStr)) {
            RED("tests selection is malformed: " + testsStr);
            exit(-1);
        }

        QStringList testsListStr = testsStr.split(",", QString::SkipEmptyParts);
        for (int i = 0; i < testsListStr.size(); i++) {
            QString group = testsListStr.at(i);
            // check for range
            if (testsListStr.at(i).count("-") == 1) {
                bool ok1, ok2;
                int low = group.split("-").at(0).toInt(&ok1) - 1;
                int high = group.split("-").at(1).toInt(&ok2) - 1;

                if (ok1 && ok2 && (low <= high) && (high < SSLTESTS_COUNT)) {
                    for (int num = low; num <= high; num++) {
                        selectedTests << num;
                    }
                } else {
                    VERBOSE("WARN: invalid test group skipped " + group);
                }
            } else {
                // check for single number
                int num = group.toInt(&ok) - 1;
                int selectedGroup = -1;
                if (ok && (SSLTESTS_COUNT > num)) {
                    selectedTests << num;
                } else if (group == SSLTESTS_GROUP_CERTS_STR) {
                    selectedGroup = SSLTESTS_GROUP_CERTS;
                } else if (group == SSLTESTS_GROUP_PROTOS_STR) {
                    selectedGroup = SSLTESTS_GROUP_PROTOS;
                } else if (group == SSLTESTS_GROUP_CIPHERS_STR) {
                    selectedGroup = SSLTESTS_GROUP_CIPHERS;
                } else {
                    VERBOSE("WARN: invalid test group skipped " + group);
                    break;
                }
                // groups handling is weird until we have global container for all existing tests
                // TODO: for now, we create a temporary local one
                for (int i = 0; i < SSLTESTS_COUNT; i++) {
                    SslTest *test = SslTest::createTest(i);
                    if (test->group() == selectedGroup) {
                        selectedTests << i;
                    }
                    delete test;
                }
            }
        }
    } else {
        // if this option is not set -- select all available tests
        for (int i = 0; i < SSLTESTS_COUNT; i++) {
            selectedTests << i;
        }
    }
    if (parser.isSet(forwardOption)) {
        settings->setForwardAddr(parser.value(forwardOption));
    }
    if (parser.isSet(starttlsOption)) {
        if (!settings->setStartTlsProtocol(parser.value(starttlsOption))) {
            RED("unsupported STARTTLS protocol");
            exit(-1);
        }
    }
    if (parser.isSet(loopTestsOption)) {
        settings->setLoopTests(true);
    }
    if (parser.isSet(waitDataTimeoutOption)) {
        bool ok = true;
        int to = parser.value(waitDataTimeoutOption).toInt(&ok);
        if (!ok || !settings->setWaitDataTimeout(to)) {
            RED("invalid timeout value " + parser.value(waitDataTimeoutOption));
            exit(-1);
        }
    }
    if (parser.isSet(outputXmlOption)) {
        ok = settings->setOutputXml(parser.value(outputXmlOption));
        if (!ok) {
            RED("check if the provided path to XML output is writable");
            exit(-1);
        };
    }
}


QList<SslTest *> prepareSslTests(const SslUserSettings &settings)
{
    QList<SslTest *> ret;

    VERBOSE("preparing selected tests...");
    for (int i = 0; i < selectedTests.size(); i++) {
        SslTest *test = SslTest::createTest(selectedTests.at(i));
        if (test->prepare(settings)) {
            ret << test;
        } else {
            VERBOSE("\tskipping test: " + test->description());
        }
    }
    VERBOSE("");

    return ret;
}


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QCoreApplication::setApplicationName("qsslcaudit");
    QCoreApplication::setApplicationVersion(QSSLC_VERSION);
    QCoreApplication::setOrganizationName("Gremwell");
    QCoreApplication::setOrganizationDomain("gremwell.com");

    SslUserSettings settings;

    parseOptions(a, &settings);

    QList<SslTest *> sslTests = prepareSslTests(settings);

    QThread *thread = new QThread;
    SslCAudit *caudit = new SslCAudit(settings);

    caudit->setSslTests(sslTests);
    caudit->moveToThread(thread);
    QObject::connect(thread, SIGNAL(started()), caudit, SLOT(run()));
    QObject::connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));

    QObject::connect(caudit, &SslCAudit::sslTestsFinished, [=](){
        caudit->printSummary();

        if (settings.getOutputXml().length() > 0)
            caudit->writeXmlSummary(settings.getOutputXml());

        qApp->exit();
    });

    thread->start();

    return a.exec();
}
