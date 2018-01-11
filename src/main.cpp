
#include "debug.h"
#include "sslusersettings.h"
#include "ssltests.h"
#include "sslcaudit.h"

#include <QCoreApplication>
#include <QCommandLineParser>
#include <QThread>
#include <QHostAddress>


void parseOptions(const QCoreApplication &a, SslUserSettings *settings)
{
    QCommandLineParser parser;
    bool ok;

    parser.setApplicationDescription("A tool to test SSL clients behavior");
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption listenAddressOption(QStringList() << "l" << "listen-address",
                                           "listen on <address>.", "0.0.0.0");
    parser.addOption(listenAddressOption);
    QCommandLineOption listenPortOption(QStringList() << "p" << "listen-port",
                                        "bind to <port>.", "8443");
    parser.addOption(listenPortOption);
    QCommandLineOption userCNOption(QStringList() << "user-cn",
                                    "common name (CN) to suggest to client", "CN");
    parser.addOption(userCNOption);
    QCommandLineOption serverOption(QStringList() << "server",
                                    "grab certificate information from <server>.", "server");
    parser.addOption(serverOption);
    QCommandLineOption userCertOption(QStringList() << "user-cert",
                                      "path to file containing custom certificate (or chain of certificates).", "path");
    parser.addOption(userCertOption);
    QCommandLineOption userKeyOption(QStringList() << "user-key",
                                     "path to file containing custom private key.", "path");
    parser.addOption(userKeyOption);
    QCommandLineOption userCaCertOption(QStringList() << "user-ca-cert",
                                        "path to file containing custom certificate usable as CA.", "path");
    parser.addOption(userCaCertOption);
    QCommandLineOption userCaKeyOption(QStringList() << "user-ca-key",
                                       "path to file containing custom private key for CA certificate.", "path");
    parser.addOption(userCaKeyOption);

    parser.process(a);

    if (parser.isSet(listenAddressOption)) {
        settings->setListenAddress(QHostAddress(parser.value(listenAddressOption)));
    }
    if (parser.isSet(listenPortOption)) {
        bool ok = true;
        quint16 port = parser.value(listenPortOption).toInt(&ok);
        if (ok)
            settings->setListenPort(port);
    }
    if (parser.isSet(userCNOption)) {
        settings->setUserCN(parser.value(userCNOption));
    }
    if (parser.isSet(serverOption)) {
        settings->setServerAddr(parser.value(serverOption));
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
}


QList<SslTest *> prepareSslTests(const SslUserSettings &settings)
{
    QList<SslTest *> ret;
    QList<SslTest *> all = QList<SslTest *>() << new SslTest01()
                                              << new SslTest02()
                                              << new SslTest03()
                                              << new SslTest04()
                                              << new SslTest05()
                                              << new SslTest06()
                                              << new SslTest07();
    SslTest *test;

    foreach (test, all) {
        if (test->prepare(settings)) {
            ret << test;
        } else {
            VERBOSE("skipping test: " + test->description());
        }
    }

    all.clear();

    return ret;
}


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QCoreApplication::setApplicationName("qsslcaudit");
    QCoreApplication::setApplicationVersion("0.1");

    SslUserSettings settings;

    parseOptions(a, &settings);

    QList<SslTest *> sslTests = prepareSslTests(settings);

    QThread *thread = new QThread;
    SslCAudit *caudit = new SslCAudit(settings);

    caudit->setSslTests(sslTests);
    caudit->moveToThread(thread);
    QObject::connect(thread, SIGNAL(started()), caudit, SLOT(run()));
    QObject::connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));
    thread->start();

    return a.exec();
}
