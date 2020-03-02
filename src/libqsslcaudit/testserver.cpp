#include "testserver.h"
#include "debug.h"
#include "ssltest.h"
#include "sslserver.h"
#include "clientinfo.h"
#include "sslusersettings.h"

TestServer::TestServer(SslTest *sslTest, const SslUserSettings *settings,
                       QObject *parent) :
    QObject(parent),
    sslSettings(settings),
    sslTest(sslTest)
{
    clientInfo = new ClientInfo();
    clientInfo->setDtlsMode(settings->getUseDtls());

    sslServer = new SslServer(settings,
                              sslTest->localCert(),
                              sslTest->privateKey(),
                              sslTest->sslProtocol(),
                              sslTest->sslCiphers(),
                              this);

    // can be emitted by both TCP and UDP servers
    connect(sslServer, &SslServer::sslSocketErrors, this, &TestServer::handleSslSocketErrors);

    // can be emitted by TCP server only
    connect(sslServer, &SslServer::sslErrors, [=](const QList<XSslError> &errors) {
        VERBOSE("SSL errors detected:");
        XSslError error;
        foreach (error, errors) {
            VERBOSE("\t" + error.errorString());
            clientInfo->addSslErrorString(error.errorString());
        }
        clientInfo->addSslErrors(errors);
    });

    // can be emitted by UDP server only
    connect(sslServer, &SslServer::dtlsHandshakeError, [=](const XDtlsError error, const QString &errorStr) {
        VERBOSE("DTLS error detected:");
        VERBOSE(QString("\t%1(%2)").arg(errorStr).arg(SslServer::dtlsErrorToString(error)));
        clientInfo->addSslErrorString(errorStr);
        clientInfo->addDtlsError(error);
    });

    // can be emitted by both TCP and UDP servers
    connect(sslServer, &SslServer::dataIntercepted, [=](const QByteArray &data) {
        clientInfo->addInterceptedData(data);
    });

    // can be emitted by both TCP and UDP servers
    connect(sslServer, &SslServer::rawDataCollected, [=](const QByteArray &rdData, const QByteArray &wrData) {
        clientInfo->addRawDataRecv(rdData);
        clientInfo->addRawDataSent(wrData);
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

        clientInfo->setSslConnectionStatus(true);
    });

    // can be emitted by TCP server only
    // for UDP see QDtls::peerVerificationErrors(), however, it does not make sense anyway
    connect(sslServer, &SslServer::peerVerifyError, [=](const XSslError &error) {
        VERBOSE("peer verify error:");
        VERBOSE("\t" + error.errorString());
    });

    // can be emitted by both TCP and UDP servers
    connect(sslServer, &SslServer::newPeer, [=](const QHostAddress &peerAddress) {
        clientInfo->setSourceHost(peerAddress.toString());
    });

    // client disconnected or similar
    connect(sslServer, &SslServer::sessionFinished, this, &TestServer::handleSessionFinished);

    // we handle SIGINT only to break forwarding process gracefully
    // in case we are not in forwarding state, just exit
    connect(this, &TestServer::sigIntHandled, sslServer, &SslServer::handleSigInt);
}

TestServer::~TestServer()
{
    delete clientInfo;
    sslServer->deleteLater();
}

void TestServer::runTest()
{
    WHITE(QString("running test #%1: %2").arg(static_cast<int>(sslTest->id()) + 1)
          .arg(sslTest->description()));

    sslTest->clear();
    clientInfo->clear();

    if (!sslServer->listen()) {
        RED("failure during listener initialization, test will not continue");
        sslTest->calcResults(clientInfo);
        emit sslTestFinished();
        return;
    }

    // check if *server* was not able to setup SSL connection
    // to check this we need to see if we already received some SSL errors
    // if this is the case -- then those errors are about SSL initialization
    if ((clientInfo->sslErrorsStr().size() > 0)
            || (clientInfo->socketErrors().size() > 0)) {
        RED("failure during SSL initialization, test will not continue");

        for (int i = 0; i < clientInfo->sslErrorsStr().size(); i++) {
            VERBOSE("\t" + clientInfo->sslErrorsStr().at(i));
        }

        sslTest->calcResults(clientInfo);
        emit sslTestFinished();
        return;
    }

    emit sslTestReady();
}

void TestServer::handleSessionFinished()
{
    sslTest->calcResults(clientInfo);

    WHITE("report:");

    if (sslTest->result() != SslTestResult::Success) {
        RED(sslTest->report());
    } else {
        GREEN(sslTest->report());
    }

    WHITE("test finished");

    emit sslTestFinished();
}

void TestServer::handleSslSocketErrors(const QList<XSslError> &sslErrors,
                                      const QString &errorStr, QAbstractSocket::SocketError socketError)
{
    VERBOSE(QString("socket error: %1 (#%2)").arg(errorStr).arg(socketError));

    clientInfo->addSslErrors(sslErrors);
    clientInfo->addSslErrorString(errorStr);
    clientInfo->addSocketErrors(QList<QAbstractSocket::SocketError>() << socketError);

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
