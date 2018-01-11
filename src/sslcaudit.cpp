
#include "sslcaudit.h"
#include "sslserver.h"
#include "debug.h"

#include <QCoreApplication>
#include <QThread>
#include <QFile>

#ifdef UNSAFE
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif


SslCAudit::SslCAudit(const SslUserSettings settings, QObject *parent) :
    QObject(parent),
    sslTests(QList<SslTest *>()),
    settings(settings)
{
    VERBOSE("SSL library used: " + XSslSocket::sslLibraryVersionString());
}

void SslCAudit::setSslTests(const QList<SslTest *> &tests)
{
    sslTests = tests;
}

void SslCAudit::runTest(const SslTest *test)
{
    QHostAddress listenAddress = settings.getListenAddress();
    quint16 listenPort = settings.getListenPort();
    SslServer sslServer;

    WHITE("running test: " + test->description());

    sslServer.setSslLocalCertificateChain(test->localCert());

    sslServer.setSslPrivateKey(test->privateKey());

    sslServer.setSslProtocol(test->sslProtocol());

    sslServer.setSslCiphers(test->sslCiphers());

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

        connect(sslSocket, static_cast<void(XSslSocket::*)(QAbstractSocket::SocketError)>(&XSslSocket::error),
                this, &SslCAudit::handleSocketError);
        connect(sslSocket, &XSslSocket::encrypted, this, &SslCAudit::sslHandshakeFinished);
        connect(sslSocket, static_cast<void(XSslSocket::*)(const QList<XSslError> &)>(&XSslSocket::sslErrors),
                this, &SslCAudit::handleSslErrors);
        connect(sslSocket, &XSslSocket::peerVerifyError, this, &SslCAudit::handlePeerVerifyError);

        VERBOSE(QString("connection from: %1:%2").arg(sslSocket->peerAddress().toString()).arg(sslSocket->peerPort()));

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
    } else {
        VERBOSE("could not establish encrypted connection (" + sslServer.errorString() + ")");
    }

    WHITE("report:");

    qDebug() << testSslErrors;
    qDebug() << testSocketErrors;
    qDebug() << testSslConnectionEstablished;
    qDebug() << testDataReceived;

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
