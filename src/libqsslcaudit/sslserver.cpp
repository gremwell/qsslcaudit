#include "sslserver.h"
#include "debug.h"
#include "starttls.h"
#include "ssltest.h"
#include "tcpsserver.h"


SslServer::SslServer(const SslUserSettings &settings, const SslTest *test, QObject *parent) : QObject(parent)
{
    m_listenAddress = settings.getListenAddress();
    m_listenPort = settings.getListenPort();
    m_dtlsMode = settings.getUseDtls();

    tcpsServer = nullptr;

    if (!m_dtlsMode) {
        tcpsServer = new TcpsServer(settings, test, this);

        connect(tcpsServer, &TcpsServer::sslSocketErrors, this, &SslServer::sslSocketErrors);
        connect(tcpsServer, &TcpsServer::sslErrors, this, &SslServer::sslErrors);
        connect(tcpsServer, &TcpsServer::dataIntercepted, this, &SslServer::dataIntercepted);
        connect(tcpsServer, &TcpsServer::rawDataCollected, this, &SslServer::rawDataCollected);
        connect(tcpsServer, &TcpsServer::sslHandshakeFinished, this, &SslServer::sslHandshakeFinished);
        connect(tcpsServer, &TcpsServer::peerVerifyError, this, &SslServer::peerVerifyError);
        connect(tcpsServer, &TcpsServer::newPeer, this, &SslServer::newPeer);
    }
}

SslServer::~SslServer()
{
    if (tcpsServer) {
        tcpsServer->close();
        delete tcpsServer;
    }
}

bool SslServer::listen()
{
    if (!m_dtlsMode) {
        if (!tcpsServer->listen(m_listenAddress, m_listenPort)) {
            RED(QString("can not bind to %1:%2").arg(m_listenAddress.toString()).arg(m_listenPort));
            return false;
        }
    } else {
        return false;
    }

    VERBOSE(QString("listening on %1:%2").arg(m_listenAddress.toString()).arg(m_listenPort));
    return true;
}

bool SslServer::waitForClient()
{
    if (!m_dtlsMode) {
        return tcpsServer->waitForNewConnection(-1);
    } else {
        return false;
    }
}

void SslServer::handleIncomingConnection()
{
    if (!m_dtlsMode) {
        XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(tcpsServer->nextPendingConnection());
        tcpsServer->handleIncomingConnection(sslSocket);
    }
}

