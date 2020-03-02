#include "sslserver.h"
#include "debug.h"
#include "sslusersettings.h"
#include "starttls.h"
#include "tcpsserver.h"
#include "dtlsserver.h"


SslServer::SslServer(const SslUserSettings *settings,
                     QList<XSslCertificate> localCert,
                     XSslKey privateKey,
                     XSsl::SslProtocol sslProtocol,
                     QList<XSslCipher> sslCiphers,
                     QObject *parent) : QObject(parent)
{
    m_listenAddress = settings->getListenAddress();
    m_listenPort = settings->getListenPort();
    m_dtlsMode = settings->getUseDtls();

    tcpsServer = nullptr;
    dtlsServer = nullptr;

    if (!m_dtlsMode) {
        tcpsServer = new TcpsServer(settings, localCert, privateKey, sslProtocol, sslCiphers, this);

        connect(tcpsServer, &TcpsServer::sslSocketErrors, this, &SslServer::sslSocketErrors);
        connect(tcpsServer, &TcpsServer::sslErrors, this, &SslServer::sslErrors);
        connect(tcpsServer, &TcpsServer::dataIntercepted, this, &SslServer::dataIntercepted);
        connect(tcpsServer, &TcpsServer::rawDataCollected, this, &SslServer::rawDataCollected);
        connect(tcpsServer, &TcpsServer::sslHandshakeFinished, this, &SslServer::sslHandshakeFinished);
        connect(tcpsServer, &TcpsServer::peerVerifyError, this, &SslServer::peerVerifyError);

        connect(tcpsServer, &TcpsServer::newConnection, this, &SslServer::handleIncomingConnection);

        connect(tcpsServer, &TcpsServer::newPeer, this, &SslServer::newPeer);

        connect(tcpsServer, &TcpsServer::sessionFinished, this, &SslServer::handleSessionFinished);
    } else {
        dtlsServer = new DtlsServer(settings, localCert, privateKey, sslProtocol, sslCiphers, this);

        connect(dtlsServer, &DtlsServer::udpSocketErrors, this, &SslServer::sslSocketErrors, Qt::DirectConnection);
        connect(dtlsServer, &DtlsServer::dtlsHandshakeError, this, &SslServer::dtlsHandshakeError, Qt::DirectConnection);
        connect(dtlsServer, &DtlsServer::dataIntercepted, this, &SslServer::dataIntercepted, Qt::DirectConnection);
        connect(dtlsServer, &DtlsServer::sslHandshakeFinished, this, &SslServer::sslHandshakeFinished, Qt::DirectConnection);
        connect(dtlsServer, &DtlsServer::rawDataCollected, this, &SslServer::rawDataCollected, Qt::DirectConnection);

        connect(dtlsServer, &DtlsServer::newConnection, this, &SslServer::handleIncomingConnection);

        connect(dtlsServer, &DtlsServer::newPeer, this, &SslServer::newPeer, Qt::DirectConnection);

        connect(dtlsServer, &DtlsServer::sessionFinished, this, &SslServer::handleSessionFinished);
    }
}

SslServer::~SslServer()
{
    if (tcpsServer)
        tcpsServer->deleteLater();
    if (dtlsServer)
        dtlsServer->deleteLater();
}

bool SslServer::listen()
{
    if (!m_dtlsMode) {
        if (!tcpsServer->listen(m_listenAddress, m_listenPort)) {
            RED(QString("can not bind to %1:%2").arg(m_listenAddress.toString()).arg(m_listenPort));
            return false;
        }
    } else {
        if (!dtlsServer->listen(m_listenAddress, m_listenPort)) {
            RED(QString("can not bind to %1:%2").arg(m_listenAddress.toString()).arg(m_listenPort));
            return false;
        }
    }

    VERBOSE(QString("listening on %1:%2").arg(m_listenAddress.toString()).arg(m_listenPort));
    return true;
}

void SslServer::handleIncomingConnection()
{
    if (!m_dtlsMode) {
        XSslSocket *sslSocket = dynamic_cast<XSslSocket*>(tcpsServer->nextPendingConnection());
        tcpsServer->handleIncomingConnection(sslSocket);
    } else {
        dtlsServer->handleClient();
    }
}

QString SslServer::dtlsErrorToString(XDtlsError error)
{
    switch (error) {
    case SslUnsafeDtlsError::NoError:
        return QString("NoError");
    case SslUnsafeDtlsError::InvalidInputParameters:
        return QString("InvalidInputParameters");
    case SslUnsafeDtlsError::InvalidOperation:
        return QString("InvalidOperation");
    case SslUnsafeDtlsError::UnderlyingSocketError:
        return QString("UnderlyingSocketError");
    case SslUnsafeDtlsError::RemoteClosedConnectionError:
        return QString("RemoteClosedConnectionError");
    case SslUnsafeDtlsError::PeerVerificationError:
        return QString("PeerVerificationError");
    case SslUnsafeDtlsError::TlsInitializationError:
        return QString("TlsInitializationError");
    case SslUnsafeDtlsError::TlsFatalError:
        return QString("TlsFatalError");
    case SslUnsafeDtlsError::TlsNonFatalError:
        return QString("TlsNonFatalError");
    }
    return QString("");
}

void SslServer::handleSessionFinished()
{
    if (!m_dtlsMode) {
        tcpsServer->close();
    } else {
        dtlsServer->close();
    }

    emit sessionFinished();
}

void SslServer::handleSigInt()
{
    // we handle SIGINT only to break forwarding process gracefully
    // in case we are not in forwarding state, just exit
    if (!m_dtlsMode) {
        if (!tcpsServer->isForwarding())
            exit(0);
        tcpsServer->handleSigInt();
    } else {
        if (!dtlsServer->isForwarding())
            exit(0);
        dtlsServer->handleSigInt();
    }
}
