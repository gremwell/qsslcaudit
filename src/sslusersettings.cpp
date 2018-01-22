
#include "sslusersettings.h"
#include "sslcertgen.h"
#include "debug.h"

#include <QUrl>

#ifdef UNSAFE
#include "sslunsafesocket.h"
#else
#include <QSslSocket>
#endif


SslUserSettings::SslUserSettings()
{
    listenAddress = QHostAddress::LocalHost;
    listenPort = 8443;
    userCN = "";
    serverAddr = "";
    userCertPath = "";
    userKeyPath = "";
    userCaCertPath = "";
    userCaKeyPath = "";
    forwardAddr = "";
}

void SslUserSettings::setListenAddress(const QHostAddress &addr)
{
    listenAddress = addr;
}

QHostAddress SslUserSettings::getListenAddress() const
{
    return listenAddress;
}

void SslUserSettings::setListenPort(quint16 port)
{
    listenPort = port;
}

quint16 SslUserSettings::getListenPort() const
{
    return listenPort;
}

void SslUserSettings::setUserCN(const QString &cn)
{
    userCN = cn;
}

QString SslUserSettings::getUserCN() const
{
    return userCN;
}

bool SslUserSettings::setServerAddr(const QString &addr)
{
    XSslSocket socket;
    QUrl url = QUrl::fromUserInput(addr);
    QString host = url.host();
    quint16 port = url.port(443);

    socket.connectToHostEncrypted(host, port);
    if (!socket.waitForEncrypted()) {
        RED("failed to connect to " + addr);
        return false;
    }

    // obtain connection parameters
    peerCerts = socket.peerCertificateChain();

    socket.disconnectFromHost();

    serverAddr = addr;

    return true;
}

QString SslUserSettings::getServerAddr() const
{
    return serverAddr;
}

QList<XSslCertificate> SslUserSettings::getPeerCertificates() const
{
    return peerCerts;
}

bool SslUserSettings::setUserCertPath(const QString &path)
{
    QList<XSslCertificate> chain = SslCertGen::certChainFromFile(path);
    if (chain.size() == 0) {
        qDebug() << "failed to read user's certificate from " << path;
        return false;
    }

    userCertPath = path;

    return true;
}

QString SslUserSettings::getUserCertPath() const
{
    return userCertPath;
}

QList<XSslCertificate> SslUserSettings::getUserCert() const
{
    return SslCertGen::certChainFromFile(userCertPath);
}

bool SslUserSettings::setUserKeyPath(const QString &path)
{
    XSslKey key = SslCertGen::keyFromFile(path);
    if (key.isNull()) {
        qDebug() << "failed to read custom private key from " << path;
        return false;
    }

    userKeyPath = path;

    return true;
}

QString SslUserSettings::getUserKeyPath() const
{
    return userKeyPath;
}

XSslKey SslUserSettings::getUserKey() const
{
    return SslCertGen::keyFromFile(userKeyPath);
}

bool SslUserSettings::setUserCaCertPath(const QString &path)
{
    QList<XSslCertificate> chain = SslCertGen::certChainFromFile(path);
    if (chain.size() == 0) {
        qDebug() << "failed to read user's CA certificate from " << path;
        return false;
    }

    userCaCertPath = path;

    return true;
}

QString SslUserSettings::getUserCaCertPath() const
{
    return userCaCertPath;
}

QList<XSslCertificate> SslUserSettings::getUserCaCert() const
{
    return SslCertGen::certChainFromFile(userCaCertPath);
}

bool SslUserSettings::setUserCaKeyPath(const QString &path)
{
    XSslKey key = SslCertGen::keyFromFile(path);
    if (key.isNull()) {
        qDebug() << "failed to read custom private key from " << path;
        return false;
    }

    userCaKeyPath = path;

    return true;
}

QString SslUserSettings::getUserCaKeyPath() const
{
    return userCaKeyPath;
}

XSslKey SslUserSettings::getUserCaKey() const
{
    return SslCertGen::keyFromFile(userCaKeyPath);
}

void SslUserSettings::setForwardAddr(const QString &addr)
{
    forwardAddr = addr;
}

QString SslUserSettings::getForwardAddr() const
{
    return forwardAddr;
}

QHostAddress SslUserSettings::getForwardHostAddr() const
{
    QUrl url = QUrl::fromUserInput(forwardAddr);
    return QHostAddress(url.host());
}

quint16 SslUserSettings::getForwardHostPort() const
{
    QUrl url = QUrl::fromUserInput(forwardAddr);
    return url.port();
}
