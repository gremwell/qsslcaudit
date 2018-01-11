
#include "sslusersettings.h"

#include "sslcertgen.h"


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

void SslUserSettings::setServerAddr(const QString &addr)
{
    serverAddr = addr;
}

QString SslUserSettings::getServerAddr() const
{
    return serverAddr;
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
