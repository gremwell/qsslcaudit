
#include "sslusersettings.h"
#include "sslcertgen.h"
#include "debug.h"

#include <QUrl>
#include <QFileInfo>
#include <QUdpSocket>

#ifdef UNSAFE_QSSL
#include "sslunsafesocket.h"
#include "sslunsafedtls.h"
#include "sslunsafeconfiguration.h"
#else
#include <QSslSocket>
#include <QDtls>
#include <QSslConfiguration>
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
    startTlsProtocol = SslServer::StartTlsUnknownProtocol;
    loopTests = false;
    waitDataTimeout = 5000;
    outputXmlFilename = "";
    pidFile = "";
    useDtls = false;
    doubleFirstTest = false;
    supportedCiphers = QList<XSslCipher>();
}

void SslUserSettings::setListenAddress(const QHostAddress &addr)
{
    listenAddress = addr;
}

QHostAddress SslUserSettings::getListenAddress() const
{
    return listenAddress;
}

bool SslUserSettings::setListenPort(int port)
{
    if ((port < 0) || (port > 65535)) {
        return false;
    }
    listenPort = static_cast<quint16>(port);
    return true;
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
    QUrl url = QUrl::fromUserInput(addr);
    QString host = url.host();
    quint16 port = url.port(443);

    if (!useDtls) {
        XSslSocket socket;
        socket.setPeerVerifyMode(XSslSocket::VerifyNone);
        socket.connectToHostEncrypted(host, port);
        if (!socket.waitForEncrypted()) {
            RED("failed to connect to " + addr);
            return false;
        }

        // obtain connection parameters
        peerCerts = socket.peerCertificateChain();

        socket.disconnectFromHost();
    } else {
        QUdpSocket socket;
        XDtls crypto(XSslSocket::SslClientMode);
        auto configuration = XSslConfiguration::defaultDtlsConfiguration();
        configuration.setPeerVerifyMode(XSslSocket::VerifyNone);
        crypto.setPeer(QHostAddress(host), port);
        crypto.setDtlsConfiguration(configuration);

        socket.connectToHost(host, port);
        while (socket.waitForReadyRead()) {
            QByteArray dgram(socket.pendingDatagramSize(), Qt::Uninitialized);
            const qint64 bytesRead = socket.readDatagram(dgram.data(), dgram.size());
            if (bytesRead <= 0) {
                return false;
            }

            dgram.resize(bytesRead);
            if (crypto.isConnectionEncrypted()) {
                // obtain connection parameters
                // not supported yet
                return true;
            } else {
                if (!crypto.doHandshake(&socket, dgram)) {
                    return false;
                }

                if (crypto.isConnectionEncrypted()) {
                    // obtain connection parameters
                    // not supported yet
                    return true;
                }
            }
        }

        if (crypto.isConnectionEncrypted())
            crypto.shutdown(&socket);
    }

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
    if (userCertPath.isEmpty())
        return QList<XSslCertificate>();
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
    if (userKeyPath.isEmpty())
        return XSslKey();
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
    if (userCaCertPath.isEmpty())
        return QList<XSslCertificate>();
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
    if (userCaKeyPath.isEmpty())
        return XSslKey();
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
    if (forwardAddr.isEmpty())
        return QHostAddress();

    QUrl url = QUrl::fromUserInput(forwardAddr);
    return QHostAddress(url.host());
}

quint16 SslUserSettings::getForwardHostPort() const
{
    if (forwardAddr.isEmpty())
        return 0;

    QUrl url = QUrl::fromUserInput(forwardAddr);
    return url.port();
}

bool SslUserSettings::setStartTlsProtocol(const QString &proto)
{
    if (proto == QString("ftp")) {
        startTlsProtocol = SslServer::StartTlsFtp;
        return true;
    } else if (proto == QString("smtp")) {
        startTlsProtocol = SslServer::StartTlsSmtp;
        return true;
    } else if (proto == QString("xmpp")) {
        startTlsProtocol = SslServer::StartTlsXmpp;
        return true;
    } else {
        startTlsProtocol = SslServer::StartTlsUnknownProtocol;
        return false;
    }
}

SslServer::StartTlsProtocol SslUserSettings::getStartTlsProtocol() const
{
    return startTlsProtocol;
}

void SslUserSettings::setLoopTests(bool loop)
{
    loopTests = loop;
}

bool SslUserSettings::getLoopTests() const
{
    return loopTests;
}

bool SslUserSettings::setWaitDataTimeout(int to)
{
    if (to < 0)
        return false;
    waitDataTimeout = static_cast<quint32>(to);
    return true;
}

quint32 SslUserSettings::getWaitDataTimeout() const
{
    return waitDataTimeout;
}

bool SslUserSettings::setOutputXml(const QString &filename)
{
    QFileInfo info(filename);
    if (info.exists()) {
        if (!info.isFile() || !info.isWritable())
            return false;
    } else {
        QFile f(filename);
        if (!f.open(QIODevice::WriteOnly)) {
            f.close();
            return false;
        }
        // file was created, but there is a chance that it won't be used, delete it
        f.remove();
    }
    outputXmlFilename = filename;
    return true;
}

QString SslUserSettings::getOutputXml() const
{
    return outputXmlFilename;
}

bool SslUserSettings::setPidFile(const QString &fileName)
{
    QFileInfo info(fileName);
    if (info.exists()) {
        if (!info.isFile() || !info.isWritable())
            return false;
    } else {
        QFile f(fileName);
        if (!f.open(QIODevice::WriteOnly)) {
            f.close();
            return false;
        }
        // file was created, but there is a chance that it won't be used, delete it
        f.remove();
    }
    pidFile = fileName;
    return true;
}

QString SslUserSettings::getPidFile() const
{
    return pidFile;
}

void SslUserSettings::setUseDtls(bool dtls)
{
    useDtls = dtls;
}

bool SslUserSettings::getUseDtls() const
{
    return useDtls;
}

void SslUserSettings::setDoubleFirstTest(bool flag)
{
    doubleFirstTest = flag;
}

bool SslUserSettings::getDoubleFirstTest() const
{
    return doubleFirstTest;
}

void SslUserSettings::setSupportedCiphers(const QString &ciphers)
{
    QStringList opensslCiphers = ciphers.split(":");

    for (int i = 0; i < opensslCiphers.size(); i++) {
        XSslCipher cipher = XSslCipher(opensslCiphers.at(i));

        if (!cipher.isNull())
            supportedCiphers << cipher;
    }
}

QList<SslUnsafeCipher> SslUserSettings::getSupportedCiphers() const
{
    return supportedCiphers;
}
