#ifndef SSLUSERSETTINGS_H
#define SSLUSERSETTINGS_H

#include <QHostAddress>

#include "sslserver.h"

#ifdef UNSAFE_QSSL
#include "sslunsafecertificate.h"
#else
#include <QSslCertificate>
#endif


class SslUserSettings
{
public:
    SslUserSettings();

    void setListenAddress(const QHostAddress &addr);
    QHostAddress getListenAddress() const;

    bool setListenPort(int port);
    quint16 getListenPort() const;

    void setUserCN(const QString &cn);
    QString getUserCN() const;

    bool setServerAddr(const QString &addr);
    QString getServerAddr() const;
    QList<XSslCertificate> getPeerCertificates() const;

    bool setUserCertPath(const QString &path);
    QString getUserCertPath() const;
    QList<XSslCertificate> getUserCert() const;

    bool setUserKeyPath(const QString &path);
    QString getUserKeyPath() const;
    XSslKey getUserKey() const;

    bool setUserCaCertPath(const QString &path);
    QString getUserCaCertPath() const;
    QList<XSslCertificate> getUserCaCert() const;

    bool setUserCaKeyPath(const QString &path);
    QString getUserCaKeyPath() const;
    XSslKey getUserCaKey() const;

    void setForwardAddr(const QString &addr);
    QString getForwardAddr() const;
    QHostAddress getForwardHostAddr() const;
    quint16 getForwardHostPort() const;

    bool setStartTlsProtocol(const QString &proto);
    SslServer::StartTlsProtocol getStartTlsProtocol() const;

    void setLoopTests(bool loop);
    bool getLoopTests() const;

    bool setWaitDataTimeout(int to);
    quint32 getWaitDataTimeout() const;

    bool setOutputXml(const QString &filename);
    QString getOutputXml() const;

    bool setPidFile(const QString &fileName);
    QString getPidFile() const;

    void setUseDtls(bool dtls);
    bool getUseDtls() const;

    void setDoubleFirstTest(bool flag);
    bool getDoubleFirstTest() const;

    void setSupportedCiphers(const QString &ciphers);
    QList<XSslCipher> getSupportedCiphers() const;

private:
    QHostAddress listenAddress;
    quint16 listenPort;
    QString userCN;
    QString serverAddr;
    QString userCertPath;
    QString userKeyPath;
    QString userCaCertPath;
    QString userCaKeyPath;
    QString forwardAddr;
    QList<XSslCertificate> peerCerts;
    SslServer::StartTlsProtocol startTlsProtocol;
    bool loopTests;
    quint32 waitDataTimeout;
    QString outputXmlFilename;
    QString pidFile;
    bool useDtls;
    bool doubleFirstTest;
    QList<XSslCipher> supportedCiphers;
};

#endif // SSLUSERSETTINGS_H
