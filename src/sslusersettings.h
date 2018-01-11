#ifndef SSLUSERSETTINGS_H
#define SSLUSERSETTINGS_H

#include <QHostAddress>

#ifdef UNSAFE
#include "sslunsafecertificate.h"
#else
#include <QSslCertificate>
#endif

#ifdef UNSAFE
#define XSslCertificate SslUnsafeCertificate
#define XSslKey SslUnsafeKey
#else
#define XSslCertificate QSslCertificate
#define XSslKey QSslKey
#endif


class SslUserSettings
{
public:
    SslUserSettings();

    void setListenAddress(const QHostAddress &addr);
    QHostAddress getListenAddress() const;

    void setListenPort(quint16 port);
    quint16 getListenPort() const;

    void setUserCN(const QString &cn);
    QString getUserCN() const;

    void setServerAddr(const QString &addr);
    QString getServerAddr() const;

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

private:
    QHostAddress listenAddress;
    quint16 listenPort;
    QString userCN;
    QString serverAddr;
    QString userCertPath;
    QString userKeyPath;
    QString userCaCertPath;
    QString userCaKeyPath;

};

#endif // SSLUSERSETTINGS_H
