#ifndef SSLTEST_H
#define SSLTEST_H

#ifdef UNSAFE
#include "sslunsafecertificate.h"
#include "sslunsafekey.h"
#include "sslunsafecipher.h"
#else
#include <QSslCertificate>
#include <QSslKey>
#include <QSslCipher>
#endif

#include "sslusersettings.h"

#ifdef UNSAFE
#define XSslError SslUnsafeError
#define XSslCertificate SslUnsafeCertificate
#define XSslKey SslUnsafeKey
#define XSslCipher SslUnsafeCipher
#else
#define XSslError QSslError
#define XSslCertificate QSslCertificate
#define XSslKey QSslKey
#define XSslCipher QSslCipher
#endif


class SslTest
{
public:
    SslTest();

    virtual bool prepare(const SslUserSettings &settings) = 0;

    virtual void report(const QList<XSslError> sslErrors,
                        const QList<QAbstractSocket::SocketError> socketErrors,
                        bool sslConnectionEstablished,
                        bool dataReceived) const = 0;

    QString description() const { return m_description; }
    void setDescription(const QString &descr) { m_description = descr; }

    void setLocalCert(const QList<XSslCertificate> &chain) { m_localCertsChain = chain; }
    QList<XSslCertificate> localCert() const { return m_localCertsChain; }

    void setPrivateKey(const XSslKey &key) { m_privateKey = key; }
    XSslKey privateKey() const { return m_privateKey; }

    void setSslProtocol(QSsl::SslProtocol proto) { m_sslProtocol = proto; }
    QSsl::SslProtocol sslProtocol() const { return m_sslProtocol; }

    void setSslCiphers(const QList<XSslCipher> ciphers) { m_sslCiphers = ciphers; }
    QList<XSslCipher> sslCiphers() const { return m_sslCiphers; }

private:
    QString m_description;
    QList<XSslCertificate> m_localCertsChain;
    XSslKey m_privateKey;
    QSsl::SslProtocol m_sslProtocol;
    QList<XSslCipher> m_sslCiphers;

};

class SslCertificatesTest : public SslTest
{
public:
    virtual void report(const QList<XSslError> sslErrors,
                        const QList<QAbstractSocket::SocketError> socketErrors,
                        bool sslConnectionEstablished,
                        bool dataReceived) const;

};

class SslProtocolsTest : public SslTest
{
public:
    virtual bool prepare(const SslUserSettings &settings);
    virtual void report(const QList<XSslError> sslErrors,
                        const QList<QAbstractSocket::SocketError> socketErrors,
                        bool sslConnectionEstablished,
                        bool dataReceived) const;
    virtual void setProtoAndCiphers() = 0;

};

#endif // SSLTEST_H
