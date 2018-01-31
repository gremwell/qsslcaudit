#ifndef SSLTEST_H
#define SSLTEST_H

#ifdef UNSAFE
#include "sslunsafecertificate.h"
#include "sslunsafekey.h"
#include "sslunsafecipher.h"
#include "sslunsafeerror.h"
#else
#include <QSslCertificate>
#include <QSslKey>
#include <QSslCipher>
#include <QSslError>
#endif

#include "sslusersettings.h"


class SslTest
{
public:
    SslTest();

    static SslTest *createTest(int id);

    virtual bool prepare(const SslUserSettings &settings) = 0;
    virtual void calcResults() = 0;

    void printReport();

    QString name() const { return m_name; }
    void setName(const QString &name) { m_name = name; }

    QString description() const { return m_description; }
    void setDescription(const QString &descr) { m_description = descr; }

    int result() const { return m_result; }
    void setResult(int result) { m_result = result; }

    void setLocalCert(const QList<XSslCertificate> &chain) { m_localCertsChain = chain; }
    QList<XSslCertificate> localCert() const { return m_localCertsChain; }

    void setPrivateKey(const XSslKey &key) { m_privateKey = key; }
    XSslKey privateKey() const { return m_privateKey; }

    void setSslProtocol(XSsl::SslProtocol proto) { m_sslProtocol = proto; }
    XSsl::SslProtocol sslProtocol() const { return m_sslProtocol; }

    void setSslCiphers(const QList<XSslCipher> ciphers) { m_sslCiphers = ciphers; }
    QList<XSslCipher> sslCiphers() const { return m_sslCiphers; }

    void addSslErrors(const QList<XSslError> errors) { m_sslErrors << errors; }
    void addSocketErrors(const QList<QAbstractSocket::SocketError> errors) { m_socketErrors << errors; }
    void setSslConnectionStatus(bool isEstablished) { m_sslConnectionEstablished = isEstablished; }
    void addInterceptedData(const QByteArray &data) { m_interceptedData.append(data); }

    const QByteArray &interceptedData() { return m_interceptedData; }

private:
    QString m_name;
    QString m_description;
    int m_result;
    QString m_report;
    QList<XSslCertificate> m_localCertsChain;
    XSslKey m_privateKey;
    XSsl::SslProtocol m_sslProtocol;
    QList<XSslCipher> m_sslCiphers;

    QList<XSslError> m_sslErrors;
    QList<QAbstractSocket::SocketError> m_socketErrors;
    bool m_sslConnectionEstablished;
    QByteArray m_interceptedData;

    friend class SslCertificatesTest;
    friend class SslProtocolsTest;
};

class SslCertificatesTest : public SslTest
{
public:
    virtual void calcResults();

};

class SslProtocolsTest : public SslTest
{
public:
    virtual bool prepare(const SslUserSettings &settings);
    virtual void calcResults();
    virtual bool setProtoAndCiphers() = 0;

};

#endif // SSLTEST_H
