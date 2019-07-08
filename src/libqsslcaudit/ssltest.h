#ifndef SSLTEST_H
#define SSLTEST_H

#ifdef UNSAFE_QSSL
#include "sslunsafecertificate.h"
#include "sslunsafekey.h"
#include "sslunsafecipher.h"
#include "sslunsafeerror.h"
#include "sslunsafeconfiguration.h"
#else
#include <QSslCertificate>
#include <QSslKey>
#include <QSslCipher>
#include <QSslError>
#include <QSslConfiguration>
#endif

#include "sslusersettings.h"
#include "ssltestresult.h"
#include "clientinfo.h"

enum {
    SSLTESTS_GROUP_CERTS,
    SSLTESTS_GROUP_PROTOS,
    SSLTESTS_GROUP_CIPHERS,
};

static const QString SSLTESTS_GROUP_CERTS_STR = QString("certs");
static const QString SSLTESTS_GROUP_PROTOS_STR = QString("protos");
static const QString SSLTESTS_GROUP_CIPHERS_STR = QString("ciphers");

class SslTest
{
public:
    SslTest();
    virtual ~SslTest();

    static SslTest *createTest(int id);
    void clear();

    // implemented by a particular tests
    virtual bool prepare(const SslUserSettings &settings) = 0;
    virtual void calcResults(const ClientInfo client) = 0;

    // test description
    int id() const { return m_id; }
    int group() const { return m_group; }
    QString name() const { return m_name; }
    QString description() const { return m_description; }

    // test results
    SslTestResult result() const { return m_result; }
    QString resultComment() const { return m_resultComment; }
    QString report() const { return m_report; }

    // used by TLS servers to setup listener
    QList<XSslCertificate> localCert() const { return m_localCertsChain; }
    XSslKey privateKey() const { return m_privateKey; }
    XSsl::SslProtocol sslProtocol() const { return m_sslProtocol; }
    QList<XSslCipher> sslCiphers() const { return m_sslCiphers; }

protected:
    // utils
    bool checkProtoSupport(XSsl::SslProtocol proto);

    // test info
    int m_id;
    int m_group;
    QString m_name;
    QString m_description;

    // test result
    SslTestResult m_result;
    QString m_resultComment;
    QString m_report;

    // generated settings
    QList<XSslCertificate> m_localCertsChain;
    XSslKey m_privateKey;
    XSsl::SslProtocol m_sslProtocol;
    QList<XSslCipher> m_sslCiphers;
};

class SslCertificatesTest : public SslTest
{
public:
    SslCertificatesTest() {
        m_group = SSLTESTS_GROUP_CERTS;
    }

    virtual void calcResults(const ClientInfo client);

};

class SslProtocolsCiphersTest : public SslTest
{
public:
    virtual bool prepare(const SslUserSettings &settings);
    virtual void calcResults(const ClientInfo client);
    virtual bool setProtoAndCiphers() = 0;
protected:
    bool setProtoAndSupportedCiphers(XSsl::SslProtocol proto);
    bool setProtoAndExportCiphers(XSsl::SslProtocol proto);
    bool setProtoAndLowCiphers(XSsl::SslProtocol proto);
    bool setProtoAndMediumCiphers(XSsl::SslProtocol proto);
private:
    bool setProtoOnly(XSsl::SslProtocol proto);
    bool setProtoAndSpecifiedCiphers(XSsl::SslProtocol proto, QString ciphersString, QString name);

};

class SslProtocolsTest : public SslProtocolsCiphersTest
{
public:
    SslProtocolsTest() {
        m_group = SSLTESTS_GROUP_PROTOS;
    }
};

class SslCiphersTest : public SslProtocolsCiphersTest
{
public:
    SslCiphersTest() {
        m_group = SSLTESTS_GROUP_CIPHERS;
    }
};

#endif // SSLTEST_H
