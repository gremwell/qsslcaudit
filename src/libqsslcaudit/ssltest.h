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


enum class SslTestGroup {
    Certificates,
    Protocols,
    Ciphers,
    Nonexisted,
};

enum class SslTestId : int {
    SslTestCertCustom1,
    SslTestCertSS1,
    SslTestCertSS2,
    SslTestCertCustom2,
    SslTestCertCustom3,
    SslTestCertCA1,
    SslTestCertCA2,
    SslTestProtoSsl2,
    SslTestProtoSsl3,
    SslTestCiphersSsl3Exp,
    SslTestCiphersSsl3Low,
    SslTestCiphersSsl3Med,
    SslTestProtoTls10,
    SslTestCiphersTls10Exp,
    SslTestCiphersTls10Low,
    SslTestCiphersTls10Med,
    SslTestCiphersTls11Exp,
    SslTestCiphersTls11Low,
    SslTestCiphersTls11Med,
    SslTestCiphersTls12Exp,
    SslTestCiphersTls12Low,
    SslTestCiphersTls12Med,
    SslTestCiphersDtls10Exp,
    SslTestCiphersDtls10Low,
    SslTestCiphersDtls10Med,
    SslTestCiphersDtls12Exp,
    SslTestCiphersDtls12Low,
    SslTestCiphersDtls12Med,
    SslTestNonexisting,
};


class SslTest
{
public:
    SslTest() { clear(); }
    virtual ~SslTest();

    void clear();

    // implemented by a particular tests
    virtual bool prepare(const SslUserSettings &settings) = 0;
    virtual void calcResults(const ClientInfo client) = 0;

    // test description
    SslTestId id() const { return m_id; }
    QString name() const { return m_name; }
    QString description() const { return m_description; }

    SslTestGroup group() const { return m_group; }
    static QString groupToStr(SslTestGroup group) {
        switch (group) {
        case SslTestGroup::Certificates:
            return "certs";
        case SslTestGroup::Protocols:
            return "protos";
        case SslTestGroup::Ciphers:
            return "ciphers";
        case SslTestGroup::Nonexisted:
            return "unassigned";
        }
        return "";
    }

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
    SslTestId m_id;
    SslTestGroup m_group;
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
        m_group = SslTestGroup::Certificates;
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
        m_group = SslTestGroup::Protocols;
    }
};

class SslCiphersTest : public SslProtocolsCiphersTest
{
public:
    SslCiphersTest() {
        m_group = SslTestGroup::Ciphers;
    }
};

#endif // SSLTEST_H
