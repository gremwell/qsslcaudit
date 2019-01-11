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

    enum SslTestResult {
        SSLTEST_RESULT_SUCCESS = 0,
        SSLTEST_RESULT_NOT_READY = -99,
        SSLTEST_RESULT_UNDEFINED = -98,
        SSLTEST_RESULT_INIT_FAILED = -1,
        SSLTEST_RESULT_DATA_INTERCEPTED = -2,
        SSLTEST_RESULT_CERT_ACCEPTED = -3,
        SSLTEST_RESULT_PROTO_ACCEPTED = -4,
        SSLTEST_RESULT_PROTO_ACCEPTED_WITH_ERR = -5,
    };

    SslTest();
    virtual ~SslTest();

    static SslTest *createTest(int id);
    static const QString resultToStatus(enum SslTest::SslTestResult result);

    virtual bool prepare(const SslUserSettings &settings) = 0;
    virtual void calcResults() = 0;

    void printReport();

    int id() const { return m_id; }
    void setId(int id) { m_id = id; }

    int group() const { return m_group; }
    void setGroup(int group) { m_group = group; }

    QString name() const { return m_name; }
    void setName(const QString &name) { m_name = name; }

    QString description() const { return m_description; }
    void setDescription(const QString &descr) { m_description = descr; }

    void clear();

    enum SslTest::SslTestResult result() const { return m_result; }
    void setResult(enum SslTest::SslTestResult result) { m_result = result; }

    void setLocalCert(const QList<XSslCertificate> &chain) { m_localCertsChain = chain; }
    QList<XSslCertificate> localCert() const { return m_localCertsChain; }

    void setPrivateKey(const XSslKey &key) { m_privateKey = key; }
    XSslKey privateKey() const { return m_privateKey; }

    void setSslProtocol(XSsl::SslProtocol proto) { m_sslProtocol = proto; }
    XSsl::SslProtocol sslProtocol() const { return m_sslProtocol; }

    void setSslCiphers(const QList<XSslCipher> ciphers) { m_sslCiphers = ciphers; }
    QList<XSslCipher> sslCiphers() const { return m_sslCiphers; }

    void addSslErrors(const QList<XSslError> errors) { m_sslErrors << errors; }
    void addSslErrorString(const QString error) { m_sslErrorsStr << error; }
    void addSocketErrors(const QList<QAbstractSocket::SocketError> errors) { m_socketErrors << errors; }
    void setSslConnectionStatus(bool isEstablished) { m_sslConnectionEstablished = isEstablished; }
    void addInterceptedData(const QByteArray &data) { m_interceptedData.append(data); }
    void addRawDataRecv(const QByteArray &data) { m_rawDataRecv.append(data); }
    void addRawDataSent(const QByteArray &data) { m_rawDataSent.append(data); }

    const QByteArray &interceptedData() { return m_interceptedData; }
    const QByteArray &rawDataRecv() { return m_rawDataRecv; }
    const QByteArray &rawDataSent() { return m_rawDataSent; }

private:
    bool checkProtoSupport(XSsl::SslProtocol proto);
    bool checkForNonSslClient();
    bool checkForSocketErrors();
    bool checkForGenericSslErrors();

    int m_id;
    int m_group;
    QString m_name;
    QString m_description;
    enum SslTest::SslTestResult m_result;
    QString m_report;
    QList<XSslCertificate> m_localCertsChain;
    XSslKey m_privateKey;
    XSsl::SslProtocol m_sslProtocol;
    QList<XSslCipher> m_sslCiphers;

    QList<XSslError> m_sslErrors;
    QStringList m_sslErrorsStr;
    QList<QAbstractSocket::SocketError> m_socketErrors;
    bool m_sslConnectionEstablished;
    QByteArray m_interceptedData;
    QByteArray m_rawDataRecv;
    QByteArray m_rawDataSent;

    friend class SslCertificatesTest;
    friend class SslProtocolsCiphersTest;
};

class SslCertificatesTest : public SslTest
{
public:
    SslCertificatesTest() {
        setGroup(SSLTESTS_GROUP_CERTS);
    }

    virtual void calcResults();

};

class SslProtocolsCiphersTest : public SslTest
{
public:
    virtual bool prepare(const SslUserSettings &settings);
    virtual void calcResults();
    virtual bool setProtoAndCiphers() = 0;
    bool setProtoOnly(XSsl::SslProtocol proto);
    bool setProtoAndSupportedCiphers(XSsl::SslProtocol proto);
    bool setProtoAndExportCiphers(XSsl::SslProtocol proto);
    bool setProtoAndLowCiphers(XSsl::SslProtocol proto);
    bool setProtoAndMediumCiphers(XSsl::SslProtocol proto);

private:
    bool setProtoAndSpecifiedCiphers(XSsl::SslProtocol proto, QString ciphersString, QString name);

};

class SslProtocolsTest : public SslProtocolsCiphersTest
{
public:
    SslProtocolsTest() {
        setGroup(SSLTESTS_GROUP_PROTOS);
    }
};

class SslCiphersTest : public SslProtocolsCiphersTest
{
public:
    SslCiphersTest() {
        setGroup(SSLTESTS_GROUP_CIPHERS);
    }
};

#endif // SSLTEST_H
