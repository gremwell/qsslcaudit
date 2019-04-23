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

class TlsClientHelloExt
{
public:
    TlsClientHelloExt() {
        clear();
    }

    QVector<QPair<quint8, QByteArray>> server_name;

    quint8 heartbeat_mode;
    quint16 padding;
    quint16 record_size_limit;
    quint16 supported_version;
    quint8 encrypt_then_mac;
    quint8 extended_master_secret;
    QByteArray cert_status_type_ocsp_responder_id_list;
    QByteArray cert_status_type_ocsp_request_extensions;
    QVector<quint16> supported_versions;
    QVector<quint8> ec_point_formats;
    QVector<quint16> supported_groups;
    QByteArray session_ticket_data;
    QVector<QPair<quint8, quint8>> sig_hash_algs;
    QVector<QByteArray> npn;
    QVector<QByteArray> alpn;

    QString printable() const;

    bool operator==(const TlsClientHelloExt &other) const {
        if ((server_name != other.server_name)
                || (heartbeat_mode != other.heartbeat_mode)
                || (supported_version != other.supported_version)
                || (encrypt_then_mac != other.encrypt_then_mac)
                || (supported_versions != other.supported_versions)
                || (ec_point_formats != other.ec_point_formats)
                || (supported_groups != other.supported_groups)
                || (sig_hash_algs != other.sig_hash_algs)
                || (npn != other.npn)
                || (alpn != other.alpn))
            return false;
        return true;
    }

    bool operator!=(const TlsClientHelloExt &other) const {
        return !operator==(other);
    }

    void clear() {
        server_name.clear();
        server_name.squeeze();
        heartbeat_mode = 0;
        padding = 0;
        record_size_limit = 0;
        supported_version = 0;
        encrypt_then_mac = 0;
        extended_master_secret = 0;
        cert_status_type_ocsp_responder_id_list.clear();
        cert_status_type_ocsp_responder_id_list.squeeze();
        cert_status_type_ocsp_request_extensions.clear();
        cert_status_type_ocsp_request_extensions.squeeze();
        supported_versions.clear();
        supported_versions.squeeze();
        ec_point_formats.clear();
        ec_point_formats.squeeze();
        supported_groups.clear();
        supported_groups.squeeze();
        session_ticket_data.clear();
        session_ticket_data.squeeze();
        sig_hash_algs.clear();
        sig_hash_algs.squeeze();
        npn.clear();
        npn.squeeze();
        alpn.clear();
        alpn.squeeze();
    }
};

class TlsClientHelloInfo
{
public:
    TlsClientHelloInfo() {
        clear();
    }

    quint16 version;
    QVector<quint32> ciphers;
    QByteArray session_id;
    QByteArray challenge;
    QVector<quint8> comp_methods;
    quint32 random_time;
    QByteArray random;

    TlsClientHelloExt hnd_hello;

    QString printable() const;

    bool operator==(const TlsClientHelloInfo &other) const {
        if ((version != other.version)
                || (ciphers != other.ciphers)
                || (comp_methods != other.comp_methods)
                || (hnd_hello != other.hnd_hello))
            return false;
        return true;
    }

    bool operator!=(const TlsClientHelloInfo &other) const {
        return !operator==(other);
    }

    void clear() {
        version = 0;
        ciphers.clear();
        ciphers.squeeze();
        session_id.clear();
        session_id.squeeze();
        challenge.clear();
        challenge.squeeze();
        comp_methods.clear();
        comp_methods.squeeze();
        random_time = 0;
        random.clear();
        random.squeeze();
        hnd_hello.clear();
    }
};

class TlsClientInfo
{
public:
    TlsClientInfo() {
        clear();
    }

    QString sourceHost;

    bool hasHelloMessage;
    bool isBrokenSslClient;

    TlsClientHelloInfo tlsHelloInfo;

    QByteArray rawDataRecv;

    QString printable() const;

    bool operator==(const TlsClientInfo &other) const {
        if ((sourceHost != other.sourceHost)
                || (hasHelloMessage != other.hasHelloMessage)
                || (isBrokenSslClient != other.isBrokenSslClient)
                || (tlsHelloInfo != other.tlsHelloInfo)
                || (isBrokenSslClient && (rawDataRecv != other.rawDataRecv)))
            return false;
        return true;
    }

    bool operator!=(const TlsClientInfo &other) const {
        return !operator==(other);
    }

    void clear() {
        sourceHost = QString();
        hasHelloMessage = false;
        isBrokenSslClient = false;
        tlsHelloInfo.clear();
        rawDataRecv.clear();
    }
};

QDebug operator<<(QDebug, const TlsClientInfo &);

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

    QString resultComment() const { return m_resultComment; }

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
    void addRawDataRecv(const QByteArray &data) {
        m_rawDataRecv.append(data);
        m_clientInfo.rawDataRecv.append(data);
    }
    void addRawDataSent(const QByteArray &data) { m_rawDataSent.append(data); }

    const QByteArray &interceptedData() { return m_interceptedData; }
    const QByteArray &rawDataRecv() { return m_rawDataRecv; }
    const QByteArray &rawDataSent() { return m_rawDataSent; }

    TlsClientInfo clientInfo() { return m_clientInfo; }

    void setClientSourceHost(const QString &host) { m_clientInfo.sourceHost = host; }

private:
    bool checkProtoSupport(XSsl::SslProtocol proto);
    bool checkForNonSslClient();
    bool checkForSocketErrors();
    bool checkForGenericSslErrors();
    bool isHelloMessage(const QByteArray &buf, bool *isSsl2);
    int helloPosInBuffer(const QByteArray &buf, bool *isSsl2);

    int m_id;
    int m_group;
    QString m_name;
    QString m_description;
    enum SslTest::SslTestResult m_result;
    QString m_resultComment;
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
    TlsClientInfo m_clientInfo;

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
