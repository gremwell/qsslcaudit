#ifndef CLIENTINFO_H
#define CLIENTINFO_H

#include <QAbstractSocket>

#ifdef UNSAFE_QSSL
#include "sslunsafecertificate.h"
#include "sslunsafekey.h"
#include "sslunsafecipher.h"
#include "sslunsafeerror.h"
#include "sslunsafeconfiguration.h"
#include "sslunsafedtls.h"
#else
#include <QSslCertificate>
#include <QSslKey>
#include <QSslCipher>
#include <QSslError>
#include <QSslConfiguration>
#include <QDtls>
#endif

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

    bool operator==(const TlsClientHelloExt &other) const;

    bool operator!=(const TlsClientHelloExt &other) const {
        return !operator==(other);
    }

    void clear();
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
    QByteArray cookie;

    TlsClientHelloExt hnd_hello;

    QString printable() const;

    bool operator==(const TlsClientHelloInfo &other) const;

    bool operator!=(const TlsClientHelloInfo &other) const {
        return !operator==(other);
    }

    void clear();
};

class ClientInfo
{
public:
    ClientInfo() {
        clear();
    }

    void addSslErrors(const QList<XSslError> errors) { m_sslErrors << errors; }

    void setDtlsMode(bool dtlsMode) { m_dtlsMode = dtlsMode; }
    bool dtlsMode() const { return m_dtlsMode; }

    void addDtlsError(XDtlsError error) { m_dtlsErrors << error; }
    const QList<XDtlsError> &dtlsErrors() const { return m_dtlsErrors; }

    void addSslErrorString(const QString error) { m_sslErrorsStr << error; }
    const QStringList &sslErrorsStr() const { return m_sslErrorsStr; }

    void setSslConnectionStatus(bool isEstablished) { m_sslConnectionEstablished = isEstablished; }
    bool sslConnectionEstablished() const { return m_sslConnectionEstablished; }

    void addSocketErrors(const QList<QAbstractSocket::SocketError> errors) { m_socketErrors << errors; }
    const QList<QAbstractSocket::SocketError> &socketErrors() const { return m_socketErrors; }

    void addInterceptedData(const QByteArray &data) { m_interceptedData.append(data); }
    const QByteArray &interceptedData() const { return m_interceptedData; }

    void addRawDataRecv(const QByteArray &data);
    const QByteArray &rawDataRecv() const { return m_rawDataRecv; }

    void addRawDataSent(const QByteArray &data) { m_rawDataSent.append(data); }
    const QByteArray &rawDataSent() const { return m_rawDataSent; }

    void setSourceHost(const QString &host) { m_sourceHost = host; }
    const QString &sourceHost() const { return m_sourceHost; }

    bool hasHelloMessage() const { return m_hasHelloMessage; }

    TlsClientHelloInfo tlsHelloInfo;

    QString printable() const;

    bool isEqualTo(const ClientInfo *other) const;

    bool operator==(const ClientInfo &other) const;

    bool operator!=(const ClientInfo &other) const {
        return !operator==(other);
    }

    void clear();

private:
    void parseRawData();

    QList<QAbstractSocket::SocketError> m_socketErrors;
    QList<XSslError> m_sslErrors;
    QStringList m_sslErrorsStr;
    bool m_sslConnectionEstablished;
    QByteArray m_interceptedData;
    QList<XDtlsError> m_dtlsErrors;
    QByteArray m_rawDataRecv;
    QByteArray m_rawDataSent;
    QString m_sourceHost;
    bool m_hasHelloMessage;
    bool m_isBrokenSslClient;
    bool m_dtlsMode;

};

QDebug operator<<(QDebug, const ClientInfo &);


#endif // CLIENTINFO_H
