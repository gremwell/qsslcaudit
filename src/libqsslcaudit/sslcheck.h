#ifndef SSLCHECK_H
#define SSLCHECK_H

#include "ssltestresult.h"

enum class SslCheckId : int
{
    SslCheckSocketErrors,
    SslCheckNoData,
    SslCheckNonSslData,
    SslCheckInvalidSsl,
    SslCheckForGenericSslErrors,
    SslCheckCertificatesValidation,
    SslCheckProtocolsCiphersSupport,
};

class SslCheckInfo
{
public:
    SslCheckId id;
    QString descr;
};

class SslCheckReport
{
public:
    QString report;
    QString comment;
    SslTestResult result;
};

class ClientInfo;
class SslCheck
{
public:
    SslCheck();
    virtual ~SslCheck();

    const SslCheckInfo getInfo() { return info; }
    virtual const SslCheckReport doCheck(const ClientInfo &client) const = 0;

protected:
    SslCheckInfo info;
};

class SslCheckSocketErrors : public SslCheck
{
public:
    SslCheckSocketErrors() {
        info.id = SslCheckId::SslCheckSocketErrors;
        info.descr = QString("check if there are any errors reported by network socket");
    }
    const SslCheckReport doCheck(const ClientInfo &client) const;
};

class SslCheckNoData : public SslCheck
{
public:
    SslCheckNoData() {
        info.id = SslCheckId::SslCheckNoData;
        info.descr = QString("check if no data was transmitted");
    }
    const SslCheckReport doCheck(const ClientInfo &client) const;
};

class SslCheckNonSslData : public SslCheck
{
public:
    SslCheckNonSslData() {
        info.id = SslCheckId::SslCheckNonSslData;
        info.descr = QString("check if data transmitted does not have valid HELLO message");
    }
    const SslCheckReport doCheck(const ClientInfo &client) const;
};

class SslCheckInvalidSsl : public SslCheck
{
public:
    SslCheckInvalidSsl() {
        info.id = SslCheckId::SslCheckInvalidSsl;
        info.descr = QString("check if the client is non-SSL or is broken in another way");
    }
    const SslCheckReport doCheck(const ClientInfo &client) const;
};

class SslCheckForGenericSslErrors : public SslCheck
{
public:
    SslCheckForGenericSslErrors() {
        info.id = SslCheckId::SslCheckForGenericSslErrors;
        info.descr = QString("check if there are generic SSL errors during handshake");
    }
    const SslCheckReport doCheck(const ClientInfo &client) const;
};

class SslCheckCertificatesValidation : public SslCheck
{
public:
    SslCheckCertificatesValidation() {
        info.id = SslCheckId::SslCheckCertificatesValidation;
        info.descr = QString("check if client properly validates certificates");
    }
    const SslCheckReport doCheck(const ClientInfo &client) const;
};

class SslCheckProtocolsCiphersSupport : public SslCheck
{
public:
    SslCheckProtocolsCiphersSupport() {
        info.id = SslCheckId::SslCheckProtocolsCiphersSupport;
        info.descr = QString("check if client supports configured protocol/ciphers");
    }
    const SslCheckReport doCheck(const ClientInfo &client) const;
};

#endif // SSLCHECK_H
