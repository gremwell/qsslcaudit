#ifndef SSLTESTS_H
#define SSLTESTS_H

#include "ssltest.h"

#ifdef UNSAFE
#define XSslConfiguration SslUnsafeConfiguration
#define XSslError SslUnsafeError
#define XSslCertificate SslUnsafeCertificate
#else
#define XSslConfiguration QSslConfiguration
#define XSslError QSslError
#define XSslCertificate QSslCertificate
#endif

class SslTest01 : public SslTest
{
public:
    bool prepare(const SslUserSettings &settings);

};

class SslTest02 : public SslTest
{
public:
    bool prepare(const SslUserSettings &settings);

};

class SslTest03 : public SslTest
{
public:
    bool prepare(const SslUserSettings &settings);

};

class SslTest04 : public SslTest
{
public:
    bool prepare(const SslUserSettings &settings);

};

class SslTest05 : public SslTest
{
public:
    bool prepare(const SslUserSettings &settings);

};

class SslTest06 : public SslTest
{
public:
    bool prepare(const SslUserSettings &settings);

};

class SslTest07 : public SslTest
{
public:
    bool prepare(const SslUserSettings &settings);

};

class SslTest08 : public SslTest
{
public:
    bool prepare(const SslUserSettings &settings);
    void report(const QList<XSslError> sslErrors,
                const QList<QAbstractSocket::SocketError> socketErrors,
                bool sslConnectionEstablished,
                bool dataReceived) const;

};

#endif // SSLTESTS_H
