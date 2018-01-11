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
    SslTest01() { setDescription("certificate trust test with user-supplied certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest02 : public SslTest
{
public:
    SslTest02() { setDescription("certificate trust test with self-signed certificate for user-supplied common name"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest03 : public SslTest
{
public:
    SslTest03() { setDescription("certificate trust test with self-signed certificate for www.example.com"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest04 : public SslTest
{
public:
    SslTest04() { setDescription("certificate trust test with user-supplied common name signed by user-supplied certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest05 : public SslTest
{
public:
    SslTest05() { setDescription("certificate trust test with www.example.com common name signed by user-supplied certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest06 : public SslTest
{
public:
    SslTest06() { setDescription("certificate trust test with user-supplied common name signed by user-supplied CA certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest07 : public SslTest
{
public:
    SslTest07() { setDescription("certificate trust test with www.example.com common name signed by user-supplied CA certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest08 : public SslTest
{
public:
    SslTest08() { setDescription("protocol/ciphers support test for protocol ..."); }
    bool prepare(const SslUserSettings &settings);
    void report(const QList<XSslError> sslErrors,
                const QList<QAbstractSocket::SocketError> socketErrors,
                bool sslConnectionEstablished,
                bool dataReceived) const;

};

#endif // SSLTESTS_H
