#ifndef SSLTESTS_H
#define SSLTESTS_H

#include "ssltest.h"


class SslTest01 : public SslCertificatesTest
{
public:
    SslTest01() { setDescription("certificate trust test with user-supplied certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest02 : public SslCertificatesTest
{
public:
    SslTest02() { setDescription("certificate trust test with self-signed certificate for user-supplied common name"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest03 : public SslCertificatesTest
{
public:
    SslTest03() { setDescription("certificate trust test with self-signed certificate for www.example.com"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest04 : public SslCertificatesTest
{
public:
    SslTest04() { setDescription("certificate trust test with user-supplied common name signed by user-supplied certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest05 : public SslCertificatesTest
{
public:
    SslTest05() { setDescription("certificate trust test with www.example.com common name signed by user-supplied certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest06 : public SslCertificatesTest
{
public:
    SslTest06() { setDescription("certificate trust test with user-supplied common name signed by user-supplied CA certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest07 : public SslCertificatesTest
{
public:
    SslTest07() { setDescription("certificate trust test with www.example.com common name signed by user-supplied CA certificate"); }
    bool prepare(const SslUserSettings &settings);

};

class SslTest08 : public SslProtocolsTest
{
public:
    SslTest08() { setDescription("SSLv2 protocol support test"); }
    void setProtoAndCiphers();

};

class SslTest09 : public SslProtocolsTest
{
public:
    SslTest09() { setDescription("SSLv3 protocol support test"); }
    void setProtoAndCiphers();

};

class SslTest10 : public SslProtocolsTest
{
public:
    SslTest10() { setDescription("SSLv3 protocol and EXPORT grade ciphers support test"); }
    void setProtoAndCiphers();

};

class SslTest11 : public SslProtocolsTest
{
public:
    SslTest11() { setDescription("SSLv3 protocol and LOW grade ciphers support test"); }
    void setProtoAndCiphers();

};

class SslTest12 : public SslProtocolsTest
{
public:
    SslTest12() { setDescription("SSLv3 protocol and MEDIUM grade ciphers support test"); }
    void setProtoAndCiphers();

};


#endif // SSLTESTS_H
