#ifndef SSLTESTS_H
#define SSLTESTS_H

#include "ssltest.h"

#define SSLTESTS_COUNT 12

class SslTest01 : public SslCertificatesTest
{
public:
    SslTest01() {
        setName("custom certificate trust");
        setDescription("certificate trust test with user-supplied certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest02 : public SslCertificatesTest
{
public:
    SslTest02() {
        setName("self-signed certificate for target domain trust");
        setDescription("certificate trust test with self-signed certificate for user-supplied common name");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest03 : public SslCertificatesTest
{
public:
    SslTest03() {
        setName("self-signed certificate for invalid domain trust");
        setDescription("certificate trust test with self-signed certificate for www.example.com");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest04 : public SslCertificatesTest
{
public:
    SslTest04() {
        setName("custom certificate for target domain trust");
        setDescription("certificate trust test with user-supplied common name signed by user-supplied certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest05 : public SslCertificatesTest
{
public:
    SslTest05() {
        setName("custom certificate for invalid domain trust");
        setDescription("certificate trust test with www.example.com common name signed by user-supplied certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest06 : public SslCertificatesTest
{
public:
    SslTest06() {
        setName("certificate for target domain signed by custom CA trust");
        setDescription("certificate trust test with user-supplied common name signed by user-supplied CA certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest07 : public SslCertificatesTest
{
public:
    SslTest07() {
        setName("certificate for invalid domain signed by custom CA trust");
        setDescription("certificate trust test with www.example.com common name signed by user-supplied CA certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest08 : public SslProtocolsTest
{
public:
    SslTest08() {
        setName("SSLv2 protocol support");
        setDescription("test for SSLv2 protocol support");
    }
    bool setProtoAndCiphers();

};

class SslTest09 : public SslProtocolsTest
{
public:
    SslTest09() {
        setName("SSLv3 protocol support");
        setDescription("test for SSLv3 protocol support");
    }
    bool setProtoAndCiphers();

};

class SslTest10 : public SslProtocolsTest
{
public:
    SslTest10() {
        setName("SSLv3 protocol and EXPORT grade ciphers support");
        setDescription("test for SSLv3 protocol and EXPORT grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest11 : public SslProtocolsTest
{
public:
    SslTest11() {
        setName("SSLv3 protocol and LOW grade ciphers support");
        setDescription("test for SSLv3 protocol and LOW grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest12 : public SslProtocolsTest
{
public:
    SslTest12() {
        setName("SSLv3 protocol and MEDIUM grade ciphers support");
        setDescription("test for SSLv3 protocol and MEDIUM grade ciphers support");
    }
    bool setProtoAndCiphers();

};


#endif // SSLTESTS_H
