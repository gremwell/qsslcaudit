#ifndef SSLTESTS_H
#define SSLTESTS_H

#include "ssltest.h"

#define SSLTESTS_COUNT 22

class SslTest01 : public SslCertificatesTest
{
public:
    SslTest01() : SslCertificatesTest() {
        setId(1);
        setName("custom certificate trust");
        setDescription("certificate trust test with user-supplied certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest02 : public SslCertificatesTest
{
public:
    SslTest02() {
        setId(2);
        setName("self-signed certificate for target domain trust");
        setDescription("certificate trust test with self-signed certificate for user-supplied common name");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest03 : public SslCertificatesTest
{
public:
    SslTest03() {
        setId(3);
        setName("self-signed certificate for invalid domain trust");
        setDescription("certificate trust test with self-signed certificate for www.example.com");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest04 : public SslCertificatesTest
{
public:
    SslTest04() {
        setId(4);
        setName("custom certificate for target domain trust");
        setDescription("certificate trust test with user-supplied common name signed by user-supplied certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest05 : public SslCertificatesTest
{
public:
    SslTest05() {
        setId(5);
        setName("custom certificate for invalid domain trust");
        setDescription("certificate trust test with www.example.com common name signed by user-supplied certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest06 : public SslCertificatesTest
{
public:
    SslTest06() {
        setId(6);
        setName("certificate for target domain signed by custom CA trust");
        setDescription("certificate trust test with user-supplied common name signed by user-supplied CA certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest07 : public SslCertificatesTest
{
public:
    SslTest07() {
        setId(7);
        setName("certificate for invalid domain signed by custom CA trust");
        setDescription("certificate trust test with www.example.com common name signed by user-supplied CA certificate");
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest08 : public SslProtocolsTest
{
public:
    SslTest08() {
        setId(8);
        setName("SSLv2 protocol support");
        setDescription("test for SSLv2 protocol support");
    }
    bool setProtoAndCiphers();

};

class SslTest09 : public SslProtocolsTest
{
public:
    SslTest09() {
        setId(9);
        setName("SSLv3 protocol support");
        setDescription("test for SSLv3 protocol support");
    }
    bool setProtoAndCiphers();

};

class SslTest10 : public SslCiphersTest
{
public:
    SslTest10() {
        setId(10);
        setName("SSLv3 protocol and EXPORT grade ciphers support");
        setDescription("test for SSLv3 protocol and EXPORT grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest11 : public SslCiphersTest
{
public:
    SslTest11() {
        setId(11);
        setName("SSLv3 protocol and LOW grade ciphers support");
        setDescription("test for SSLv3 protocol and LOW grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest12 : public SslCiphersTest
{
public:
    SslTest12() {
        setId(12);
        setName("SSLv3 protocol and MEDIUM grade ciphers support");
        setDescription("test for SSLv3 protocol and MEDIUM grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest13 : public SslProtocolsTest
{
public:
    SslTest13() {
        setId(13);
        setName("TLS 1.0 protocol support");
        setDescription("test for TLS 1.0 protocol support");
    }
    bool setProtoAndCiphers();

};

class SslTest14 : public SslCiphersTest
{
public:
    SslTest14() {
        setId(14);
        setName("TLS 1.0 protocol and EXPORT grade ciphers support");
        setDescription("test for TLS 1.0 protocol and EXPORT grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest15 : public SslCiphersTest
{
public:
    SslTest15() {
        setId(15);
        setName("TLS 1.0 protocol and LOW grade ciphers support");
        setDescription("test for TLS 1.0 protocol and LOW grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest16 : public SslCiphersTest
{
public:
    SslTest16() {
        setId(16);
        setName("TLS 1.0 protocol and MEDIUM grade ciphers support");
        setDescription("test for TLS 1.0 protocol and MEDIUM grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest17 : public SslCiphersTest
{
public:
    SslTest17() {
        setId(17);
        setName("TLS 1.1 protocol and EXPORT grade ciphers support");
        setDescription("test for TLS 1.1 protocol and EXPORT grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest18 : public SslCiphersTest
{
public:
    SslTest18() {
        setId(18);
        setName("TLS 1.1 protocol and LOW grade ciphers support");
        setDescription("test for TLS 1.1 protocol and LOW grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest19 : public SslCiphersTest
{
public:
    SslTest19() {
        setId(19);
        setName("TLS 1.1 protocol and MEDIUM grade ciphers support");
        setDescription("test for TLS 1.1 protocol and MEDIUM grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest20 : public SslCiphersTest
{
public:
    SslTest20() {
        setId(20);
        setName("TLS 1.2 protocol and EXPORT grade ciphers support");
        setDescription("test for TLS 1.2 protocol and EXPORT grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest21 : public SslCiphersTest
{
public:
    SslTest21() {
        setId(21);
        setName("TLS 1.2 protocol and LOW grade ciphers support");
        setDescription("test for TLS 1.2 protocol and LOW grade ciphers support");
    }
    bool setProtoAndCiphers();

};

class SslTest22 : public SslCiphersTest
{
public:
    SslTest22() {
        setId(22);
        setName("TLS 1.2 protocol and MEDIUM grade ciphers support");
        setDescription("test for TLS 1.2 protocol and MEDIUM grade ciphers support");
    }
    bool setProtoAndCiphers();

};

#endif // SSLTESTS_H
