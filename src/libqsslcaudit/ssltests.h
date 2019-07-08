#ifndef SSLTESTS_H
#define SSLTESTS_H

#include "ssltest.h"

#define SSLTESTS_COUNT 28

class SslTest01 : public SslCertificatesTest
{
public:
    SslTest01() : SslCertificatesTest() {
        m_id = 1;
        m_name = "custom certificate trust";
        m_description = "certificate trust test with user-supplied certificate";
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest02 : public SslCertificatesTest
{
public:
    SslTest02() {
        m_id = 2;
        m_name = "self-signed certificate for target domain trust";
        m_description = "certificate trust test with self-signed certificate for user-supplied common name";
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest03 : public SslCertificatesTest
{
public:
    SslTest03() {
        m_id = 3;
        m_name = "self-signed certificate for invalid domain trust";
        m_description = "certificate trust test with self-signed certificate for www.example.com";
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest04 : public SslCertificatesTest
{
public:
    SslTest04() {
        m_id = 4;
        m_name = "custom certificate for target domain trust";
        m_description = "certificate trust test with user-supplied common name signed by user-supplied certificate";
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest05 : public SslCertificatesTest
{
public:
    SslTest05() {
        m_id = 5;
        m_name = "custom certificate for invalid domain trust";
        m_description = "certificate trust test with www.example.com common name signed by user-supplied certificate";
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest06 : public SslCertificatesTest
{
public:
    SslTest06() {
        m_id = 6;
        m_name = "certificate for target domain signed by custom CA trust";
        m_description = "certificate trust test with user-supplied common name signed by user-supplied CA certificate";
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest07 : public SslCertificatesTest
{
public:
    SslTest07() {
        m_id = 7;
        m_name = "certificate for invalid domain signed by custom CA trust";
        m_description = "certificate trust test with www.example.com common name signed by user-supplied CA certificate";
    }
    bool prepare(const SslUserSettings &settings);

};

class SslTest08 : public SslProtocolsTest
{
public:
    SslTest08() {
        m_id = 8;
        m_name = "SSLv2 protocol support";
        m_description = "test for SSLv2 protocol support";
    }
    bool setProtoAndCiphers();

};

class SslTest09 : public SslProtocolsTest
{
public:
    SslTest09() {
        m_id = 9;
        m_name = "SSLv3 protocol support";
        m_description = "test for SSLv3 protocol support";
    }
    bool setProtoAndCiphers();

};

class SslTest10 : public SslCiphersTest
{
public:
    SslTest10() {
        m_id = 10;
        m_name = "SSLv3 protocol and EXPORT grade ciphers support";
        m_description = "test for SSLv3 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest11 : public SslCiphersTest
{
public:
    SslTest11() {
        m_id = 11;
        m_name = "SSLv3 protocol and LOW grade ciphers support";
        m_description = "test for SSLv3 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest12 : public SslCiphersTest
{
public:
    SslTest12() {
        m_id = 12;
        m_name = "SSLv3 protocol and MEDIUM grade ciphers support";
        m_description = "test for SSLv3 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest13 : public SslProtocolsTest
{
public:
    SslTest13() {
        m_id = 13;
        m_name = "TLS 1.0 protocol support";
        m_description = "test for TLS 1.0 protocol support";
    }
    bool setProtoAndCiphers();

};

class SslTest14 : public SslCiphersTest
{
public:
    SslTest14() {
        m_id = 14;
        m_name = "TLS 1.0 protocol and EXPORT grade ciphers support";
        m_description = "test for TLS 1.0 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest15 : public SslCiphersTest
{
public:
    SslTest15() {
        m_id = 15;
        m_name = "TLS 1.0 protocol and LOW grade ciphers support";
        m_description = "test for TLS 1.0 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest16 : public SslCiphersTest
{
public:
    SslTest16() {
        m_id = 16;
        m_name = "TLS 1.0 protocol and MEDIUM grade ciphers support";
        m_description = "test for TLS 1.0 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest17 : public SslCiphersTest
{
public:
    SslTest17() {
        m_id = 17;
        m_name = "TLS 1.1 protocol and EXPORT grade ciphers support";
        m_description = "test for TLS 1.1 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest18 : public SslCiphersTest
{
public:
    SslTest18() {
        m_id = 18;
        m_name = "TLS 1.1 protocol and LOW grade ciphers support";
        m_description = "test for TLS 1.1 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest19 : public SslCiphersTest
{
public:
    SslTest19() {
        m_id = 19;
        m_name = "TLS 1.1 protocol and MEDIUM grade ciphers support";
        m_description = "test for TLS 1.1 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest20 : public SslCiphersTest
{
public:
    SslTest20() {
        m_id = 20;
        m_name = "TLS 1.2 protocol and EXPORT grade ciphers support";
        m_description = "test for TLS 1.2 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest21 : public SslCiphersTest
{
public:
    SslTest21() {
        m_id = 21;
        m_name = "TLS 1.2 protocol and LOW grade ciphers support";
        m_description = "test for TLS 1.2 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest22 : public SslCiphersTest
{
public:
    SslTest22() {
        m_id = 22;
        m_name = "TLS 1.2 protocol and MEDIUM grade ciphers support";
        m_description = "test for TLS 1.2 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest23 : public SslCiphersTest
{
public:
    SslTest23() {
        m_id = 23;
        m_name = "DTLS 1.0 protocol and EXPORT grade ciphers support";
        m_description = "test for DTLS 1.0 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest24 : public SslCiphersTest
{
public:
    SslTest24() {
        m_id = 24;
        m_name = "DTLS 1.0 protocol and LOW grade ciphers support";
        m_description = "test for DTLS 1.0 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest25 : public SslCiphersTest
{
public:
    SslTest25() {
        m_id = 25;
        m_name = "DTLS 1.0 protocol and MEDIUM grade ciphers support";
        m_description = "test for DTLS 1.0 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest26 : public SslCiphersTest
{
public:
    SslTest26() {
        m_id = 26;
        m_name = "DTLS 1.2 protocol and EXPORT grade ciphers support";
        m_description = "test for DTLS 1.2 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest27 : public SslCiphersTest
{
public:
    SslTest27() {
        m_id = 27;
        m_name = "DTLS 1.2 protocol and LOW grade ciphers support";
        m_description = "test for DTLS 1.2 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTest28 : public SslCiphersTest
{
public:
    SslTest28() {
        m_id = 28;
        m_name = "DTLS 1.2 protocol and MEDIUM grade ciphers support";
        m_description = "test for DTLS 1.2 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

#endif // SSLTESTS_H
