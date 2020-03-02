#ifndef SSLTESTS_H
#define SSLTESTS_H

#include "ssltest.h"


template <typename T>
class SslTestsFactory
{
public:
    template <typename TDerived>
    void registerType(SslTestId name) {
        static_assert(std::is_base_of<T, TDerived>::value, "Factory::registerType doesn't accept this type because doesn't derive from base class");
        _createFuncs[name] = &createFunc<TDerived>;
    }

    T* create(SslTestId name) {
        typename QMap<SslTestId, PCreateFunc>::const_iterator it = _createFuncs.find(name);
        if (it != _createFuncs.end()) {
            return it.value()();
        }
        return nullptr;
    }

private:
    template <typename TDerived>
    static T* createFunc() {
        return new TDerived();
    }

    typedef T* (*PCreateFunc)();
    QMap<SslTestId, PCreateFunc> _createFuncs;
};

extern SslTestsFactory<SslTest> sslTestsFactory;
extern void fillSslTestsFactory();

class SslTestCertCustom1 : public SslCertificatesTest
{
public:
    SslTestCertCustom1() : SslCertificatesTest() {
        m_id = SslTestId::SslTestCertCustom1;
        m_name = "custom certificate trust";
        m_description = "certificate trust test with user-supplied certificate";
    }
    bool prepare(const SslUserSettings *settings);

};

class SslTestCertSS1 : public SslCertificatesTest
{
public:
    SslTestCertSS1() {
        m_id = SslTestId::SslTestCertSS1;
        m_name = "self-signed certificate for target domain trust";
        m_description = "certificate trust test with self-signed certificate for user-supplied common name";
    }
    bool prepare(const SslUserSettings *settings);

};

class SslTestCertSS2 : public SslCertificatesTest
{
public:
    SslTestCertSS2() {
        m_id = SslTestId::SslTestCertSS2;
        m_name = "self-signed certificate for invalid domain trust";
        m_description = "certificate trust test with self-signed certificate for www.example.com";
    }
    bool prepare(const SslUserSettings *settings);

};

class SslTestCertCustom2 : public SslCertificatesTest
{
public:
    SslTestCertCustom2() {
        m_id = SslTestId::SslTestCertCustom2;
        m_name = "custom certificate for target domain trust";
        m_description = "certificate trust test with user-supplied common name signed by user-supplied certificate";
    }
    bool prepare(const SslUserSettings *settings);

};

class SslTestCertCustom3 : public SslCertificatesTest
{
public:
    SslTestCertCustom3() {
        m_id = SslTestId::SslTestCertCustom3;
        m_name = "custom certificate for invalid domain trust";
        m_description = "certificate trust test with www.example.com common name signed by user-supplied certificate";
    }
    bool prepare(const SslUserSettings *settings);

};

class SslTestCertCA1 : public SslCertificatesTest
{
public:
    SslTestCertCA1() {
        m_id = SslTestId::SslTestCertCA1;
        m_name = "certificate for target domain signed by custom CA trust";
        m_description = "certificate trust test with user-supplied common name signed by user-supplied CA certificate";
    }
    bool prepare(const SslUserSettings *settings);

};

class SslTestCertCA2 : public SslCertificatesTest
{
public:
    SslTestCertCA2() {
        m_id = SslTestId::SslTestCertCA2;
        m_name = "certificate for invalid domain signed by custom CA trust";
        m_description = "certificate trust test with www.example.com common name signed by user-supplied CA certificate";
    }
    bool prepare(const SslUserSettings *settings);

};

class SslTestProtoSsl2 : public SslProtocolsTest
{
public:
    SslTestProtoSsl2() {
        m_id = SslTestId::SslTestProtoSsl2;
        m_name = "SSLv2 protocol support";
        m_description = "test for SSLv2 protocol support";
    }
    bool setProtoAndCiphers();

};

class SslTestProtoSsl3 : public SslProtocolsTest
{
public:
    SslTestProtoSsl3() {
        m_id = SslTestId::SslTestProtoSsl3;
        m_name = "SSLv3 protocol support";
        m_description = "test for SSLv3 protocol support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersSsl3Exp : public SslCiphersTest
{
public:
    SslTestCiphersSsl3Exp() {
        m_id = SslTestId::SslTestCiphersSsl3Exp;
        m_name = "SSLv3 protocol and EXPORT grade ciphers support";
        m_description = "test for SSLv3 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersSsl3Low : public SslCiphersTest
{
public:
    SslTestCiphersSsl3Low() {
        m_id = SslTestId::SslTestCiphersSsl3Low;
        m_name = "SSLv3 protocol and LOW grade ciphers support";
        m_description = "test for SSLv3 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersSsl3Med : public SslCiphersTest
{
public:
    SslTestCiphersSsl3Med() {
        m_id = SslTestId::SslTestCiphersSsl3Med;
        m_name = "SSLv3 protocol and MEDIUM grade ciphers support";
        m_description = "test for SSLv3 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestProtoTls10 : public SslProtocolsTest
{
public:
    SslTestProtoTls10() {
        m_id = SslTestId::SslTestProtoTls10;
        m_name = "TLS 1.0 protocol support";
        m_description = "test for TLS 1.0 protocol support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersTls10Exp : public SslCiphersTest
{
public:
    SslTestCiphersTls10Exp() {
        m_id = SslTestId::SslTestCiphersTls10Exp;
        m_name = "TLS 1.0 protocol and EXPORT grade ciphers support";
        m_description = "test for TLS 1.0 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersTls10Low : public SslCiphersTest
{
public:
    SslTestCiphersTls10Low() {
        m_id = SslTestId::SslTestCiphersTls10Low;
        m_name = "TLS 1.0 protocol and LOW grade ciphers support";
        m_description = "test for TLS 1.0 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersTls10Med : public SslCiphersTest
{
public:
    SslTestCiphersTls10Med() {
        m_id = SslTestId::SslTestCiphersTls10Med;
        m_name = "TLS 1.0 protocol and MEDIUM grade ciphers support";
        m_description = "test for TLS 1.0 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersTls11Exp : public SslCiphersTest
{
public:
    SslTestCiphersTls11Exp() {
        m_id = SslTestId::SslTestCiphersTls11Exp;
        m_name = "TLS 1.1 protocol and EXPORT grade ciphers support";
        m_description = "test for TLS 1.1 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersTls11Low : public SslCiphersTest
{
public:
    SslTestCiphersTls11Low() {
        m_id = SslTestId::SslTestCiphersTls11Low;
        m_name = "TLS 1.1 protocol and LOW grade ciphers support";
        m_description = "test for TLS 1.1 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersTls11Med : public SslCiphersTest
{
public:
    SslTestCiphersTls11Med() {
        m_id = SslTestId::SslTestCiphersTls11Med;
        m_name = "TLS 1.1 protocol and MEDIUM grade ciphers support";
        m_description = "test for TLS 1.1 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersTls12Exp : public SslCiphersTest
{
public:
    SslTestCiphersTls12Exp() {
        m_id = SslTestId::SslTestCiphersTls12Exp;
        m_name = "TLS 1.2 protocol and EXPORT grade ciphers support";
        m_description = "test for TLS 1.2 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersTls12Low : public SslCiphersTest
{
public:
    SslTestCiphersTls12Low() {
        m_id = SslTestId::SslTestCiphersTls12Low;
        m_name = "TLS 1.2 protocol and LOW grade ciphers support";
        m_description = "test for TLS 1.2 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersTls12Med : public SslCiphersTest
{
public:
    SslTestCiphersTls12Med() {
        m_id = SslTestId::SslTestCiphersTls12Med;
        m_name = "TLS 1.2 protocol and MEDIUM grade ciphers support";
        m_description = "test for TLS 1.2 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersDtls10Exp : public SslCiphersTest
{
public:
    SslTestCiphersDtls10Exp() {
        m_id = SslTestId::SslTestCiphersDtls10Exp;
        m_name = "DTLS 1.0 protocol and EXPORT grade ciphers support";
        m_description = "test for DTLS 1.0 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersDtls10Low : public SslCiphersTest
{
public:
    SslTestCiphersDtls10Low() {
        m_id = SslTestId::SslTestCiphersDtls10Low;
        m_name = "DTLS 1.0 protocol and LOW grade ciphers support";
        m_description = "test for DTLS 1.0 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersDtls10Med : public SslCiphersTest
{
public:
    SslTestCiphersDtls10Med() {
        m_id = SslTestId::SslTestCiphersDtls10Med;
        m_name = "DTLS 1.0 protocol and MEDIUM grade ciphers support";
        m_description = "test for DTLS 1.0 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersDtls12Exp : public SslCiphersTest
{
public:
    SslTestCiphersDtls12Exp() {
        m_id = SslTestId::SslTestCiphersDtls12Exp;
        m_name = "DTLS 1.2 protocol and EXPORT grade ciphers support";
        m_description = "test for DTLS 1.2 protocol and EXPORT grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersDtls12Low : public SslCiphersTest
{
public:
    SslTestCiphersDtls12Low() {
        m_id = SslTestId::SslTestCiphersDtls12Low;
        m_name = "DTLS 1.2 protocol and LOW grade ciphers support";
        m_description = "test for DTLS 1.2 protocol and LOW grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCiphersDtls12Med : public SslCiphersTest
{
public:
    SslTestCiphersDtls12Med() {
        m_id = SslTestId::SslTestCiphersDtls12Med;
        m_name = "DTLS 1.2 protocol and MEDIUM grade ciphers support";
        m_description = "test for DTLS 1.2 protocol and MEDIUM grade ciphers support";
    }
    bool setProtoAndCiphers();

};

class SslTestCertCve20200601 : public SslCertificatesTest
{
public:
    SslTestCertCve20200601() : SslCertificatesTest() {
        m_id = SslTestId::SslTestCertCve20200601;
        m_name = "CVE-2020-0601 ECC cert trust";
        m_description = "test for trusting certificate signed by private key with custom curve";
    }
    bool prepare(const SslUserSettings *settings);

};

#endif // SSLTESTS_H
