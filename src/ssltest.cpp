#include "ssltest.h"
#include "debug.h"
#include "sslcertgen.h"
#include "ssltests.h"


SslTest::SslTest()
{

}

SslTest *SslTest::createTest(int id)
{
    switch (id) {
    case 0:
        return new SslTest01();
    case 1:
        return new SslTest02();
    case 2:
        return new SslTest03();
    case 3:
        return new SslTest04();
    case 4:
        return new SslTest05();
    case 5:
        return new SslTest06();
    case 6:
        return new SslTest07();
    case 7:
        return new SslTest08();
    case 8:
        return new SslTest09();
    case 9:
        return new SslTest10();
    case 10:
        return new SslTest11();
    case 11:
        return new SslTest12();
    }
    return NULL;
}

void SslCertificatesTest::report(const QList<XSslError> sslErrors,
                                 const QList<QAbstractSocket::SocketError> socketErrors,
                                 bool sslConnectionEstablished,
                                 bool dataReceived)
{
    if (dataReceived) {
        RED("test failed, client accepted fake certificate, data was intercepted");
        setResult(-1);
        return;
    }

    if (sslConnectionEstablished && !dataReceived
            && !socketErrors.contains(QAbstractSocket::RemoteHostClosedError)) {
        RED("test failed, client accepted fake certificate, but no data transmitted");
        setResult(-1);
        return;
    }

    GREEN("test passed, client refused fake certificate");
    setResult(0);
}

void SslProtocolsTest::report(const QList<XSslError> sslErrors,
                              const QList<QAbstractSocket::SocketError> socketErrors,
                              bool sslConnectionEstablished,
                              bool dataReceived)
{
    if (dataReceived) {
        RED("test failed, client accepted fake certificate and weak protocol, data was intercepted");
        setResult(-1);
        return;
    }

    if (sslConnectionEstablished && !dataReceived
            && !socketErrors.contains(QAbstractSocket::RemoteHostClosedError)) {
        RED("test failed, client accepted fake certificate and weak protocol, but no data transmitted");
        setResult(-1);
        return;
    }

    if (sslConnectionEstablished) {
        RED("test failed, client accepted weak protocol");
        setResult(-1);
        return;
    }

    GREEN("test passed, client does not accept weak protocol");
    setResult(0);
}

bool SslProtocolsTest::prepare(const SslUserSettings &settings)
{
    XSslKey key;
    QList<XSslCertificate> chain = settings.getUserCert();
    if (chain.size() != 0) {
        key = settings.getUserKey();
    }

    if ((chain.size() == 0) || key.isNull()) {
        QString cn;

        if (settings.getUserCN().length() > 0) {
            cn = settings.getUserCN();
        } else {
            cn = "www.example.com";
        }

        QPair<XSslCertificate, XSslKey> generatedCert = SslCertGen::genSignedCert(cn);
        chain.clear();
        chain << generatedCert.first;
        key = generatedCert.second;
    }

    // these parameters should be insignificant, but we tried to make them as much "trustful" as possible
    setLocalCert(chain);
    setPrivateKey(key);

    return setProtoAndCiphers();
}
