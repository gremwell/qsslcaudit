#include "ssltest.h"
#include "debug.h"
#include "sslcertgen.h"
#include "ssltests.h"


SslTest::SslTest()
{
    m_sslErrors = QList<XSslError>();
    m_socketErrors = QList<QAbstractSocket::SocketError>();
    m_sslConnectionEstablished = false;
    m_interceptedData = QByteArray();
    m_result = -99;
    m_report = QString("test results undefined");
}

SslTest::~SslTest()
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
    case 12:
        return new SslTest13();
    case 13:
        return new SslTest14();
    case 14:
        return new SslTest15();
    case 15:
        return new SslTest16();
    }
    return NULL;
}

void SslTest::printReport()
{
    if (m_result < 0) {
        RED(m_report);
    } else {
        GREEN(m_report);
    }
}

void SslCertificatesTest::calcResults()
{
    if (m_interceptedData.size() > 0) {
        m_report = QString("test failed, client accepted fake certificate, data was intercepted");
        setResult(-1);
        return;
    }

    if (m_sslConnectionEstablished && (m_interceptedData.size() == 0)
            && !m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)) {
        m_report = QString("test failed, client accepted fake certificate, but no data transmitted");
        setResult(-2);
        return;
    }

    if (m_socketErrors.contains(QAbstractSocket::SslInternalError)
            || m_socketErrors.contains(QAbstractSocket::SslInvalidUserDataError)) {
        m_report = QString("failure during SSL initialization");
        setResult(-3);
        return;
    }

    m_report = QString("test passed, client refused fake certificate");
    setResult(0);
}

void SslProtocolsTest::calcResults()
{
    if (m_interceptedData.size() > 0) {
        m_report = QString("test failed, client accepted fake certificate and weak protocol, data was intercepted");
        setResult(-1);
        return;
    }

    if (m_sslConnectionEstablished && (m_interceptedData.size() == 0)
            && !m_socketErrors.contains(QAbstractSocket::RemoteHostClosedError)) {
        m_report = QString("test failed, client accepted fake certificate and weak protocol, but no data transmitted");
        setResult(-2);
        return;
    }

    if (m_sslConnectionEstablished) {
        m_report = QString("test failed, client accepted weak protocol");
        setResult(-3);
        return;
    }

    if (m_socketErrors.contains(QAbstractSocket::SslInternalError)
            || m_socketErrors.contains(QAbstractSocket::SslInvalidUserDataError)) {
        m_report = QString("failure during SSL initialization");
        setResult(-4);
        return;
    }

    m_report = QString("test passed, client does not accept weak protocol");
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
