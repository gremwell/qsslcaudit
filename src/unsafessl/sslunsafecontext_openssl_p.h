
#ifndef SSLUNSAFECONTEXT_OPENSSL_P_H
#define SSLUNSAFECONTEXT_OPENSSL_P_H

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include <QtCore/qvariant.h>
#include <QtNetwork/qsslcertificate.h>
#include "sslunsafeconfiguration.h"
#include "sslunsafeerror.h"
#include <openssl/ssl.h>

class SslUnsafeContextPrivate;

class SslUnsafeContext
{
public:

    ~SslUnsafeContext();

    static SslUnsafeContext* fromConfiguration(SslUnsafeSocket::SslMode mode, const SslUnsafeConfiguration &configuration,
                                          bool allowRootCertOnDemandLoading);
    static QSharedPointer<SslUnsafeContext> sharedFromConfiguration(SslUnsafeSocket::SslMode mode, const SslUnsafeConfiguration &configuration,
                                                               bool allowRootCertOnDemandLoading);

    SslUnsafeError::SslError error() const;
    QString errorString() const;

    SSL* createSsl();
    bool cacheSession(SSL*); // should be called when handshake completed

    QByteArray sessionASN1() const;
    void setSessionASN1(const QByteArray &sessionASN1);
    int sessionTicketLifeTimeHint() const;

#if OPENSSL_VERSION_NUMBER >= 0x1000100fL && !defined(OPENSSL_NO_NEXTPROTONEG)
    // must be public because we want to use it from an OpenSSL callback
    struct NPNContext {
        NPNContext() : data(0),
            len(0),
            status(SslUnsafeConfiguration::NextProtocolNegotiationNone)
        { }
        unsigned char *data;
        unsigned short len;
        SslUnsafeConfiguration::NextProtocolNegotiationStatus status;
    };
    NPNContext npnContext() const;
#endif // OPENSSL_VERSION_NUMBER >= 0x1000100fL ...

protected:
    SslUnsafeContext();
    friend class QSharedPointer<SslUnsafeContext>;

private:
    static void initSslContext(SslUnsafeContext* sslContext, SslUnsafeSocket::SslMode mode, const SslUnsafeConfiguration &configuration,
                               bool allowRootCertOnDemandLoading);

private:
    SSL_CTX* ctx;
    EVP_PKEY *pkey;
    SSL_SESSION *session;
    QByteArray m_sessionASN1;
    int m_sessionTicketLifeTimeHint;
    SslUnsafeError::SslError errorCode;
    QString errorStr;
    SslUnsafeConfiguration sslConfiguration;
#if OPENSSL_VERSION_NUMBER >= 0x1000100fL && !defined(OPENSSL_NO_NEXTPROTONEG)
    QByteArray m_supportedNPNVersions;
    NPNContext m_npnContext;
#endif // OPENSSL_VERSION_NUMBER >= 0x1000100fL ...
};

#endif // QSSLCONTEXT_OPENSSL_P_H
