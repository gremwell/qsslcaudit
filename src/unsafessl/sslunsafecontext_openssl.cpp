
#include "sslunsafesocket.h"
#include "sslunsafediffiehellmanparameters.h"
#include <QtCore/qmutex.h>

//#include "private/qssl_p.h"
#include "sslunsafeerror.h"
#include "sslunsafecontext_openssl_p.h"
#include "sslunsafesocket_p.h"
#include "sslunsafesocket_openssl_p.h"
#include "sslunsafesocket_openssl_symbols_p.h"
#include "sslunsafediffiehellmanparameters_p.h"

// defined in SslUnsafeSocket_openssl.cpp:
extern int uq_X509Callback(int ok, X509_STORE_CTX *ctx);
extern QString getErrorsFromOpenSsl();

SslUnsafeContext::SslUnsafeContext()
    : ctx(0),
    pkey(0),
    session(0),
    m_sessionTicketLifeTimeHint(-1)
{
}

SslUnsafeContext::~SslUnsafeContext()
{
    if (ctx)
        // This will decrement the reference count by 1 and free the context eventually when possible
        uq_SSL_CTX_free(ctx);

    if (pkey)
        uq_EVP_PKEY_free(pkey);

    if (session)
        uq_SSL_SESSION_free(session);
}

static inline QString msgErrorSettingEllipticCurves(const QString &why)
{
    return SslUnsafeSocket::tr("Error when setting the elliptic curves (%1)").arg(why);
}

// static
void SslUnsafeContext::initSslContext(SslUnsafeContext *sslContext, SslUnsafeSocket::SslMode mode, const SslUnsafeConfiguration &configuration, bool allowRootCertOnDemandLoading)
{
    sslContext->sslConfiguration = configuration;
    sslContext->errorCode = SslUnsafeError::NoError;

    bool client = (mode == SslUnsafeSocket::SslClientMode);

    bool reinitialized = false;
    bool unsupportedProtocol = false;
init_context:
    switch (sslContext->sslConfiguration.protocol()) {
    case QSsl::SslV2:
#ifndef OPENSSL_NO_SSL2
        sslContext->ctx = uq_SSL_CTX_new(client ? uq_SSLv2_client_method() : uq_SSLv2_server_method());
#else
        // SSL 2 not supported by the system, but chosen deliberately -> error
        sslContext->ctx = 0;
        unsupportedProtocol = true;
#endif
        break;
    case QSsl::SslV3:
#ifndef OPENSSL_NO_SSL3_METHOD
        sslContext->ctx = uq_SSL_CTX_new(client ? uq_SSLv3_client_method() : uq_SSLv3_server_method());
#else
        // SSL 3 not supported by the system, but chosen deliberately -> error
        sslContext->ctx = 0;
        unsupportedProtocol = true;
#endif
        break;
    case QSsl::SecureProtocols:
        // SSLv2 and SSLv3 will be disabled by SSL options
        // But we need uq_SSLv23_server_method() otherwise AnyProtocol will be unable to connect on Win32.
    case QSsl::TlsV1SslV3:
        // SSLv2 will will be disabled by SSL options
    case QSsl::AnyProtocol:
    default:
        sslContext->ctx = uq_SSL_CTX_new(client ? uq_SSLv23_client_method() : uq_SSLv23_server_method());
        break;
    case QSsl::TlsV1_0:
        sslContext->ctx = uq_SSL_CTX_new(client ? uq_TLSv1_client_method() : uq_TLSv1_server_method());
        break;
    case QSsl::TlsV1_1:
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        sslContext->ctx = uq_SSL_CTX_new(client ? uq_TLSv1_1_client_method() : uq_TLSv1_1_server_method());
#else
        // TLS 1.1 not supported by the system, but chosen deliberately -> error
        sslContext->ctx = 0;
        unsupportedProtocol = true;
#endif
        break;
    case QSsl::TlsV1_2:
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        sslContext->ctx = uq_SSL_CTX_new(client ? uq_TLSv1_2_client_method() : uq_TLSv1_2_server_method());
#else
        // TLS 1.2 not supported by the system, but chosen deliberately -> error
        sslContext->ctx = 0;
        unsupportedProtocol = true;
#endif
        break;
    case QSsl::TlsV1_0OrLater:
        // Specific protocols will be specified via SSL options.
        sslContext->ctx = uq_SSL_CTX_new(client ? uq_SSLv23_client_method() : uq_SSLv23_server_method());
        break;
    case QSsl::TlsV1_1OrLater:
    case QSsl::TlsV1_2OrLater:
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        // Specific protocols will be specified via SSL options.
        sslContext->ctx = uq_SSL_CTX_new(client ? uq_SSLv23_client_method() : uq_SSLv23_server_method());
#else
        // TLS 1.1/1.2 not supported by the system, but chosen deliberately -> error
        sslContext->ctx = 0;
        unsupportedProtocol = true;
#endif
        break;
    }

    if (!sslContext->ctx) {
        // After stopping Flash 10 the SSL library looses its ciphers. Try re-adding them
        // by re-initializing the library.
        if (!reinitialized) {
            reinitialized = true;
            if (uq_SSL_library_init() == 1)
                goto init_context;
        }

        sslContext->errorStr = SslUnsafeSocket::tr("Error creating SSL context (%1)").arg(
            unsupportedProtocol ? SslUnsafeSocket::tr("unsupported protocol") : SslUnsafeSocketBackendPrivate::getErrorsFromOpenSsl()
        );
        sslContext->errorCode = SslUnsafeError::UnspecifiedError;
        return;
    }

    // Enable bug workarounds.
    long options = SslUnsafeSocketBackendPrivate::setupOpenSslOptions(configuration.protocol(), configuration.d->sslOptions);
    uq_SSL_CTX_set_options(sslContext->ctx, options);

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    // Tell OpenSSL to release memory early
    // http://www.openssl.org/docs/ssl/SSL_CTX_set_mode.html
    if (uq_SSLeay() >= 0x10000000L)
        uq_SSL_CTX_set_mode(sslContext->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

    // Initialize ciphers
    QByteArray cipherString;
    bool first = true;
    QList<SslUnsafeCipher> ciphers = sslContext->sslConfiguration.ciphers();
    if (ciphers.isEmpty())
        ciphers = SslUnsafeSocketPrivate::defaultCiphers();
    for (const SslUnsafeCipher &cipher : const_cast<const QList<SslUnsafeCipher>&>(ciphers)) { // qAsConst(ciphers)) {
        if (first)
            first = false;
        else
            cipherString.append(':');
        cipherString.append(cipher.name().toLatin1());
    }

    if (!uq_SSL_CTX_set_cipher_list(sslContext->ctx, cipherString.data())) {
        sslContext->errorStr = SslUnsafeSocket::tr("Invalid or empty cipher list (%1)").arg(SslUnsafeSocketBackendPrivate::getErrorsFromOpenSsl());
        sslContext->errorCode = SslUnsafeError::UnspecifiedError;
        return;
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();

    // Add all our CAs to this store.
    const auto caCertificates = sslContext->sslConfiguration.caCertificates();
    for (const SslUnsafeCertificate &caCertificate : caCertificates) {
        // From https://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html:
        //
        // If several CA certificates matching the name, key identifier, and
        // serial number condition are available, only the first one will be
        // examined. This may lead to unexpected results if the same CA
        // certificate is available with different expiration dates. If a
        // ``certificate expired'' verification error occurs, no other
        // certificate will be searched. Make sure to not have expired
        // certificates mixed with valid ones.
        //
        // See also: SslUnsafeSocketBackendPrivate::verify()
        if (caCertificate.expiryDate() >= now) {
            uq_X509_STORE_add_cert(uq_SSL_CTX_get_cert_store(sslContext->ctx), (X509 *)caCertificate.handle());
        }
    }

    if (SslUnsafeSocketPrivate::s_loadRootCertsOnDemand && allowRootCertOnDemandLoading) {
        // tell OpenSSL the directories where to look up the root certs on demand
        const QList<QByteArray> unixDirs = SslUnsafeSocketPrivate::unixRootCertDirectories();
        for (const QByteArray &unixDir : unixDirs)
            uq_SSL_CTX_load_verify_locations(sslContext->ctx, 0, unixDir.constData());
    }

    if (!sslContext->sslConfiguration.localCertificate().isNull()) {
        // Require a private key as well.
        if (sslContext->sslConfiguration.privateKey().isNull()) {
            sslContext->errorStr = SslUnsafeSocket::tr("Cannot provide a certificate with no key, %1").arg(SslUnsafeSocketBackendPrivate::getErrorsFromOpenSsl());
            sslContext->errorCode = SslUnsafeError::UnspecifiedError;
            return;
        }

        // Load certificate
        if (!uq_SSL_CTX_use_certificate(sslContext->ctx, (X509 *)sslContext->sslConfiguration.localCertificate().handle())) {
            sslContext->errorStr = SslUnsafeSocket::tr("Error loading local certificate, %1").arg(SslUnsafeSocketBackendPrivate::getErrorsFromOpenSsl());
            sslContext->errorCode = SslUnsafeError::UnspecifiedError;
            return;
        }

        if (configuration.d->privateKey.algorithm() == QSsl::Opaque) {
            sslContext->pkey = reinterpret_cast<EVP_PKEY *>(configuration.d->privateKey.handle());
        } else {
            // Load private key
            sslContext->pkey = uq_EVP_PKEY_new();
            // before we were using EVP_PKEY_assign_R* functions and did not use EVP_PKEY_free.
            // this lead to a memory leak. Now we use the *_set1_* functions which do not
            // take ownership of the RSA/DSA key instance because the QSslKey already has ownership.
            if (configuration.d->privateKey.algorithm() == QSsl::Rsa)
                uq_EVP_PKEY_set1_RSA(sslContext->pkey, reinterpret_cast<RSA *>(configuration.d->privateKey.handle()));
            else if (configuration.d->privateKey.algorithm() == QSsl::Dsa)
                uq_EVP_PKEY_set1_DSA(sslContext->pkey, reinterpret_cast<DSA *>(configuration.d->privateKey.handle()));
#ifndef OPENSSL_NO_EC
            else if (configuration.d->privateKey.algorithm() == QSsl::Ec)
                uq_EVP_PKEY_set1_EC_KEY(sslContext->pkey, reinterpret_cast<EC_KEY *>(configuration.d->privateKey.handle()));
#endif
        }

        if (!uq_SSL_CTX_use_PrivateKey(sslContext->ctx, sslContext->pkey)) {
            sslContext->errorStr = SslUnsafeSocket::tr("Error loading private key, %1").arg(SslUnsafeSocketBackendPrivate::getErrorsFromOpenSsl());
            sslContext->errorCode = SslUnsafeError::UnspecifiedError;
            return;
        }
        if (configuration.d->privateKey.algorithm() == QSsl::Opaque)
            sslContext->pkey = 0; // Don't free the private key, it belongs to QSslKey

        // Check if the certificate matches the private key.
        if (!uq_SSL_CTX_check_private_key(sslContext->ctx)) {
            sslContext->errorStr = SslUnsafeSocket::tr("Private key does not certify public key, %1").arg(SslUnsafeSocketBackendPrivate::getErrorsFromOpenSsl());
            sslContext->errorCode = SslUnsafeError::UnspecifiedError;
            return;
        }

        // If we have any intermediate certificates then we need to add them to our chain
        bool first = true;
        for (const SslUnsafeCertificate &cert : const_cast<const QList<SslUnsafeCertificate>&>(configuration.d->localCertificateChain)) { //qAsConst(configuration.d->localCertificateChain)) {
            if (first) {
                first = false;
                continue;
            }
            uq_SSL_CTX_ctrl(sslContext->ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0,
                           uq_X509_dup(reinterpret_cast<X509 *>(cert.handle())));
        }
    }

    // Initialize peer verification.
    if (sslContext->sslConfiguration.peerVerifyMode() == SslUnsafeSocket::VerifyNone) {
        uq_SSL_CTX_set_verify(sslContext->ctx, SSL_VERIFY_NONE, 0);
    } else {
        uq_SSL_CTX_set_verify(sslContext->ctx, SSL_VERIFY_PEER, uq_X509Callback);
    }

    // Set verification depth.
    if (sslContext->sslConfiguration.peerVerifyDepth() != 0)
        uq_SSL_CTX_set_verify_depth(sslContext->ctx, sslContext->sslConfiguration.peerVerifyDepth());

    // set persisted session if the user set it
    if (!configuration.sessionTicket().isEmpty())
        sslContext->setSessionASN1(configuration.sessionTicket());

    // Set temp DH params
    SslUnsafeDiffieHellmanParameters dhparams = configuration.diffieHellmanParameters();

    if (!dhparams.isValid()) {
        sslContext->errorStr = SslUnsafeSocket::tr("Diffie-Hellman parameters are not valid");
        sslContext->errorCode = SslUnsafeError::UnspecifiedError;
        return;
    }

    if (!dhparams.isEmpty()) {
        const QByteArray &params = dhparams.d->derData;
        const char *ptr = params.constData();
        DH *dh = uq_d2i_DHparams(NULL, reinterpret_cast<const unsigned char **>(&ptr), params.length());
        if (dh == NULL)
            qFatal("q_d2i_DHparams failed to convert QSslDiffieHellmanParameters to DER form");
        uq_SSL_CTX_set_tmp_dh(sslContext->ctx, dh);
        uq_DH_free(dh);
    }

    // we need 512-bits ephemeral RSA key in case we use some insecure ciphers
    // see NOTES on https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_cipher_list.html
    // here we do it always, which is not optimal and insecure. well, we are in 'unsafe' mode anyway.
    {
        BIGNUM *bn = uq_BN_new();
        RSA *rsa = uq_RSA_new();
        uq_BN_set_word(bn, RSA_F4);
        uq_RSA_generate_key_ex(rsa, 512, bn, NULL);
        uq_SSL_CTX_set_tmp_rsa(sslContext->ctx, rsa);
        uq_RSA_free(rsa);
        uq_BN_free(bn);
    }

#ifndef OPENSSL_NO_EC
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (uq_SSLeay() >= 0x10002000L) {
        uq_SSL_CTX_ctrl(sslContext->ctx, SSL_CTRL_SET_ECDH_AUTO, 1, NULL);
    } else
#endif
    {
        // Set temp ECDH params
        EC_KEY *ecdh = 0;
        ecdh = uq_EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        uq_SSL_CTX_set_tmp_ecdh(sslContext->ctx, ecdh);
        uq_EC_KEY_free(ecdh);
    }
#endif // OPENSSL_NO_EC

#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
    if (!client)
        uq_SSL_CTX_use_psk_identity_hint(sslContext->ctx, sslContext->sslConfiguration.preSharedKeyIdentityHint().constData());
#endif // OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)

    const QVector<SslUnsafeEllipticCurve> qcurves = sslContext->sslConfiguration.ellipticCurves();
    if (!qcurves.isEmpty()) {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined(OPENSSL_NO_EC)
        // Set the curves to be used
        if (uq_SSLeay() >= 0x10002000L) {
            // SSL_CTX_ctrl wants a non-const pointer as last argument,
            // but let's avoid a copy into a temporary array
            if (!uq_SSL_CTX_ctrl(sslContext->ctx,
                                SSL_CTRL_SET_CURVES,
                                qcurves.size(),
                                const_cast<int *>(reinterpret_cast<const int *>(qcurves.data())))) {
                sslContext->errorStr = msgErrorSettingEllipticCurves(SslUnsafeSocketBackendPrivate::getErrorsFromOpenSsl());
                sslContext->errorCode = SslUnsafeError::UnspecifiedError;
            }
        } else
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined(OPENSSL_NO_EC)
        {
            // specific curves requested, but not possible to set -> error
            sslContext->errorStr = msgErrorSettingEllipticCurves(SslUnsafeSocket::tr("OpenSSL version too old, need at least v1.0.2"));
            sslContext->errorCode = SslUnsafeError::UnspecifiedError;
        }
    }
}

SslUnsafeContext* SslUnsafeContext::fromConfiguration(SslUnsafeSocket::SslMode mode, const SslUnsafeConfiguration &configuration, bool allowRootCertOnDemandLoading)
{
    SslUnsafeContext *sslContext = new SslUnsafeContext();
    initSslContext(sslContext, mode, configuration, allowRootCertOnDemandLoading);
    return sslContext;
}

QSharedPointer<SslUnsafeContext> SslUnsafeContext::sharedFromConfiguration(SslUnsafeSocket::SslMode mode, const SslUnsafeConfiguration &configuration, bool allowRootCertOnDemandLoading)
{
    QSharedPointer<SslUnsafeContext> sslContext = QSharedPointer<SslUnsafeContext>::create();
    initSslContext(sslContext.data(), mode, configuration, allowRootCertOnDemandLoading);
    return sslContext;
}

#if OPENSSL_VERSION_NUMBER >= 0x1000100fL && !defined(OPENSSL_NO_NEXTPROTONEG)

static int next_proto_cb(SSL *, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen, void *arg)
{
    SslUnsafeContext::NPNContext *ctx = reinterpret_cast<SslUnsafeContext::NPNContext *>(arg);

    // comment out to debug:
//    QList<QByteArray> supportedVersions;
//    for (unsigned int i = 0; i < inlen; ) {
//        QByteArray version(reinterpret_cast<const char *>(&in[i+1]), in[i]);
//        supportedVersions << version;
//        i += in[i] + 1;
//    }

    int proto = uq_SSL_select_next_proto(out, outlen, in, inlen, ctx->data, ctx->len);
    switch (proto) {
    case OPENSSL_NPN_UNSUPPORTED:
        ctx->status = SslUnsafeConfiguration::NextProtocolNegotiationNone;
        break;
    case OPENSSL_NPN_NEGOTIATED:
        ctx->status = SslUnsafeConfiguration::NextProtocolNegotiationNegotiated;
        break;
    case OPENSSL_NPN_NO_OVERLAP:
        ctx->status = SslUnsafeConfiguration::NextProtocolNegotiationUnsupported;
        break;
    default:
        qWarning() << "OpenSSL sent unknown NPN status";
    }

    return SSL_TLSEXT_ERR_OK;
}

SslUnsafeContext::NPNContext SslUnsafeContext::npnContext() const
{
    return m_npnContext;
}
#endif // OPENSSL_VERSION_NUMBER >= 0x1000100fL ...

// Needs to be deleted by caller
SSL* SslUnsafeContext::createSsl()
{
    SSL* ssl = uq_SSL_new(ctx);
    uq_SSL_clear(ssl);

    if (!session && !sessionASN1().isEmpty()
            && !sslConfiguration.testSslOption(QSsl::SslOptionDisableSessionPersistence)) {
        const unsigned char *data = reinterpret_cast<const unsigned char *>(m_sessionASN1.constData());
        session = uq_d2i_SSL_SESSION(0, &data, m_sessionASN1.size()); // refcount is 1 already, set by function above
    }

    if (session) {
        // Try to resume the last session we cached
        if (!uq_SSL_set_session(ssl, session)) {
            qWarning() << "could not set SSL session";
            uq_SSL_SESSION_free(session);
            session = 0;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x1000100fL && !defined(OPENSSL_NO_NEXTPROTONEG)
    QList<QByteArray> protocols = sslConfiguration.d->nextAllowedProtocols;
    if (!protocols.isEmpty()) {
        m_supportedNPNVersions.clear();
        for (int a = 0; a < protocols.count(); ++a) {
            if (protocols.at(a).size() > 255) {
                qWarning() << "TLS NPN extension" << protocols.at(a)
                                 << "is too long and will be truncated to 255 characters.";
                protocols[a] = protocols.at(a).left(255);
            }
            m_supportedNPNVersions.append(protocols.at(a).size()).append(protocols.at(a));
        }
        m_npnContext.data = reinterpret_cast<unsigned char *>(m_supportedNPNVersions.data());
        m_npnContext.len = m_supportedNPNVersions.count();
        m_npnContext.status = SslUnsafeConfiguration::NextProtocolNegotiationNone;
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        if (uq_SSLeay() >= 0x10002000L) {
            // Callback's type has a parameter 'const unsigned char ** out'
            // since it was introduced in 1.0.2. Internally, OpenSSL's own code
            // (tests/examples) cast it to unsigned char * (since it's 'out').
            // We just re-use our NPN callback and cast here:
            typedef int (*alpn_callback_t) (SSL *, const unsigned char **, unsigned char *,
                                            const unsigned char *, unsigned int, void *);
            // With ALPN callback is for a server side only, for a client m_npnContext.status
            // will stay in NextProtocolNegotiationNone.
            uq_SSL_CTX_set_alpn_select_cb(ctx, alpn_callback_t(next_proto_cb), &m_npnContext);
            // Client:
            uq_SSL_set_alpn_protos(ssl, m_npnContext.data, m_npnContext.len);
        }
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L ...

        // And in case our peer does not support ALPN, but supports NPN:
        uq_SSL_CTX_set_next_proto_select_cb(ctx, next_proto_cb, &m_npnContext);
    }
#endif // OPENSSL_VERSION_NUMBER >= 0x1000100fL ...

    return ssl;
}

// We cache exactly one session here
bool SslUnsafeContext::cacheSession(SSL* ssl)
{
    // don't cache the same session again
    if (session && session == uq_SSL_get_session(ssl))
        return true;

    // decrease refcount of currently stored session
    // (this might happen if there are several concurrent handshakes in flight)
    if (session)
        uq_SSL_SESSION_free(session);

    // cache the session the caller gave us and increase reference count
    session = uq_SSL_get1_session(ssl);

    if (session && !sslConfiguration.testSslOption(QSsl::SslOptionDisableSessionPersistence)) {
        int sessionSize = uq_i2d_SSL_SESSION(session, 0);
        if (sessionSize > 0) {
            m_sessionASN1.resize(sessionSize);
            unsigned char *data = reinterpret_cast<unsigned char *>(m_sessionASN1.data());
            if (!uq_i2d_SSL_SESSION(session, &data))
                qWarning() << "could not store persistent version of SSL session";
            m_sessionTicketLifeTimeHint = session->tlsext_tick_lifetime_hint;
        }
    }

    return (session != 0);
}

QByteArray SslUnsafeContext::sessionASN1() const
{
    return m_sessionASN1;
}

void SslUnsafeContext::setSessionASN1(const QByteArray &session)
{
    m_sessionASN1 = session;
}

int SslUnsafeContext::sessionTicketLifeTimeHint() const
{
    return m_sessionTicketLifeTimeHint;
}

SslUnsafeError::SslError SslUnsafeContext::error() const
{
    return errorCode;
}

QString SslUnsafeContext::errorString() const
{
    return errorStr;
}
