/****************************************************************************
**
** Copyright (C) 2017 The Qt Company Ltd.
** Copyright (C) 2014 BlackBerry Limited. All rights reserved.
** Copyright (C) 2014 Governikus GmbH & Co. KG.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/


#include "sslunsafesocket.h"

#include "sslunsafe_p.h"
#include "sslunsafecontext_openssl_p.h"
#include "sslunsafesocket_openssl_p.h"
#include "sslunsafesocket_openssl_symbols_p.h"

QT_BEGIN_NAMESPACE

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
        q_SSL_CTX_free(ctx);

    if (pkey)
        q_EVP_PKEY_free(pkey);

    if (session)
        q_SSL_SESSION_free(session);
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

    int proto = q_SSL_select_next_proto(out, outlen, in, inlen, ctx->data, ctx->len);
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
        qCWarning(lcSsl, "OpenSSL sent unknown NPN status");
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
    SSL* ssl = q_SSL_new(ctx);
    q_SSL_clear(ssl);

    if (!session && !sessionASN1().isEmpty()
            && !sslConfiguration.testSslOption(SslUnsafe::SslOptionDisableSessionPersistence)) {
        const unsigned char *data = reinterpret_cast<const unsigned char *>(m_sessionASN1.constData());
        session = q_d2i_SSL_SESSION(0, &data, m_sessionASN1.size()); // refcount is 1 already, set by function above
    }

    if (session) {
        // Try to resume the last session we cached
        if (!q_SSL_set_session(ssl, session)) {
            qCWarning(lcSsl, "could not set SSL session");
            q_SSL_SESSION_free(session);
            session = 0;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x1000100fL && !defined(OPENSSL_NO_NEXTPROTONEG)
    QList<QByteArray> protocols = sslConfiguration.d->nextAllowedProtocols;
    if (!protocols.isEmpty()) {
        m_supportedNPNVersions.clear();
        for (int a = 0; a < protocols.count(); ++a) {
            if (protocols.at(a).size() > 255) {
                qCWarning(lcSsl) << "TLS NPN extension" << protocols.at(a)
                                 << "is too long and will be truncated to 255 characters.";
                protocols[a] = protocols.at(a).left(255);
            }
            m_supportedNPNVersions.append(protocols.at(a).size()).append(protocols.at(a));
        }
        m_npnContext.data = reinterpret_cast<unsigned char *>(m_supportedNPNVersions.data());
        m_npnContext.len = m_supportedNPNVersions.count();
        m_npnContext.status = SslUnsafeConfiguration::NextProtocolNegotiationNone;
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        if (SslUnsafeSocket::sslLibraryVersionNumber() >= 0x10002000L) {
            // Callback's type has a parameter 'const unsigned char ** out'
            // since it was introduced in 1.0.2. Internally, OpenSSL's own code
            // (tests/examples) cast it to unsigned char * (since it's 'out').
            // We just re-use our NPN callback and cast here:
            typedef int (*alpn_callback_t) (SSL *, const unsigned char **, unsigned char *,
                                            const unsigned char *, unsigned int, void *);
            // With ALPN callback is for a server side only, for a client m_npnContext.status
            // will stay in NextProtocolNegotiationNone.
            q_SSL_CTX_set_alpn_select_cb(ctx, alpn_callback_t(next_proto_cb), &m_npnContext);
            // Client:
            q_SSL_set_alpn_protos(ssl, m_npnContext.data, m_npnContext.len);
        }
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L ...

        // And in case our peer does not support ALPN, but supports NPN:
        q_SSL_CTX_set_next_proto_select_cb(ctx, next_proto_cb, &m_npnContext);
    }
#endif // OPENSSL_VERSION_NUMBER >= 0x1000100fL ...

    return ssl;
}

// We cache exactly one session here
bool SslUnsafeContext::cacheSession(SSL* ssl)
{
    // don't cache the same session again
    if (session && session == q_SSL_get_session(ssl))
        return true;

    // decrease refcount of currently stored session
    // (this might happen if there are several concurrent handshakes in flight)
    if (session)
        q_SSL_SESSION_free(session);

    // cache the session the caller gave us and increase reference count
    session = q_SSL_get1_session(ssl);

    if (session && !sslConfiguration.testSslOption(SslUnsafe::SslOptionDisableSessionPersistence)) {
        int sessionSize = q_i2d_SSL_SESSION(session, 0);
        if (sessionSize > 0) {
            m_sessionASN1.resize(sessionSize);
            unsigned char *data = reinterpret_cast<unsigned char *>(m_sessionASN1.data());
            if (!q_i2d_SSL_SESSION(session, &data))
                qCWarning(lcSsl, "could not store persistent version of SSL session");
            m_sessionTicketLifeTimeHint = q_SSL_SESSION_get_ticket_lifetime_hint(session);
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

QT_END_NAMESPACE
