/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Copyright (C) 2014 BlackBerry Limited. All rights reserved.
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


#ifndef SSLUNSAFECONTEXT_OPENSSL_P_H
#define SSLUNSAFECONTEXT_OPENSSL_P_H

//
//  W A R N I N G
//  -------------
//
// This file is not part of the Qt API.  It exists purely as an
// implementation detail.  This header file may change from version to
// version without notice, or even be removed.
//
// We mean it.
//

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include <QtCore/qvariant.h>
#include "sslunsafecertificate.h"
#include "sslunsafeconfiguration.h"
#ifdef UNSAFE
#include <openssl-unsafe/ssl.h>
#else
#include <openssl/ssl.h>
#endif

QT_BEGIN_NAMESPACE

#ifndef QT_NO_SSL

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
    static void applyBackendConfig(SslUnsafeContext *sslContext);

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

#endif // QT_NO_SSL

QT_END_NAMESPACE

#endif // SSLUNSAFECONTEXT_OPENSSL_P_H
