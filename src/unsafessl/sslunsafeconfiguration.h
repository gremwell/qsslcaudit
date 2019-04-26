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

/****************************************************************************
**
** In addition, as a special exception, the copyright holders listed above give
** permission to link the code of its release of Qt with the OpenSSL project's
** "OpenSSL" library (or modified versions of the "OpenSSL" library that use the
** same license as the original version), and distribute the linked executables.
**
** You must comply with the GNU General Public License version 2 in all
** respects for all of the code used other than the "OpenSSL" code.  If you
** modify this file, you may extend this exception to your version of the file,
** but you are not obligated to do so.  If you do not wish to do so, delete
** this exception statement from your version of this file.
**
****************************************************************************/

#ifndef SSLUNSAFECONFIGURATION_H
#define SSLUNSAFECONFIGURATION_H

#include "sslunsafenetworkglobal.h"
#include <QtCore/qmap.h>
#include <QtCore/qshareddata.h>
#include "sslunsafesocket.h"
#include "sslunsafe.h"

#ifndef QT_NO_SSL

QT_BEGIN_NAMESPACE

template<typename T> class QList;
class SslUnsafeCertificate;
class SslUnsafeCipher;
class SslUnsafeKey;
class SslUnsafeEllipticCurve;
class SslUnsafeDiffieHellmanParameters;

namespace dtlsopenssl
{
class SslUnsafeDtlsState;
}

class SslUnsafeConfigurationPrivate;
class Q_NETWORK_EXPORT SslUnsafeConfiguration
{
public:
    SslUnsafeConfiguration();
    SslUnsafeConfiguration(const SslUnsafeConfiguration &other);
    ~SslUnsafeConfiguration();
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeConfiguration &operator=(SslUnsafeConfiguration &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeConfiguration &operator=(const SslUnsafeConfiguration &other);

    void swap(SslUnsafeConfiguration &other) Q_DECL_NOTHROW
    { qSwap(d, other.d); }

    bool operator==(const SslUnsafeConfiguration &other) const;
    inline bool operator!=(const SslUnsafeConfiguration &other) const
    { return !(*this == other); }

    bool isNull() const;

    SslUnsafe::SslProtocol protocol() const;
    void setProtocol(SslUnsafe::SslProtocol protocol);

    // Verification
    SslUnsafeSocket::PeerVerifyMode peerVerifyMode() const;
    void setPeerVerifyMode(SslUnsafeSocket::PeerVerifyMode mode);

    int peerVerifyDepth() const;
    void setPeerVerifyDepth(int depth);

    // Certificate & cipher configuration
    QList<SslUnsafeCertificate> localCertificateChain() const;
    void setLocalCertificateChain(const QList<SslUnsafeCertificate> &localChain);

    SslUnsafeCertificate localCertificate() const;
    void setLocalCertificate(const SslUnsafeCertificate &certificate);

    SslUnsafeCertificate peerCertificate() const;
    QList<SslUnsafeCertificate> peerCertificateChain() const;
    SslUnsafeCipher sessionCipher() const;
    SslUnsafe::SslProtocol sessionProtocol() const;

    // Private keys, for server sockets
    SslUnsafeKey privateKey() const;
    void setPrivateKey(const SslUnsafeKey &key);

    // Cipher settings
    QList<SslUnsafeCipher> ciphers() const;
    void setCiphers(const QList<SslUnsafeCipher> &ciphers);
    static QList<SslUnsafeCipher> supportedCiphers();

    // Certificate Authority (CA) settings
    QList<SslUnsafeCertificate> caCertificates() const;
    void setCaCertificates(const QList<SslUnsafeCertificate> &certificates);
    static QList<SslUnsafeCertificate> systemCaCertificates();

    void setSslOption(SslUnsafe::SslOption option, bool on);
    bool testSslOption(SslUnsafe::SslOption option) const;

    QByteArray sessionTicket() const;
    void setSessionTicket(const QByteArray &sessionTicket);
    int sessionTicketLifeTimeHint() const;

    SslUnsafeKey ephemeralServerKey() const;

    // EC settings
    QVector<SslUnsafeEllipticCurve> ellipticCurves() const;
    void setEllipticCurves(const QVector<SslUnsafeEllipticCurve> &curves);
    static QVector<SslUnsafeEllipticCurve> supportedEllipticCurves();

    QByteArray preSharedKeyIdentityHint() const;
    void setPreSharedKeyIdentityHint(const QByteArray &hint);

    SslUnsafeDiffieHellmanParameters diffieHellmanParameters() const;
    void setDiffieHellmanParameters(const SslUnsafeDiffieHellmanParameters &dhparams);

    QMap<QByteArray, QVariant> backendConfiguration() const;
    void setBackendConfigurationOption(const QByteArray &name, const QVariant &value);
    void setBackendConfiguration(const QMap<QByteArray, QVariant> &backendConfiguration = QMap<QByteArray, QVariant>());

    static SslUnsafeConfiguration defaultConfiguration();
    static void setDefaultConfiguration(const SslUnsafeConfiguration &configuration);

#if QT_CONFIG(dtls) || defined(Q_CLANG_QDOC)
    bool dtlsCookieVerificationEnabled() const;
    void setDtlsCookieVerificationEnabled(bool enable);

    static SslUnsafeConfiguration defaultDtlsConfiguration();
    static void setDefaultDtlsConfiguration(const SslUnsafeConfiguration &configuration);
#endif // dtls

    enum NextProtocolNegotiationStatus {
        NextProtocolNegotiationNone,
        NextProtocolNegotiationNegotiated,
        NextProtocolNegotiationUnsupported
    };

#if QT_VERSION >= QT_VERSION_CHECK(6,0,0)
    void setAllowedNextProtocols(const QList<QByteArray> &protocols);
#else
    void setAllowedNextProtocols(QList<QByteArray> protocols);
#endif
    QList<QByteArray> allowedNextProtocols() const;

    QByteArray nextNegotiatedProtocol() const;
    NextProtocolNegotiationStatus nextProtocolNegotiationStatus() const;

    static const char ALPNProtocolHTTP2[];
    static const char NextProtocolSpdy3_0[];
    static const char NextProtocolHttp1_1[];

private:
    friend class SslUnsafeSocket;
    friend class SslUnsafeConfigurationPrivate;
    friend class SslUnsafeSocketBackendPrivate;
    friend class SslUnsafeContext;
    friend class SslUnsafeDtlsBasePrivate;
    friend class dtlsopenssl::SslUnsafeDtlsState;
    SslUnsafeConfiguration(SslUnsafeConfigurationPrivate *dd);
    QSharedDataPointer<SslUnsafeConfigurationPrivate> d;
};

Q_DECLARE_SHARED(SslUnsafeConfiguration)

QT_END_NAMESPACE

Q_DECLARE_METATYPE(SslUnsafeConfiguration)

#endif  // QT_NO_SSL

#endif
