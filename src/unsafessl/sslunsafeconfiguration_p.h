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

#ifndef SSLUNSAFECONFIGURATION_P_H
#define SSLUNSAFECONFIGURATION_P_H

//
//  W A R N I N G
//  -------------
//
// This file is not part of the Qt API.  It exists for the convenience
// of the SslUnsafeSocket API.  This header file may change from
// version to version without notice, or even be removed.
//
// We mean it.
//

#include <QtCore/qmap.h>
//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "sslunsafeconfiguration.h"
#include "qlist.h"
#include "sslunsafecertificate.h"
#include "sslunsafecipher.h"
#include "sslunsafekey.h"
#include "sslunsafeellipticcurve.h"
#include "sslunsafediffiehellmanparameters.h"

QT_BEGIN_NAMESPACE

class SslUnsafeConfigurationPrivate: public QSharedData
{
public:
    SslUnsafeConfigurationPrivate()
        : sessionProtocol(SslUnsafe::UnknownProtocol),
          protocol(SslUnsafe::SecureProtocols),
          peerVerifyMode(SslUnsafeSocket::AutoVerifyPeer),
          peerVerifyDepth(0),
          allowRootCertOnDemandLoading(true),
          peerSessionShared(false),
          sslOptions(SslUnsafeConfigurationPrivate::defaultSslOptions),
          dhParams(SslUnsafeDiffieHellmanParameters::defaultParameters()),
          sslSessionTicketLifeTimeHint(-1),
          ephemeralServerKey(),
          preSharedKeyIdentityHint(),
          nextProtocolNegotiationStatus(SslUnsafeConfiguration::NextProtocolNegotiationNone)
    { }

    SslUnsafeCertificate peerCertificate;
    QList<SslUnsafeCertificate> peerCertificateChain;

    QList<SslUnsafeCertificate> localCertificateChain;

    SslUnsafeKey privateKey;
    SslUnsafeCipher sessionCipher;
    SslUnsafe::SslProtocol sessionProtocol;
    QList<SslUnsafeCipher> ciphers;
    QList<SslUnsafeCertificate> caCertificates;

    SslUnsafe::SslProtocol protocol;
    SslUnsafeSocket::PeerVerifyMode peerVerifyMode;
    int peerVerifyDepth;
    bool allowRootCertOnDemandLoading;
    bool peerSessionShared;

    Q_AUTOTEST_EXPORT static bool peerSessionWasShared(const SslUnsafeConfiguration &configuration);

    SslUnsafe::SslOptions sslOptions;

    Q_AUTOTEST_EXPORT static const SslUnsafe::SslOptions defaultSslOptions;

    QVector<SslUnsafeEllipticCurve> ellipticCurves;

    SslUnsafeDiffieHellmanParameters dhParams;

    QMap<QByteArray, QVariant> backendConfig;

    QByteArray sslSession;
    int sslSessionTicketLifeTimeHint;

    SslUnsafeKey ephemeralServerKey;

    QByteArray preSharedKeyIdentityHint;

    QList<QByteArray> nextAllowedProtocols;
    QByteArray nextNegotiatedProtocol;
    SslUnsafeConfiguration::NextProtocolNegotiationStatus nextProtocolNegotiationStatus;

#if 1 // QT_CONFIG(dtls)
    bool dtlsCookieEnabled = true;
#else
    const bool dtlsCookieEnabled = false;
#endif // dtls

    // in qsslsocket.cpp:
    static SslUnsafeConfiguration defaultConfiguration();
    static void setDefaultConfiguration(const SslUnsafeConfiguration &configuration);
    static void deepCopyDefaultConfiguration(SslUnsafeConfigurationPrivate *config);

    static SslUnsafeConfiguration defaultDtlsConfiguration();
    static void setDefaultDtlsConfiguration(const SslUnsafeConfiguration &configuration);
};

// implemented here for inlining purposes
inline SslUnsafeConfiguration::SslUnsafeConfiguration(SslUnsafeConfigurationPrivate *dd)
    : d(dd)
{
}

QT_END_NAMESPACE

#endif
