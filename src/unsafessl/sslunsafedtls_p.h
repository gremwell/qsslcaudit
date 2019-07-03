/****************************************************************************
**
** Copyright (C) 2017 The Qt Company Ltd.
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

#ifndef SSLUNSAFEDTLS_P_H
#define SSLUNSAFEDTLS_P_H

//#include <private/qtnetworkglobal_p.h>

#include "sslunsafedtls.h"

#include "sslunsafeconfiguration_p.h"
//#include <private/qobject_p.h>

#include <QtNetwork/qabstractsocket.h>
#include <QtNetwork/qhostaddress.h>
#include "sslunsafesocket.h"
#include "sslunsafecipher.h"
#include "sslunsafe.h"

#include <QtCore/qcryptographichash.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qstring.h>

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

//QT_REQUIRE_CONFIG(dtls);

QT_BEGIN_NAMESPACE

class QHostAddress;

class SslUnsafeDtlsBasePrivate : public QObjectData, public QObject
{
    Q_DECLARE_PUBLIC(SslUnsafeDtls)
public:

    void setDtlsError(SslUnsafeDtlsError code, const QString &description)
    {
        errorCode = code;
        errorDescription = description;
    }

    void clearDtlsError()
    {
        errorCode = SslUnsafeDtlsError::NoError;
        errorDescription.clear();
    }

    void setConfiguration(const SslUnsafeConfiguration &configuration);
    SslUnsafeConfiguration configuration() const;

    bool setCookieGeneratorParameters(QCryptographicHash::Algorithm alg,
                                      const QByteArray &secret);

    static bool isDtlsProtocol(SslUnsafe::SslProtocol protocol);

    QHostAddress remoteAddress;
    quint16 remotePort = 0;
    quint16 mtuHint = 0;

    SslUnsafeDtlsError errorCode = SslUnsafeDtlsError::NoError;
    QString errorDescription;
    SslUnsafeConfigurationPrivate dtlsConfiguration;
    SslUnsafeSocket::SslMode mode = SslUnsafeSocket::SslClientMode;
    SslUnsafeCipher sessionCipher;
    SslUnsafe::SslProtocol sessionProtocol = SslUnsafe::UnknownProtocol;
    QString peerVerificationName;
    QByteArray secret;

    QByteArray rawWrittenData;

#ifdef QT_CRYPTOGRAPHICHASH_ONLY_SHA1
    QCryptographicHash::Algorithm hashAlgorithm = QCryptographicHash::Sha1;
#else
    QCryptographicHash::Algorithm hashAlgorithm = QCryptographicHash::Sha256;
#endif
};

class SslUnsafeDtlsClientVerifierPrivate : public SslUnsafeDtlsBasePrivate
{
public:

    QByteArray verifiedClientHello;

    virtual bool verifyClient(QUdpSocket *socket, const QByteArray &dgram,
                              const QHostAddress &address, quint16 port) = 0;
};

class SslUnsafeDtlsPrivate : public SslUnsafeDtlsBasePrivate
{
public:

    virtual bool startHandshake(QUdpSocket *socket, const QByteArray &dgram) = 0;
    virtual bool handleTimeout(QUdpSocket *socket) = 0;
    virtual bool continueHandshake(QUdpSocket *socket, const QByteArray &dgram) = 0;
    virtual bool resumeHandshake(QUdpSocket *socket) = 0;
    virtual void abortHandshake(QUdpSocket *socket) = 0;
    virtual void sendShutdownAlert(QUdpSocket *socket) = 0;

    virtual qint64 writeDatagramEncrypted(QUdpSocket *socket, const QByteArray &dgram) = 0;
    virtual QByteArray decryptDatagram(QUdpSocket *socket, const QByteArray &dgram) = 0;

    SslUnsafeDtls::HandshakeState handshakeState = SslUnsafeDtls::HandshakeNotStarted;

    QVector<SslUnsafeError> tlsErrors;
    QVector<SslUnsafeError> tlsErrorsToIgnore;

    bool connectionEncrypted = false;
};

QT_END_NAMESPACE

#endif // SSLUNSAFEDTLS_P_H
