/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
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


#ifndef SSLUNSAFEKEY_OPENSSL_P_H
#define SSLUNSAFEKEY_OPENSSL_P_H

//
//  W A R N I N G
//  -------------
//
// This file is not part of the Qt API.  It exists for the convenience
// of SslUnsafecertificate.cpp.  This header file may change from version to version
// without notice, or even be removed.
//
// We mean it.
//

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "sslunsafekey.h"
#include "sslunsafesocket_p.h" // includes wincrypt.h

#ifndef QT_NO_OPENSSL
#ifdef UNSAFE
#include <openssl-unsafe/rsa.h>
#include <openssl-unsafe/dsa.h>
#else
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#endif
#endif

QT_BEGIN_NAMESPACE

class SslUnsafeKeyPrivate
{
public:
    inline SslUnsafeKeyPrivate()
        : algorithm(SslUnsafe::Opaque)
        , opaque(0)
    {
        clear(false);
    }

    inline ~SslUnsafeKeyPrivate()
    { clear(); }

    void clear(bool deep = true);

#ifndef QT_NO_OPENSSL
    bool fromEVP_PKEY(EVP_PKEY *pkey);
#endif
    void decodeDer(const QByteArray &der, bool deepClear = true);
    void decodePem(const QByteArray &pem, const QByteArray &passPhrase,
                   bool deepClear = true);
    QByteArray pemHeader() const;
    QByteArray pemFooter() const;
    QByteArray pemFromDer(const QByteArray &der, const QMap<QByteArray, QByteArray> &headers) const;
    QByteArray derFromPem(const QByteArray &pem, QMap<QByteArray, QByteArray> *headers) const;

    int length() const;
    QByteArray toPem(const QByteArray &passPhrase) const;
    Qt::HANDLE handle() const;

    bool isNull;
    SslUnsafe::KeyType type;
    SslUnsafe::KeyAlgorithm algorithm;

    enum Cipher {
        DesCbc,
        DesEde3Cbc,
        Rc2Cbc
    };

    Q_AUTOTEST_EXPORT static QByteArray decrypt(Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv);
    Q_AUTOTEST_EXPORT static QByteArray encrypt(Cipher cipher, const QByteArray &data, const QByteArray &key, const QByteArray &iv);

#ifndef QT_NO_OPENSSL
    union {
        EVP_PKEY *opaque;
        RSA *rsa;
        DSA *dsa;
#ifndef OPENSSL_NO_EC
        EC_KEY *ec;
#endif
    };
#else
    Qt::HANDLE opaque;
    QByteArray derData;
    int keyLength;
#endif

    QAtomicInt ref;

private:
    Q_DISABLE_COPY(SslUnsafeKeyPrivate)
};

QT_END_NAMESPACE

#endif // SslUnsafeKey_OPENSSL_P_H
