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


#ifndef SSLUNSAFEKEY_H
#define SSLUNSAFEKEY_H

#include "sslunsafenetworkglobal.h"
#include <QtCore/qnamespace.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qsharedpointer.h>
#include "sslunsafe.h"

QT_BEGIN_NAMESPACE


#ifndef QT_NO_SSL

template <typename A, typename B> struct QPair;

class QIODevice;

class SslUnsafeKeyPrivate;
class Q_NETWORK_EXPORT SslUnsafeKey
{
public:
    SslUnsafeKey();
    SslUnsafeKey(const QByteArray &encoded, SslUnsafe::KeyAlgorithm algorithm,
            SslUnsafe::EncodingFormat format = SslUnsafe::Pem,
            SslUnsafe::KeyType type = SslUnsafe::PrivateKey,
            const QByteArray &passPhrase = QByteArray());
    SslUnsafeKey(QIODevice *device, SslUnsafe::KeyAlgorithm algorithm,
            SslUnsafe::EncodingFormat format = SslUnsafe::Pem,
            SslUnsafe::KeyType type = SslUnsafe::PrivateKey,
            const QByteArray &passPhrase = QByteArray());
    explicit SslUnsafeKey(Qt::HANDLE handle, SslUnsafe::KeyType type = SslUnsafe::PrivateKey);
    SslUnsafeKey(const SslUnsafeKey &other);
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeKey &operator=(SslUnsafeKey &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeKey &operator=(const SslUnsafeKey &other);
    ~SslUnsafeKey();

    void swap(SslUnsafeKey &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    bool isNull() const;
    void clear();

    int length() const;
    SslUnsafe::KeyType type() const;
    SslUnsafe::KeyAlgorithm algorithm() const;

    QByteArray toPem(const QByteArray &passPhrase = QByteArray()) const;
    QByteArray toDer(const QByteArray &passPhrase = QByteArray()) const;

    Qt::HANDLE handle() const;

    bool operator==(const SslUnsafeKey &key) const;
    inline bool operator!=(const SslUnsafeKey &key) const { return !operator==(key); }

private:
    QExplicitlySharedDataPointer<SslUnsafeKeyPrivate> d;
    friend class SslUnsafeCertificate;
    friend class SslUnsafeSocketBackendPrivate;
};

Q_DECLARE_SHARED(SslUnsafeKey)

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const SslUnsafeKey &key);
#endif

#endif // QT_NO_SSL

QT_END_NAMESPACE

#endif
