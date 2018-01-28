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


#ifndef SSLUNSAFECIPHER_H
#define SSLUNSAFECIPHER_H

#include "sslunsafenetworkglobal.h"
#include <QtCore/qstring.h>
#include <QtCore/qscopedpointer.h>
#include "sslunsafe.h"

QT_BEGIN_NAMESPACE


#ifndef QT_NO_SSL

class SslUnsafeCipherPrivate;
class Q_NETWORK_EXPORT SslUnsafeCipher
{
public:
    SslUnsafeCipher();
    explicit SslUnsafeCipher(const QString &name);
    SslUnsafeCipher(const QString &name, SslUnsafe::SslProtocol protocol);
    SslUnsafeCipher(const SslUnsafeCipher &other);
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeCipher &operator=(SslUnsafeCipher &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeCipher &operator=(const SslUnsafeCipher &other);
    ~SslUnsafeCipher();

    void swap(SslUnsafeCipher &other) Q_DECL_NOTHROW
    { qSwap(d, other.d); }

    bool operator==(const SslUnsafeCipher &other) const;
    inline bool operator!=(const SslUnsafeCipher &other) const { return !operator==(other); }

    bool isNull() const;
    QString name() const;
    int supportedBits() const;
    int usedBits() const;

    QString keyExchangeMethod() const;
    QString authenticationMethod() const;
    QString encryptionMethod() const;
    QString protocolString() const;
    SslUnsafe::SslProtocol protocol() const;

private:
    QScopedPointer<SslUnsafeCipherPrivate> d;
    friend class SslUnsafeSocketBackendPrivate;
};

Q_DECLARE_SHARED(SslUnsafeCipher)

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const SslUnsafeCipher &cipher);
#endif

#endif // QT_NO_SSL

QT_END_NAMESPACE

#endif

