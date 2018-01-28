/****************************************************************************
**
** Copyright (C) 2015 Mikkel Krautz <mikkel@krautz.dk>
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


#ifndef SSLUNSAFEDIFFIEHELLMANPARAMETERS_H
#define SSLUNSAFEDIFFIEHELLMANPARAMETERS_H

#include "sslunsafe.h"
#include <QtCore/qnamespace.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qshareddata.h>

QT_BEGIN_NAMESPACE

#ifndef QT_NO_SSL

class QIODevice;
class SslUnsafeContext;
class SslUnsafeDiffieHellmanParametersPrivate;

class SslUnsafeDiffieHellmanParameters;
// qHash is a friend, but we can't use default arguments for friends (§8.3.6.4)
Q_NETWORK_EXPORT uint qHash(const SslUnsafeDiffieHellmanParameters &dhparam, uint seed = 0) Q_DECL_NOTHROW;

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const SslUnsafeDiffieHellmanParameters &dhparams);
#endif

Q_NETWORK_EXPORT bool operator==(const SslUnsafeDiffieHellmanParameters &lhs, const SslUnsafeDiffieHellmanParameters &rhs) Q_DECL_NOTHROW;

inline bool operator!=(const SslUnsafeDiffieHellmanParameters &lhs, const SslUnsafeDiffieHellmanParameters &rhs) Q_DECL_NOTHROW
{
    return !operator==(lhs, rhs);
}

class SslUnsafeDiffieHellmanParameters
{
public:
    enum Error {
        NoError,
        InvalidInputDataError,
        UnsafeParametersError
    };

    Q_NETWORK_EXPORT static SslUnsafeDiffieHellmanParameters defaultParameters();

    Q_NETWORK_EXPORT SslUnsafeDiffieHellmanParameters();
    Q_NETWORK_EXPORT SslUnsafeDiffieHellmanParameters(const SslUnsafeDiffieHellmanParameters &other);
    SslUnsafeDiffieHellmanParameters(SslUnsafeDiffieHellmanParameters &&other) Q_DECL_NOTHROW : d(other.d) { other.d = nullptr; }
    Q_NETWORK_EXPORT ~SslUnsafeDiffieHellmanParameters();

    Q_NETWORK_EXPORT SslUnsafeDiffieHellmanParameters &operator=(const SslUnsafeDiffieHellmanParameters &other);
    SslUnsafeDiffieHellmanParameters &operator=(SslUnsafeDiffieHellmanParameters &&other) Q_DECL_NOTHROW { swap(other); return *this; }

    void swap(SslUnsafeDiffieHellmanParameters &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    Q_NETWORK_EXPORT static SslUnsafeDiffieHellmanParameters fromEncoded(const QByteArray &encoded, SslUnsafe::EncodingFormat format = SslUnsafe::Pem);
    Q_NETWORK_EXPORT static SslUnsafeDiffieHellmanParameters fromEncoded(QIODevice *device, SslUnsafe::EncodingFormat format = SslUnsafe::Pem);

    Q_NETWORK_EXPORT bool isEmpty() const Q_DECL_NOTHROW;
    Q_NETWORK_EXPORT bool isValid() const Q_DECL_NOTHROW;
    Q_NETWORK_EXPORT Error error() const Q_DECL_NOTHROW;
    Q_NETWORK_EXPORT QString errorString() const Q_DECL_NOTHROW;

private:
    SslUnsafeDiffieHellmanParametersPrivate *d;
    friend class SslUnsafeContext;
    friend Q_NETWORK_EXPORT bool operator==(const SslUnsafeDiffieHellmanParameters &lhs, const SslUnsafeDiffieHellmanParameters &rhs) Q_DECL_NOTHROW;
#ifndef QT_NO_DEBUG_STREAM
    friend Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const SslUnsafeDiffieHellmanParameters &dhparam);
#endif
    friend Q_NETWORK_EXPORT uint qHash(const SslUnsafeDiffieHellmanParameters &dhparam, uint seed) Q_DECL_NOTHROW;
};

Q_DECLARE_SHARED(SslUnsafeDiffieHellmanParameters)

#endif // QT_NO_SSL

QT_END_NAMESPACE

#endif
