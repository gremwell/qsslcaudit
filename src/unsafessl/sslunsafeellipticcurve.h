/****************************************************************************
**
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

#ifndef SSLUNSAFEELLIPTICCURVE_H
#define SSLUNSAFEELLIPTICCURVE_H

#include "sslunsafenetworkglobal.h"
#include <QtCore/QString>
#include <QtCore/QMetaType>
#if QT_DEPRECATED_SINCE(5, 6)
#include <QtCore/QHash>
#endif
//#include <QtCore/qhashfunctions.h>

QT_BEGIN_NAMESPACE

class SslUnsafeEllipticCurve;
// qHash is a friend, but we can't use default arguments for friends (§8.3.6.4)
Q_DECL_CONSTEXPR uint qHash(SslUnsafeEllipticCurve curve, uint seed = 0) Q_DECL_NOTHROW;

class SslUnsafeEllipticCurve {
public:
    Q_DECL_CONSTEXPR SslUnsafeEllipticCurve() Q_DECL_NOTHROW
        : id(0)
    {
    }

    Q_NETWORK_EXPORT static SslUnsafeEllipticCurve fromShortName(const QString &name);
    Q_NETWORK_EXPORT static SslUnsafeEllipticCurve fromLongName(const QString &name);

    Q_REQUIRED_RESULT Q_NETWORK_EXPORT QString shortName() const;
    Q_REQUIRED_RESULT Q_NETWORK_EXPORT QString longName() const;

    Q_DECL_CONSTEXPR bool isValid() const Q_DECL_NOTHROW
    {
        return id != 0;
    }

    Q_NETWORK_EXPORT bool isTlsNamedCurve() const Q_DECL_NOTHROW;

private:
    int id;

    friend Q_DECL_CONSTEXPR bool operator==(SslUnsafeEllipticCurve lhs, SslUnsafeEllipticCurve rhs) Q_DECL_NOTHROW;
    friend Q_DECL_CONSTEXPR uint qHash(SslUnsafeEllipticCurve curve, uint seed) Q_DECL_NOTHROW;

    friend class SslUnsafeContext;
    friend class SslUnsafeSocketPrivate;
    friend class SslUnsafeSocketBackendPrivate;
};

Q_DECLARE_TYPEINFO(SslUnsafeEllipticCurve, Q_PRIMITIVE_TYPE);

Q_DECL_CONSTEXPR inline uint qHash(SslUnsafeEllipticCurve curve, uint seed) Q_DECL_NOTHROW
{ return qHash(curve.id, seed); }

Q_DECL_CONSTEXPR inline bool operator==(SslUnsafeEllipticCurve lhs, SslUnsafeEllipticCurve rhs) Q_DECL_NOTHROW
{ return lhs.id == rhs.id; }

Q_DECL_CONSTEXPR inline bool operator!=(SslUnsafeEllipticCurve lhs, SslUnsafeEllipticCurve rhs) Q_DECL_NOTHROW
{ return !operator==(lhs, rhs); }

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, SslUnsafeEllipticCurve curve);
#endif

QT_END_NAMESPACE

Q_DECLARE_METATYPE(SslUnsafeEllipticCurve)

#endif // SSLUNSAFEELLIPTICCURVE_H
