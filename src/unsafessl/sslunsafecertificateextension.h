/****************************************************************************
**
** Copyright (C) 2011 Richard J. Moore <rich@kde.org>
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

#ifndef SSLUNSAFECERTIFICATEEXTENSION_H
#define SSLUNSAFECERTIFICATEEXTENSION_H

#include "sslunsafenetworkglobal.h"
#include <QtCore/qnamespace.h>
#include <QtCore/qshareddata.h>
#include <QtCore/qstring.h>
#include <QtCore/qvariant.h>

QT_BEGIN_NAMESPACE


#ifndef QT_NO_SSL

class SslUnsafeCertificateExtensionPrivate;

class Q_NETWORK_EXPORT SslUnsafeCertificateExtension
{
public:
    SslUnsafeCertificateExtension();
    SslUnsafeCertificateExtension(const SslUnsafeCertificateExtension &other);
#ifdef Q_COMPILER_RVALUE_REFS
    SslUnsafeCertificateExtension &operator=(SslUnsafeCertificateExtension &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif
    SslUnsafeCertificateExtension &operator=(const SslUnsafeCertificateExtension &other);
    ~SslUnsafeCertificateExtension();

    void swap(SslUnsafeCertificateExtension &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    QString oid() const;
    QString name() const;
    QVariant value() const;
    bool isCritical() const;

    bool isSupported() const;

private:
    friend class SslUnsafeCertificatePrivate;
    QSharedDataPointer<SslUnsafeCertificateExtensionPrivate> d;
};

Q_DECLARE_SHARED(SslUnsafeCertificateExtension)

#endif // QT_NO_SSL

QT_END_NAMESPACE


#endif // SslUnsafeCERTIFICATEEXTENSION_H


