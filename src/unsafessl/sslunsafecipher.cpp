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


/*!
    \class SslUnsafeCipher
    \brief The SslUnsafeCipher class represents an SSL cryptographic cipher.
    \since 4.3

    \reentrant
    \ingroup network
    \ingroup ssl
    \ingroup shared
    \inmodule QtNetwork

    SslUnsafeCipher stores information about one cryptographic cipher. It
    is most commonly used with SslUnsafeSocket, either for configuring
    which ciphers the socket can use, or for displaying the socket's
    ciphers to the user.

    \sa SslUnsafeSocket, SslUnsafeKey
*/

#include "sslunsafecipher.h"
#include "sslunsafecipher_p.h"
#include "sslunsafesocket.h"
#include "sslunsafeconfiguration.h"

#ifndef QT_NO_DEBUG_STREAM
#include <QtCore/qdebug.h>
#endif

QT_BEGIN_NAMESPACE

/*!
    Constructs an empty SslUnsafeCipher object.
*/
SslUnsafeCipher::SslUnsafeCipher()
    : d(new SslUnsafeCipherPrivate)
{
}

/*!
    \since 5.3

    Constructs a SslUnsafeCipher object for the cipher determined by \a
    name. The constructor accepts only supported ciphers (i.e., the
    \a name must identify a cipher in the list of ciphers returned by
    SslUnsafeSocket::supportedCiphers()).

    You can call isNull() after construction to check if \a name
    correctly identified a supported cipher.
*/
SslUnsafeCipher::SslUnsafeCipher(const QString &name)
    : d(new SslUnsafeCipherPrivate)
{
    const auto ciphers = SslUnsafeConfiguration::supportedCiphers();
    for (const SslUnsafeCipher &cipher : ciphers) {
        if (cipher.name() == name) {
            *this = cipher;
            return;
        }
    }
}

/*!
    Constructs a SslUnsafeCipher object for the cipher determined by \a
    name and \a protocol. The constructor accepts only supported
    ciphers (i.e., the \a name and \a protocol must identify a cipher
    in the list of ciphers returned by
    SslUnsafeSocket::supportedCiphers()).

    You can call isNull() after construction to check if \a name and
    \a protocol correctly identified a supported cipher.
*/
SslUnsafeCipher::SslUnsafeCipher(const QString &name, SslUnsafe::SslProtocol protocol)
    : d(new SslUnsafeCipherPrivate)
{
    const auto ciphers = SslUnsafeConfiguration::supportedCiphers();
    for (const SslUnsafeCipher &cipher : ciphers) {
        if (cipher.name() == name && cipher.protocol() == protocol) {
            *this = cipher;
            return;
        }
    }
}

/*!
    Constructs an identical copy of the \a other cipher.
*/
SslUnsafeCipher::SslUnsafeCipher(const SslUnsafeCipher &other)
    : d(new SslUnsafeCipherPrivate)
{
    *d.data() = *other.d.data();
}

/*!
    Destroys the SslUnsafeCipher object.
*/
SslUnsafeCipher::~SslUnsafeCipher()
{
}

/*!
    Copies the contents of \a other into this cipher, making the two
    ciphers identical.
*/
SslUnsafeCipher &SslUnsafeCipher::operator=(const SslUnsafeCipher &other)
{
    *d.data() = *other.d.data();
    return *this;
}

/*!
    \fn void SslUnsafeCipher::swap(SslUnsafeCipher &other)
    \since 5.0

    Swaps this cipher instance with \a other. This function is very
    fast and never fails.
*/

/*!
    Returns \c true if this cipher is the same as \a other; otherwise,
    false is returned.
*/
bool SslUnsafeCipher::operator==(const SslUnsafeCipher &other) const
{
    return d->name == other.d->name && d->protocol == other.d->protocol;
}

/*!
    \fn bool SslUnsafeCipher::operator!=(const SslUnsafeCipher &other) const

    Returns \c true if this cipher is not the same as \a other;
    otherwise, false is returned.
*/

/*!
    Returns \c true if this is a null cipher; otherwise returns \c false.
*/
bool SslUnsafeCipher::isNull() const
{
    return d->isNull;
}

/*!
    Returns the name of the cipher, or an empty QString if this is a null
    cipher.

    \sa isNull()
*/
QString SslUnsafeCipher::name() const
{
    return d->name;
}

/*!
    Returns the number of bits supported by the cipher.

    \sa usedBits()
*/
int SslUnsafeCipher::supportedBits()const
{
    return d->supportedBits;
}

/*!
    Returns the number of bits used by the cipher.

    \sa supportedBits()
*/
int SslUnsafeCipher::usedBits() const
{
    return d->bits;
}

/*!
    Returns the cipher's key exchange method as a QString.
*/
QString SslUnsafeCipher::keyExchangeMethod() const
{
    return d->keyExchangeMethod;
}

/*!
    Returns the cipher's authentication method as a QString.
*/
QString SslUnsafeCipher::authenticationMethod() const
{
    return d->authenticationMethod;
}

/*!
    Returns the cipher's encryption method as a QString.
*/
QString SslUnsafeCipher::encryptionMethod() const
{
    return d->encryptionMethod;
}

/*!
    Returns the cipher's protocol as a QString.

    \sa protocol()
*/
QString SslUnsafeCipher::protocolString() const
{
    return d->protocolString;
}

/*!
    Returns the cipher's protocol type, or \l SslUnsafe::UnknownProtocol if
    SslUnsafeCipher is unable to determine the protocol (protocolString() may
    contain more information).

    \sa protocolString()
*/
SslUnsafe::SslProtocol SslUnsafeCipher::protocol() const
{
    return d->protocol;
}

#ifndef QT_NO_DEBUG_STREAM
QDebug operator<<(QDebug debug, const SslUnsafeCipher &cipher)
{
    QDebugStateSaver saver(debug);
    debug.resetFormat().nospace().noquote();
    debug << "SslUnsafeCipher(name=" << cipher.name()
          << ", bits=" << cipher.usedBits()
          << ", proto=" << cipher.protocolString()
          << ')';
    return debug;
}
#endif

QT_END_NAMESPACE
