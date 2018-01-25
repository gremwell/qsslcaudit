/**
 * Qt-SslServer, a Tcp Server class with SSL support using QTcpServer and QSslSocket.
 * Copyright (C) 2014  TRUCHOT Guillaume
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sslserver.h"
#include "debug.h"
#include "starttls.h"

#include <QFile>

#ifdef UNSAFE
#include "sslunsafeconfiguration.h"
#else
#include <QSslConfiguration>
#endif


SslServer::SslServer(QObject *parent) : QTcpServer(parent),
    m_sslLocalCertificate(),
    m_sslCertsChain(),
    m_sslPrivateKey(),
    m_sslProtocol(QSsl::UnknownProtocol),
    m_sslCiphers(XSslConfiguration::supportedCiphers()),
    m_sslEllipticCurves(XSslConfiguration::supportedEllipticCurves()),
    m_startTlsProtocol(SslServer::StartTlsUnknownProtocol)
{
}

void SslServer::incomingConnection(qintptr socketDescriptor)
{
    XSslSocket *sslSocket = new XSslSocket(this);

    if (!sslSocket->setSocketDescriptor(socketDescriptor)) {
        delete sslSocket;
        return;
    }

    addPendingConnection(sslSocket);

    // set SSL options using QSslConfiguration class
    XSslConfiguration sslConf;
    sslConf.setProtocol(m_sslProtocol);
    sslConf.setPrivateKey(m_sslPrivateKey);
    // in case both chain and certificate are provided, only chain is used
    if (!m_sslCertsChain.isEmpty()) {
        sslConf.setLocalCertificateChain(m_sslCertsChain);
    } else {
        sslConf.setLocalCertificate(m_sslLocalCertificate);
    }
    if (!m_sslCiphers.isEmpty())
        sslConf.setCiphers(m_sslCiphers);
#if SSLSERVER_ELL_CURVES
    if (!m_sslEllipticCurves.isEmpty())
        sslConf.setEllipticCurves(m_sslEllipticCurves);
#endif
    /* this is important to set even in server mode to properly verify SSLv3 / SSLv2 support */
    sslConf.setPeerVerifyMode(SslUnsafeSocket::VerifyNone);

    sslSocket->setSslConfiguration(sslConf);

    handleStartTls(sslSocket);

    sslSocket->startServerEncryption();
}

const XSslCertificate &SslServer::getSslLocalCertificate() const
{
    return m_sslLocalCertificate;
}

const XSslKey &SslServer::getSslPrivateKey() const
{
    return m_sslPrivateKey;
}

QSsl::SslProtocol SslServer::getSslProtocol() const
{
    return m_sslProtocol;
}

void SslServer::setSslLocalCertificate(const XSslCertificate &certificate)
{
    m_sslLocalCertificate = certificate;
}

bool SslServer::setSslLocalCertificate(const QString &path, QSsl::EncodingFormat format)
{
    QFile certificateFile(path);

    if (!certificateFile.open(QIODevice::ReadOnly))
        return false;

    m_sslLocalCertificate = XSslCertificate(certificateFile.readAll(), format);
    if (m_sslLocalCertificate.isNull())
        return false;

    return true;
}

void SslServer::setSslLocalCertificateChain(const QList<XSslCertificate> &chain)
{
    m_sslCertsChain = chain;
}

bool SslServer::setSslLocalCertificateChain(const QString &path, QSsl::EncodingFormat format)
{
    QFile certificateFile(path);

    if (!certificateFile.open(QIODevice::ReadOnly))
        return false;

    // fromData reads all certificates in file
    m_sslCertsChain = XSslCertificate::fromData(certificateFile.readAll(), format);
    if (m_sslCertsChain.isEmpty())
        return false;

    return true;
}

void SslServer::setSslPrivateKey(const XSslKey &key)
{
    m_sslPrivateKey = key;
}

bool SslServer::setSslPrivateKey(const QString &fileName, QSsl::KeyAlgorithm algorithm, QSsl::EncodingFormat format, const QByteArray &passPhrase)
{
    QFile keyFile(fileName);

    if (!keyFile.open(QIODevice::ReadOnly))
        return false;

    m_sslPrivateKey = XSslKey(keyFile.readAll(), algorithm, format, QSsl::PrivateKey, passPhrase);
    return true;
}

void SslServer::setSslProtocol(const QSsl::SslProtocol protocol)
{
    m_sslProtocol = protocol;
}

void SslServer::setSslCiphers(const QList<XSslCipher> &ciphers)
{
    m_sslCiphers = ciphers;
}

void SslServer::setSslEllipticCurves(const QVector<XSslEllipticCurve> &ecurves)
{
    m_sslEllipticCurves = ecurves;
}

void SslServer::setStartTlsProto(const SslServer::StartTlsProtocol protocol)
{
    m_startTlsProtocol = protocol;
}

void SslServer::handleStartTls(XSslSocket *const socket)
{
    switch (m_startTlsProtocol) {
    case SslServer::StartTlsFtp:
        handleStartTlsFtp(socket);
        break;
    case SslServer::StartTlsSmtp:
        handleStartTlsSmtp(socket);
        break;
    default:
        break;
    }
}
