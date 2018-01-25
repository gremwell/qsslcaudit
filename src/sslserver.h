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


#ifndef SSLSERVER_H
#define SSLSERVER_H

#include <QTcpServer>
#include <QString>

#ifdef UNSAFE
#include "sslunsafecertificate.h"
#include "sslunsafekey.h"
#include "sslunsafeellipticcurve.h"
#include "sslunsafecipher.h"
#else
#include <QSslCertificate>
#include <QSslKey>
#include <QSslEllipticCurve>
#include <QSslCipher>
#endif

#ifdef UNSAFE
#define XSslConfiguration SslUnsafeConfiguration
#define XSslSocket SslUnsafeSocket
#define XSslCertificate SslUnsafeCertificate
#define XSslKey SslUnsafeKey
#define XSslCipher SslUnsafeCipher
#define XSslEllipticCurve SslUnsafeEllipticCurve
#else
#define XSslConfiguration QSslConfiguration
#define XSslSocket QSslSocket
#define XSslCertificate QSslCertificate
#define XSslKey QSslKey
#define XSslCipher QSslCipher
#define XSslEllipticCurve QSslEllipticCurve
#endif

class XSslSocket;

class SslServer : public QTcpServer
{
    Q_OBJECT

public:
    SslServer(QObject *parent = 0);

    const XSslCertificate &getSslLocalCertificate() const;
    const XSslKey &getSslPrivateKey() const;
    QSsl::SslProtocol getSslProtocol() const;

    void setSslLocalCertificate(const XSslCertificate &certificate);
    bool setSslLocalCertificate(const QString &path, QSsl::EncodingFormat format = QSsl::Pem);

    void setSslLocalCertificateChain(const QList<XSslCertificate> &chain);
    bool setSslLocalCertificateChain(const QString &path, QSsl::EncodingFormat format = QSsl::Pem);

    void setSslPrivateKey(const XSslKey &key);
    bool setSslPrivateKey(const QString &fileName, QSsl::KeyAlgorithm algorithm = QSsl::Rsa,
                          QSsl::EncodingFormat format = QSsl::Pem, const QByteArray &passPhrase = QByteArray());

    void setSslProtocol(const QSsl::SslProtocol protocol);

    void setSslCiphers(const QList<XSslCipher> &ciphers);
    void setSslEllipticCurves(const QVector<XSslEllipticCurve> &ecurves);

    enum StartTlsProtocol {
        StartTlsFtp,
        StartTlsSmtp,
        StartTlsUnknownProtocol = -1
    };

    void setStartTlsProto(const SslServer::StartTlsProtocol protocol);

protected:
    void incomingConnection(qintptr socketDescriptor) override final;

private:
    void handleStartTls(XSslSocket *const socket);

    XSslCertificate m_sslLocalCertificate;
    QList<XSslCertificate> m_sslCertsChain;
    XSslKey m_sslPrivateKey;
    QSsl::SslProtocol m_sslProtocol;
    QList<XSslCipher> m_sslCiphers;
    QVector<XSslEllipticCurve> m_sslEllipticCurves;
    SslServer::StartTlsProtocol m_startTlsProtocol;

};

#endif // SSLSERVER_H
