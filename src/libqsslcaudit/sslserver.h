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

#ifdef UNSAFE_QSSL
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


class XSslSocket;

class SslServer : public QTcpServer
{
    Q_OBJECT

public:
    SslServer(QObject *parent = 0);

    const XSslCertificate &getSslLocalCertificate() const;
    const XSslKey &getSslPrivateKey() const;
    XSsl::SslProtocol getSslProtocol() const;

    void setSslLocalCertificate(const XSslCertificate &certificate);
    bool setSslLocalCertificate(const QString &path, XSsl::EncodingFormat format = XSsl::Pem);

    void setSslLocalCertificateChain(const QList<XSslCertificate> &chain);
    bool setSslLocalCertificateChain(const QString &path, XSsl::EncodingFormat format = XSsl::Pem);

    void setSslPrivateKey(const XSslKey &key);
    bool setSslPrivateKey(const QString &fileName, XSsl::KeyAlgorithm algorithm = XSsl::Rsa,
                          XSsl::EncodingFormat format = XSsl::Pem, const QByteArray &passPhrase = QByteArray());

    void setSslProtocol(const XSsl::SslProtocol protocol);

    void setSslCiphers(const QList<XSslCipher> &ciphers);
    void setSslEllipticCurves(const QVector<XSslEllipticCurve> &ecurves);

    enum StartTlsProtocol {
        StartTlsFtp,
        StartTlsSmtp,
        StartTlsUnknownProtocol = -1
    };

    void setStartTlsProto(const SslServer::StartTlsProtocol protocol);

    const QStringList &getSslInitErrorsStr() const;
    const QList<QAbstractSocket::SocketError> &getSslInitErrors() const;

protected:
    void incomingConnection(qintptr socketDescriptor) override final;

private:
    void handleStartTls(XSslSocket *const socket);
    void handleSocketError(QAbstractSocket::SocketError socketError);

    XSslCertificate m_sslLocalCertificate;
    QList<XSslCertificate> m_sslCertsChain;
    XSslKey m_sslPrivateKey;
    XSsl::SslProtocol m_sslProtocol;
    QList<XSslCipher> m_sslCiphers;
    QVector<XSslEllipticCurve> m_sslEllipticCurves;
    SslServer::StartTlsProtocol m_startTlsProtocol;
    QStringList m_sslInitErrorsStr;
    QList<QAbstractSocket::SocketError> m_sslInitErrors;

};

#endif // SSLSERVER_H
