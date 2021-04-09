#include "sslcheck.h"
#include "clientinfo.h"


SslCheck::SslCheck()
{

}

SslCheck::~SslCheck()
{

}

const SslCheckReport SslCheckSocketErrors::doCheck(const ClientInfo *client) const
{
    SslCheckReport rep;

    // the errors here should not appear during regular communication
    // the rest is fine and are important for other checks
    if (client->socketErrors().contains(QAbstractSocket::ConnectionRefusedError)
            || client->socketErrors().contains(QAbstractSocket::HostNotFoundError)
            || client->socketErrors().contains(QAbstractSocket::SocketAccessError)
            || client->socketErrors().contains(QAbstractSocket::SocketResourceError)
            || client->socketErrors().contains(QAbstractSocket::DatagramTooLargeError)
            || client->socketErrors().contains(QAbstractSocket::NetworkError)
            || client->socketErrors().contains(QAbstractSocket::AddressInUseError)
            || client->socketErrors().contains(QAbstractSocket::SocketAddressNotAvailableError)
            || client->socketErrors().contains(QAbstractSocket::UnsupportedSocketOperationError)
            || client->socketErrors().contains(QAbstractSocket::UnfinishedSocketOperationError)
            || client->socketErrors().contains(QAbstractSocket::ProxyAuthenticationRequiredError)
            || client->socketErrors().contains(QAbstractSocket::ProxyConnectionRefusedError)
            || client->socketErrors().contains(QAbstractSocket::ProxyConnectionClosedError)
            || client->socketErrors().contains(QAbstractSocket::ProxyConnectionTimeoutError)
            || client->socketErrors().contains(QAbstractSocket::ProxyNotFoundError)
            || client->socketErrors().contains(QAbstractSocket::ProxyProtocolError)
            || client->socketErrors().contains(QAbstractSocket::OperationError)
            || client->socketErrors().contains(QAbstractSocket::TemporaryError)) {
        rep.report = QString("socket/network error occuried");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("socket error");
        rep.isPassed = false;
        return rep;
    } else if (client->socketErrors().contains(QAbstractSocket::UnknownSocketError)) {
        rep.report = QString("unknown socket error occuried");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("socket error");
        rep.isPassed = false;
        return rep;
    }

    rep.report = QString("");
    rep.suggestedTestResult = SslTestResult::Undefined;
    rep.comment = QString("");
    rep.isPassed = true;
    return rep;
}

const SslCheckReport SslCheckNoData::doCheck(const ClientInfo *client) const
{
    SslCheckReport rep;

    if ((client->rawDataRecv().size() == 0)
            && !client->socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && client->socketErrors().contains(QAbstractSocket::SocketTimeoutError)) {
        rep.report = QString("no data was transmitted before timeout expired");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        rep.isPassed = false;
        return rep;
    }

    if ((client->rawDataRecv().size() == 0)
            && client->socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && !client->socketErrors().contains(QAbstractSocket::SocketTimeoutError)) {
        rep.report = QString("client closed the connection without transmitting any data");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        rep.isPassed = false;
        return rep;
    }

    if (client->rawDataRecv().size() > 0) {
        rep.report = QString("");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("");
        rep.isPassed = true;
        return rep;
    }

    rep.report = QString("no data received with socket in incorrect state");
    rep.suggestedTestResult = SslTestResult::UnhandledCase;
    rep.comment = QString("report this case to developers");
    rep.isPassed = false;
    return rep;
}

const SslCheckReport SslCheckNonSslData::doCheck(const ClientInfo *client) const
{
    SslCheckReport rep;

    if (client->hasHelloMessage()) {
        rep.report = QString("");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("");
        rep.isPassed = true;
        return rep;
    }

    if ((client->rawDataRecv().size() > 0)
            && !client->hasHelloMessage()
            && ((client->sslErrorsStr().filter(QString("SSL23_GET_CLIENT_HELLO:http request")).size() > 0)
                || (client->sslErrorsStr().filter(QString("SSL23_GET_CLIENT_HELLO:unknown protocol")).size() > 0))) {
        rep.report = QString("%1 bytes of unexpected protocol were received before the connection was closed")
                .arg(client->rawDataRecv().size());
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        rep.isPassed = false;
        return rep;
    }

    if ((client->rawDataRecv().size() > 0)
            && !client->hasHelloMessage()
            && client->socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && !client->socketErrors().contains(QAbstractSocket::SocketTimeoutError)) {
        rep.report = QString("%1 non-SSL bytes were received before client closed the connection")
                .arg(client->rawDataRecv().size());
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        rep.isPassed = false;
        return rep;
    }

    if ((client->rawDataRecv().size() > 0)
            && !client->hasHelloMessage()
            && !client->socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && client->socketErrors().contains(QAbstractSocket::SocketTimeoutError)) {
        rep.report = QString("%1 non-SSL bytes were received before timeout expired")
                .arg(client->rawDataRecv().size());
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        rep.isPassed = false;
        return rep;
    }

    rep.report = QString("%1 bytes were received, however, unexpected set of other errors observed")
            .arg(client->rawDataRecv().size());
    rep.suggestedTestResult = SslTestResult::Undefined;
    rep.comment = QString("broken client");
    rep.isPassed = false;
    return rep;
}

const SslCheckReport SslCheckInvalidSsl::doCheck(const ClientInfo *client) const
{
    SslCheckReport rep;

    if (client->hasHelloMessage()
            && !client->sslConnectionEstablished()
            // specifically checking that there are no SSL-related errors
            && (((client->sslErrorsStr().size() == 1) && client->sslErrorsStr().contains("Network operation timed out"))
                || (client->sslErrorsStr().size() == 0))) {
        // client sent HELLO, but as SSL errors list is empty and encrypted connection
        // was not established, something went wrong in the middle of handshake
        // thus, consider client as non-SSL
        rep.report = QString("secure connection was not properly established (however, the attempt was made)");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        rep.isPassed = false;
        return rep;
    }

    rep.report = QString("");
    rep.suggestedTestResult = SslTestResult::Undefined;
    rep.comment = QString("");
    rep.isPassed = true;
    return rep;
}

const SslCheckReport SslCheckForGenericSslErrors::doCheck(const ClientInfo *client) const
{
    SslCheckReport rep;

    if (client->socketErrors().contains(QAbstractSocket::SslInternalError)
            || client->socketErrors().contains(QAbstractSocket::SslInvalidUserDataError)) {
        // somehow Firefox triggers SslInternalError when refusing the proposed certificate
        // checking it here
        if (client->socketErrors().contains(QAbstractSocket::SslInternalError)) {
            int idx = client->socketErrors().indexOf(QAbstractSocket::SslInternalError);
            if ((client->sslErrorsStr().at(idx).contains("alert bad certificate"))
                    || (client->sslErrorsStr().at(idx).contains("alert unknown ca"))) {
                rep.report = QString("");
                rep.suggestedTestResult = SslTestResult::Undefined;
                rep.comment = QString("");
                rep.isPassed = true;
                return rep;
            }
        }
        rep.report = QString("failure during SSL initialization");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("can't init SSL context");
        rep.isPassed = false;
        return rep;
    }

    if (!client->sslConnectionEstablished()
            && (client->socketErrors().contains(QAbstractSocket::SslHandshakeFailedError)
                && ((client->sslErrorsStr().filter(QString("SSL23_GET_CLIENT_HELLO:unknown protocol")).size() > 0)
                    || (client->sslErrorsStr().filter(QString("ssl3_get_client_hello:wrong version number")).size() > 0)))) {
        rep.report = QString("secure connection was not established, %1 bytes of unsupported TLS/SSL protocol were received before the connection was closed")
                .arg(client->rawDataRecv().size());
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("client proposed unsupported TLS/SSL protocol");
        rep.isPassed = false;
        return rep;
    }

    rep.report = QString("");
    rep.suggestedTestResult = SslTestResult::Undefined;
    rep.comment = QString("");
    rep.isPassed = true;
    return rep;
}

const SslCheckReport SslCheckConnectionEstablished::doCheck(const ClientInfo *client) const
{
    SslCheckReport rep;

    if (client->sslConnectionEstablished()
            && (client->interceptedData().size() > 0)) {
        rep.report = QString("test failed, client accepted fake certificate, data was intercepted");
        rep.suggestedTestResult = SslTestResult::DataIntercepted;
        rep.comment = QString("mitm possible");
        rep.isPassed = false;
        return rep;
    }

    if (client->sslConnectionEstablished()
            && (client->interceptedData().size() == 0)
            && ((client->dtlsMode() && !client->dtlsErrors().contains(XDtlsError::RemoteClosedConnectionError))
                || (!client->dtlsMode() && !client->socketErrors().contains(QAbstractSocket::RemoteHostClosedError)))) {
        rep.report = QString("test failed, client accepted fake certificate, but no data transmitted");
        rep.suggestedTestResult = SslTestResult::CertAccepted;
        rep.comment = QString("mitm possible");
        rep.isPassed = false;
        return rep;
    }

    // this is a controversion situation
    if (client->sslConnectionEstablished()
            && (client->interceptedData().size() == 0)
            && ((client->dtlsMode() && client->dtlsErrors().contains(XDtlsError::RemoteClosedConnectionError))
                || (!client->dtlsMode() && client->socketErrors().contains(QAbstractSocket::RemoteHostClosedError)))) {
        rep.report = QString("test result not clear, client established TLS session but disconnected without data transmission and explicit error message");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("consider PASSED for clients which send data on the first connection. other clients test with complete MitM setup (see --forward)");
        rep.isPassed = false;
        return rep;
    }

    if (client->sslConnectionEstablished()) {
        rep.report = QString("unhandled case! please report it to developers!");
        rep.suggestedTestResult = SslTestResult::UnhandledCase;
        rep.comment = QString("report this to developers");
        rep.isPassed = false;
        return rep;
    }

    rep.report = QString("");
    rep.suggestedTestResult = SslTestResult::Undefined;
    rep.comment = QString("");
    rep.isPassed = true;
    return rep;
}

const SslCheckReport SslCheckCertificateRefused::doCheck(const ClientInfo *client) const
{
    SslCheckReport rep;

    rep.suggestedTestResult = SslTestResult::Success;
    rep.isPassed = true;

    if (!client->sslConnectionEstablished()
            && (client->dtlsMode() || (!client->dtlsMode() && client->socketErrors().contains(QAbstractSocket::SslHandshakeFailedError)))
            && ((client->sslErrorsStr().filter(QString("certificate unknown")).size() > 0)
                || (client->sslErrorsStr().filter(QString("unknown ca")).size() > 0)
                || (client->sslErrorsStr().filter(QString("bad certificate")).size() > 0))) {
        rep.report = QString("client accepted our protocol but explicitly refused our certificate");
        rep.suggestedTestResult = SslTestResult::ProtoAcceptedWithErr;
        rep.comment = QString("");
        rep.isPassed = false;
        return rep;
    }

    return rep;
}

const SslCheckReport SslCheckNoSharedCipher::doCheck(const ClientInfo *client) const
{
    SslCheckReport rep;

    rep.suggestedTestResult = SslTestResult::Success;
    rep.isPassed = true;

    if (!client->sslConnectionEstablished()
            && (client->sslErrorsStr().filter(QString("no shared cipher")).size() > 0)) {
        rep.report = QString("client accepted our protocol but explicitly refused our ciphers");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("");
        rep.isPassed = false;
        return rep;
    }

    return rep;
}

const SslCheckReport SslCheckHttpsClient::doCheck(const ClientInfo *client) const
{
    SslCheckReport rep;

    if (client->hasHelloMessage()
            && (client->tlsHelloInfo.hnd_hello.alpn.contains(QByteArray("h2"))
                || client->tlsHelloInfo.hnd_hello.alpn.contains(QByteArray("http/1.1")))) {
        rep.report = QString("client identifies itself as HTTPS client");
        rep.suggestedTestResult = SslTestResult::Success;
        rep.comment = QString("");
        rep.isPassed = true;
        return rep;
    }

    if (client->hasHelloMessage()
            && client->tlsHelloInfo.hnd_hello.alpn.isEmpty()) {
        rep.report = QString("client does not explitictly define application layer protocol");
        rep.suggestedTestResult = SslTestResult::Undefined;
        rep.comment = QString("");
        rep.isPassed = false;
        return rep;
    }

    rep.report = QString("client requests some other protocol");
    rep.suggestedTestResult = SslTestResult::Undefined;
    rep.comment = QString("");
    rep.isPassed = false;
    return rep;
}
