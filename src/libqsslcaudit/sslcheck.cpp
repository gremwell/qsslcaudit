#include "sslcheck.h"
#include "clientinfo.h"


SslCheck::SslCheck()
{

}

SslCheck::~SslCheck()
{

}

const SslCheckReport SslCheckSocketErrors::doCheck(const ClientInfo &client) const
{
    SslCheckReport rep;

    rep.result = SslTestResult::Success;

    // all errors should be here except those which we handle below in a particular test
    if (client.socketErrors().contains(QAbstractSocket::ConnectionRefusedError)
            || client.socketErrors().contains(QAbstractSocket::HostNotFoundError)
            || client.socketErrors().contains(QAbstractSocket::SocketAccessError)
            || client.socketErrors().contains(QAbstractSocket::SocketResourceError)
            || client.socketErrors().contains(QAbstractSocket::DatagramTooLargeError)
            || client.socketErrors().contains(QAbstractSocket::NetworkError)
            || client.socketErrors().contains(QAbstractSocket::AddressInUseError)
            || client.socketErrors().contains(QAbstractSocket::SocketAddressNotAvailableError)
            || client.socketErrors().contains(QAbstractSocket::UnsupportedSocketOperationError)
            || client.socketErrors().contains(QAbstractSocket::UnfinishedSocketOperationError)
            || client.socketErrors().contains(QAbstractSocket::OperationError)
            || client.socketErrors().contains(QAbstractSocket::TemporaryError)) {
        rep.report = QString("socket/network error occuried");
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("socket error");
        return rep;
    }

    if (client.socketErrors().contains(QAbstractSocket::UnknownSocketError)) {
        rep.report = QString("unknown socket error occuried");
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("socket error");
        return rep;
    }

    return rep;
}

const SslCheckReport SslCheckNonSslClient::doCheck(const ClientInfo &client) const
{
    SslCheckReport rep;

    rep.result = SslTestResult::Success;

    // technically it depends on UNSAFE_QSSL, but it is always enabled
//#ifdef UNSAFE_QSSL
    // some conditions below are excessive, this is for purpose to make our decisions clear
    if ((client.rawDataRecv().size() == 0)
            && !client.sslConnectionEstablished()
            && !client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && client.socketErrors().contains(QAbstractSocket::SocketTimeoutError)) {
        rep.report = QString("no data was transmitted before timeout expired");
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        return rep;
    }

    if ((client.rawDataRecv().size() == 0)
            && !client.sslConnectionEstablished()
            && client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && !client.socketErrors().contains(QAbstractSocket::SocketTimeoutError)) {
        rep.report = QString("client closed the connection without transmitting any data");
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        return rep;
    }

    if ((client.rawDataRecv().size() > 0)
            && !client.sslConnectionEstablished()
            && client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && !client.socketErrors().contains(QAbstractSocket::SocketTimeoutError)
            && !client.hasHelloMessage()) {
        rep.report = QString("secure connection was not established, %1 bytes were received before client closed the connection")
                .arg(client.rawDataRecv().size());
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        return rep;
    }

    // this case is the same for broken SSL clients and perfectly valid ones
#if 0
    if ((client.rawDataRecv().size() > 0)
            && !client.sslConnectionEstablished()
            && client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && !client.socketErrors().contains(QAbstractSocket::SocketTimeoutError)
            && client.hasHelloMessage()
            && (client.sslErrorsStr().size() == 1)
            && client.sslErrorsStr().contains("The remote host closed the connection")) {
        // client sent HELLO, but as SSL errors list is empty and encrypted connection
        // was not established, something went wrong in the middle of handshake
        // thus, consider client as non-SSL
        rep.report = QString("secure connection was not properly established (however, the attempt was made), client closed the connection");
        rep.result = SSLTEST_RESULT_UNDEFINED);
        return true;
    }
#endif

    if ((client.rawDataRecv().size() > 0)
            && !client.sslConnectionEstablished()
            && !client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && client.socketErrors().contains(QAbstractSocket::SocketTimeoutError)
            && !client.hasHelloMessage()) {
        rep.report = QString("secure connection was not established, %1 bytes were received before client was disconnected")
                .arg(client.rawDataRecv().size());
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        return rep;
    }

    if ((client.rawDataRecv().size() > 0)
            && !client.sslConnectionEstablished()
            && !client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && client.socketErrors().contains(QAbstractSocket::SocketTimeoutError)
            && client.hasHelloMessage()
            && (client.sslErrorsStr().size() == 1)
            && client.sslErrorsStr().contains("Network operation timed out")) {
        // client sent HELLO, but as SSL errors list is empty and encrypted connection
        // was not established, something went wrong in the middle of handshake
        // thus, consider client as non-SSL
        rep.report = QString("secure connection was not properly established (however, the attempt was made), client was disconnected");
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        return rep;
    }

    if ((client.rawDataRecv().size() > 0)
            && !client.sslConnectionEstablished()
            && !client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)
            && !client.socketErrors().contains(QAbstractSocket::SocketTimeoutError)
            && !client.hasHelloMessage()
            && (client.socketErrors().contains(QAbstractSocket::SslHandshakeFailedError)
                && ((client.sslErrorsStr().filter(QString("SSL23_GET_CLIENT_HELLO:http request")).size() > 0)
                    || (client.sslErrorsStr().filter(QString("SSL23_GET_CLIENT_HELLO:unknown protocol")).size() > 0)))) {
        rep.report = QString("secure connection was not established, %1 bytes of unexpected protocol were received before the connection was closed")
                .arg(client.rawDataRecv().size());
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        return rep;
    }

    // failsafe check. this can't be SSL client without HELLO message intercepted
    if ((client.rawDataRecv().size() > 0)
            && !client.hasHelloMessage()) {
        rep.report = QString("secure connection was not established, %1 bytes were received before the connection was closed")
                .arg(client.rawDataRecv().size());
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("broken client");
        return rep;
    }
//#endif
    return rep;
}

const SslCheckReport SslCheckForGenericSslErrors::doCheck(const ClientInfo &client) const
{
    SslCheckReport rep;

    rep.result = SslTestResult::Success;

    if (client.socketErrors().contains(QAbstractSocket::SslInternalError)
            || client.socketErrors().contains(QAbstractSocket::SslInvalidUserDataError)) {
        rep.report = QString("failure during SSL initialization");
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("can't init SSL");
        return rep;
    }

    return rep;
}

const SslCheckReport SslCheckCertificatesValidation::doCheck(const ClientInfo &client) const
{
    SslCheckReport rep;

    rep.result = SslTestResult::Success;

    if (client.interceptedData().size() > 0) {
        rep.report = QString("test failed, client accepted fake certificate, data was intercepted");
        rep.result = SslTestResult::DataIntercepted;
        rep.comment = QString("mitm possible");
        return rep;
    }

    if (client.sslConnectionEstablished()
            && (client.interceptedData().size() == 0)
            && ((client.dtlsMode() && !client.dtlsErrors().contains(XDtlsError::RemoteClosedConnectionError))
                || (!client.dtlsMode() && !client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)))) {
        rep.report = QString("test failed, client accepted fake certificate, but no data transmitted");
        rep.result = SslTestResult::CertAccepted;
        rep.comment = QString("mitm possible");
        return rep;
    }

    if (!client.sslConnectionEstablished()
            && (client.socketErrors().contains(QAbstractSocket::SslHandshakeFailedError)
                && ((client.sslErrorsStr().filter(QString("SSL23_GET_CLIENT_HELLO:unknown protocol")).size() > 0)
                    || (client.sslErrorsStr().filter(QString("ssl3_get_client_hello:wrong version number")).size() > 0)))) {
        rep.report = QString("secure connection was not established, %1 bytes of unsupported TLS/SSL protocol were received before the connection was closed")
                .arg(client.rawDataRecv().size());
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("client proposed unsupported TLS/SSL protocol");
        return rep;
    }

    if (!client.sslConnectionEstablished()) {
        rep.report = QString("test passed, client refused fake certificate");
        rep.result = SslTestResult::Success;
        rep.comment = QString("");
        return rep;
    }

    // this is a controversion situation
    if (client.sslConnectionEstablished()
            && (client.interceptedData().size() == 0)
            && ((client.dtlsMode() && client.dtlsErrors().contains(XDtlsError::RemoteClosedConnectionError))
                || (!client.dtlsMode() && client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)))) {
        rep.report = QString("test result not clear, client established TLS session but disconnected without data transmission and explicit error message");
        rep.result = SslTestResult::Undefined;
        rep.comment = QString("Invalid clients refuse cert in this way. Clients without data transmitted accept fake cert with the same diagnostics. Setup MitM proxy to be sure.");
        return rep;
    }

    rep.report = QString("unhandled case! please report it to developers!");
    rep.result = SslTestResult::Undefined;
    rep.comment = QString("report this to developers");

    return rep;
}

const SslCheckReport SslCheckProtocolsCiphersSupport::doCheck(const ClientInfo &client) const
{
    SslCheckReport rep;

    rep.result = SslTestResult::Success;

    if (client.interceptedData().size() > 0) {
        rep.report = QString("test failed, client accepted fake certificate and weak protocol, data was intercepted");
        rep.result = SslTestResult::DataIntercepted;
        rep.comment = QString("mitm possible");
        return rep;
    }

    if (client.sslConnectionEstablished()
            && (client.interceptedData().size() == 0)
            && ((client.dtlsMode() && !client.dtlsErrors().contains(XDtlsError::RemoteClosedConnectionError))
                || (!client.dtlsMode() && !client.socketErrors().contains(QAbstractSocket::RemoteHostClosedError)))) {
        rep.report = QString("test failed, client accepted fake certificate and weak protocol, but no data transmitted");
        rep.result = SslTestResult::CertAccepted;
        rep.comment = QString("mitm possible");
        return rep;
    }

    if (client.sslConnectionEstablished()) {
        rep.report = QString("test failed, client accepted weak protocol");
        rep.result = SslTestResult::ProtoAccepted;
        rep.comment = QString("");
        return rep;
    }

    if (!client.sslConnectionEstablished()
            && (client.dtlsMode() || (!client.dtlsMode() && client.socketErrors().contains(QAbstractSocket::SslHandshakeFailedError)))
            && ((client.sslErrorsStr().filter(QString("certificate unknown")).size() > 0)
                || (client.sslErrorsStr().filter(QString("unknown ca")).size() > 0)
                || (client.sslErrorsStr().filter(QString("bad certificate")).size() > 0))) {
        rep.report = QString("test failed, client accepted weak protocol");
        rep.result = SslTestResult::ProtoAcceptedWithErr;
        rep.comment = QString("");
        return rep;
    } else if (!client.sslConnectionEstablished()) {
        rep.report = QString("test passed, client does not accept weak protocol");
        rep.result = SslTestResult::Success;
        rep.comment = QString("");
        return rep;
    }

    rep.report = QString("unhandled case! please report it to developers!");
    rep.result = SslTestResult::Undefined;
    rep.comment = QString("report to developers");

    return rep;
}
