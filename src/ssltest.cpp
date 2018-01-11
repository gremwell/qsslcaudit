#include "ssltest.h"
#include "debug.h"


SslTest::SslTest()
{

}

/* default implementation handles certificate accept/refuse case */
void SslTest::report(const QList<XSslError> sslErrors,
                     const QList<QAbstractSocket::SocketError> socketErrors,
                     bool sslConnectionEstablished,
                     bool dataReceived) const
{
    if (dataReceived) {
        RED("test failed, client accepted user-supplied certificate, data was intercepted");
        return;
    }

    if (sslConnectionEstablished && !dataReceived
            && !socketErrors.contains(QAbstractSocket::RemoteHostClosedError)) {
        RED("test failed, client accepted user-supplied certificate, but no data transmitted");
        return;
    }

    GREEN("test passed, client refused user-supplied certificate");
}
