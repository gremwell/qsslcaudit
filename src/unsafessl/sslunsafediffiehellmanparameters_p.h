#ifndef SSLUNSAFEDIFFIEHELLMANPARAMETERS_P_H
#define SSLUNSAFEDIFFIEHELLMANPARAMETERS_P_H

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include <QSharedData>

#include "sslunsafekey.h"
#include "sslunsafediffiehellmanparameters.h"
#include "sslunsafesocket_p.h" // includes wincrypt.h

class SslUnsafeDiffieHellmanParametersPrivate : public QSharedData
{
public:
    SslUnsafeDiffieHellmanParametersPrivate() : error(SslUnsafeDiffieHellmanParameters::NoError) {};

    void decodeDer(const QByteArray &der);
    void decodePem(const QByteArray &pem);

    SslUnsafeDiffieHellmanParameters::Error error;
    QByteArray derData;
};

#endif // QSSLDIFFIEHELLMANPARAMETERS_P_H
