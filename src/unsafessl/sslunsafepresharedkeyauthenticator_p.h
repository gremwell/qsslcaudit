#ifndef SSLUNSAFEPRESHAREDKEYAUTHENTICATOR_P_H
#define SSLUNSAFEPRESHAREDKEYAUTHENTICATOR_P_H

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include <QSharedData>

class SslUnsafePreSharedKeyAuthenticatorPrivate : public QSharedData
{
public:
    SslUnsafePreSharedKeyAuthenticatorPrivate();

    QByteArray identityHint;

    QByteArray identity;
    int maximumIdentityLength;

    QByteArray preSharedKey;
    int maximumPreSharedKeyLength;
};

#endif // QSSLPRESHAREDKEYAUTHENTICATOR_P_H
