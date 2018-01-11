#ifndef SSLUNSAFECERTIFICATEEXTENSION_P_H
#define SSLUNSAFECERTIFICATEEXTENSION_P_H

//#include <QtNetwork/private/qtnetworkglobal_p.h>
#include "sslunsafecertificateextension.h"

class SslUnsafeCertificateExtensionPrivate : public QSharedData
{
public:
    inline SslUnsafeCertificateExtensionPrivate()
        : critical(false),
          supported(false)
    {
    }

    QString oid;
    QString name;
    QVariant value;
    bool critical;
    bool supported;
};

#endif // QSSLCERTIFICATEEXTENSION_P_H
