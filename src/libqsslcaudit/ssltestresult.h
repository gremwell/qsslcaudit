#ifndef SSLTESTRESULT_H
#define SSLTESTRESULT_H

#include <QString>

enum class SslTestResult : int
{
    Success = 0,
    NotReady = -99,
    Undefined = -98,
    InitFailed = -1,
    DataIntercepted = -2,
    CertAccepted = -3,
    ProtoAccepted = -4,
    ProtoAcceptedWithErr = -5,
};

extern const QString sslTestResultToString(SslTestResult r);
extern const QString sslTestResultToStatus(SslTestResult result);


#endif // SSLTESTRESULT_H
