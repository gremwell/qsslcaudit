#include "ssltestresult.h"

const QString sslTestResultToString(SslTestResult r) {
    switch (r) {
    case SslTestResult::Success:
        return "success";
    case SslTestResult::NotReady:
        return "not ready";
    case SslTestResult::Undefined:
        return "undefined";
    case SslTestResult::UnhandledCase:
        return "unhandled case";
    case SslTestResult::InitFailed:
        return "init failed";
    case SslTestResult::DataIntercepted:
        return "data intercepted";
    case SslTestResult::CertAccepted:
        return "certificate accepted";
    case SslTestResult::ProtoAccepted:
        return "protocol accepted";
    case SslTestResult::ProtoAcceptedWithErr:
        return "protocol accepted with error";
    }
    return "should not happen";
}

const QString sslTestResultToStatus(SslTestResult r)
{
    switch (r) {
    case SslTestResult::Success:
        return "PASSED";
    case SslTestResult::NotReady:
    case SslTestResult::Undefined:
    case SslTestResult::UnhandledCase:
    case SslTestResult::InitFailed:
        return "UNDEFINED";
    case SslTestResult::DataIntercepted:
    case SslTestResult::CertAccepted:
    case SslTestResult::ProtoAccepted:
    case SslTestResult::ProtoAcceptedWithErr:
        return "FAILED";
    }
    return "should not happen";
}
