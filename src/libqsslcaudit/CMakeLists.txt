project(libqsslcaudit)

set(qsslcauditSources
    sslcaudit.cpp
    sslserver.cpp
    tcpsserver.cpp
    dtlsserver.cpp
    sslcertgen.cpp
    ssltest.cpp
    ssltests.cpp
    sslusersettings.cpp
    starttls.cpp
    tlshello.cpp
    sslcheck.cpp
    ssltestresult.cpp
    clientinfo.cpp
    openssl-helper.cpp
    cve-2020-0601_poc.cpp
    testserver.cpp
    )

set(qsslcauditHeaders
    ciphers.h
    debug.h
    errorhandler.h
    sslcaudit.h
    sslcertgen.h
    sslserver.h
    tcpsserver.h
    dtlsserver.h
    ssltest.h
    ssltests.h
    sslusersettings.h
    starttls.h
    tlshello.h
    sslcheck.h
    ssltestresult.h
    clientinfo.h
    openssl-helper.h
    cve-2020-0601_poc.h
    testserver.h
    )

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${THIRDPARTY_DIR}/qt-certificate-addon/src/certificate
    )

if(UNSAFE_QSSL)
  include_directories(${UNSAFESSL_DIR})
endif()

add_library(qsslcaudit_lib STATIC ${qsslcauditSources} ${qsslcauditHeaders})
set_target_properties(qsslcaudit_lib PROPERTIES AUTOMOC TRUE)

target_link_libraries(qsslcaudit_lib qtcertificateaddon ${CRYPTOPP_LIBRARIES})

if(UNSAFE_QSSL)
    target_link_libraries(qsslcaudit_lib unsafessl)
endif()
