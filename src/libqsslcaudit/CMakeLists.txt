project(libqsslcaudit)

set(qsslcauditSources
    sslcaudit.cpp
    sslserver.cpp
    sslcertgen.cpp
    ssltest.cpp
    ssltests.cpp
    sslusersettings.cpp
    starttls.cpp
    )

set(qsslcauditHeaders
    ciphers.h
    debug.h
    errorhandler.h
    sslcaudit.h
    sslcertgen.h
    sslserver.h
    ssltest.h
    ssltests.h
    sslusersettings.h
    starttls.h
    )

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${THIRDPARTY_DIR}/qt-certificate-addon/src/certificate
    ${UNSAFESSL_DIR}
    )

add_library(qsslcaudit_lib STATIC ${qsslcauditSources} ${qsslcauditHeaders})
set_target_properties(qsslcaudit_lib PROPERTIES AUTOMOC TRUE)

target_link_libraries(qsslcaudit_lib
    qtcertificateaddon
    unsafessl
    )
