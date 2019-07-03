project(libqsslcaudit)

set(qsslcauditSources
    sslcaudit.cpp
    sslserver.cpp
    tcpsserver.cpp
    sslcertgen.cpp
    ssltest.cpp
    ssltests.cpp
    sslusersettings.cpp
    starttls.cpp
    tlshello.cpp
    )

set(qsslcauditHeaders
    ciphers.h
    debug.h
    errorhandler.h
    sslcaudit.h
    sslcertgen.h
    sslserver.h
    tcpsserver.h
    ssltest.h
    ssltests.h
    sslusersettings.h
    starttls.h
    tlshello.h
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

target_link_libraries(qsslcaudit_lib qtcertificateaddon)

if(UNSAFE_QSSL)
    target_link_libraries(qsslcaudit_lib unsafessl)
endif()
