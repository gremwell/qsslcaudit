set(APPLICATION_TARGET qsslcaudit)

SET( qsslcauditSources
    sslcaudit.cpp
    sslserver.cpp
    sslcertgen.cpp
    ssltest.cpp
    ssltests.cpp
    sslusersettings.cpp
    main.cpp
    )

SET( qsslcauditHeaders
    ciphers.h
    debug.h
    errorhandler.h
    sslcaudit.h
    sslcertgen.h
    sslserver.h
    ssltest.h
    ssltests.h
    sslusersettings.h
    )

add_definitions(-DUNSAFE)

add_subdirectory(unsafessl)

SET( THIRDPARTY_DIR "${CMAKE_SOURCE_DIR}/thirdparty" )
SET( UNSAFESSL_DIR "${CMAKE_SOURCE_DIR}/src/unsafessl" )

INCLUDE_DIRECTORIES(
    .
    ${CMAKE_CURRENT_BINARY_DIR}
    ${THIRDPARTY_DIR}/qt-certificate-addon/src/certificate
    ${UNSAFESSL_DIR}
    )

ADD_EXECUTABLE( ${APPLICATION_TARGET} ${qsslcauditSources} ${qsslcauditHeaders} )
SET_TARGET_PROPERTIES( ${APPLICATION_TARGET}
    PROPERTIES
    AUTOMOC TRUE
    )

target_link_libraries(${APPLICATION_TARGET} Qt5::Core Qt5::Network)

TARGET_LINK_LIBRARIES( ${APPLICATION_TARGET}
    qtcertificateaddon
    unsafessl
    ${GNUTLS_LIBRARIES}
    )
