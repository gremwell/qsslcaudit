set(APPLICATION_TARGET qsslcaudit.bin)

SET( qsslcauditSources
    sslcaudit.cpp
    sslserver.cpp
    sslcertgen.cpp
    ssltest.cpp
    ssltests.cpp
    sslusersettings.cpp
    starttls.cpp
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
    starttls.h
    )

# unsafe mode
add_definitions(-DUNSAFE)

add_definitions(-DXSsl=SslUnsafe)
add_definitions(-DXSslConfiguration=SslUnsafeConfiguration)
add_definitions(-DXSslSocket=SslUnsafeSocket)
add_definitions(-DXSslCertificate=SslUnsafeCertificate)
add_definitions(-DXSslKey=SslUnsafeKey)
add_definitions(-DXSslCipher=SslUnsafeCipher)
add_definitions(-DXSslEllipticCurve=SslUnsafeEllipticCurve)
add_definitions(-DXSslError=SslUnsafeError)

add_subdirectory(unsafessl)

# safe mode
#add_definitions(-DXSsl=QSsl)
#add_definitions(-DXSslConfiguration=QSslConfiguration)
#add_definitions(-DXSslSocket=QSslSocket)
#add_definitions(-DXSslCertificate=QSslCertificate)
#add_definitions(-DXSslKey=QSslKey)
#add_definitions(-DXSslCipher=QSslCipher)
#add_definitions(-DXSslEllipticCurve=QSslEllipticCurve)
#add_definitions(-DXSslError=QSslError)


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

INSTALL(TARGETS ${APPLICATION_TARGET} RUNTIME DESTINATION bin)
