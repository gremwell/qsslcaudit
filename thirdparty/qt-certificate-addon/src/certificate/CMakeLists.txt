add_definitions( -fPIC )

list(APPEND qtcertificateaddon_INCLUDE_DIRECTORIES
    ${QT_INCLUDES}
    ${QT_QTCORE_INCLUDE_DIR}
    ${QT_QTNETWORK_INCLUDE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/src/unsafessl
)

list(APPEND qtcertificateaddon_SOURCES
    certificatebuilder.cpp
    keybuilder.cpp
    certificaterequestbuilder.cpp
    randomgenerator.cpp
    certificaterequest.cpp
    utils.cpp
)

list(APPEND qtcertificateaddon_HEADERS
    certificatebuilder.h
    certificatebuilder_p.h
    certificate_global.h
    certificate.h
    certificaterequestbuilder.h
    certificaterequestbuilder_p.h
    certificaterequest.h
    certificaterequest_p.h
    keybuilder.h
    randomgenerator.h
    utils_p.h
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

# safe mode
#add_definitions(-DXSsl=QSsl)
#add_definitions(-DXSslConfiguration=QSslConfiguration)
#add_definitions(-DXSslSocket=QSslSocket)
#add_definitions(-DXSslCertificate=QSslCertificate)
#add_definitions(-DXSslKey=QSslKey)
#add_definitions(-DXSslCipher=QSslCipher)
#add_definitions(-DXSslEllipticCurve=QSslEllipticCurve)
#add_definitions(-DXSslError=QSslError)


include_directories(${qtcertificateaddon_INCLUDE_DIRECTORIES} ${GNUTLS_INCLUDE_DIR})
add_library(qtcertificateaddon STATIC ${qtcertificateaddon_SOURCES} ${qtcertificateaddon_HEADERS})
set_target_properties(
    qtcertificateaddon
        PROPERTIES
            AUTOMOC TRUE
)
target_link_libraries(qtcertificateaddon Qt5::Core Qt5::Network)
