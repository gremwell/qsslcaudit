project(unsafessl)

list(APPEND unsafessl_INCLUDE_DIRECTORIES
    ${QT_INCLUDES}
    ${QT_QTCORE_INCLUDE_DIR}
    ${QT_QTNETWORK_INCLUDE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

list(APPEND unsafessl_SOURCES
    sslunsafecertificate.cpp
    sslunsafecertificate_openssl.cpp
    sslunsafecertificateextension.cpp
    sslunsafecipher.cpp
    sslunsafecontext_openssl.cpp
    sslunsafeconfiguration.cpp
    sslunsafediffiehellmanparameters.cpp
    sslunsafediffiehellmanparameters_openssl.cpp
    sslunsafeerror.cpp
    sslunsafekey_openssl.cpp
    sslunsafekey_p.cpp
    sslunsafemutexpool.cpp
    sslunsafepresharedkeyauthenticator.cpp
    sslunsaferingbuffer.cpp
    sslunsafesocket.cpp
    sslunsafesocket_openssl.cpp
    sslunsafesocket_openssl_symbols.cpp
)

include_directories(${unsafessl_INCLUDE_DIRECTORIES})
add_library(unsafessl STATIC ${unsafessl_SOURCES})
set_target_properties(
    unsafessl
        PROPERTIES
            AUTOMOC TRUE
)
target_link_libraries(unsafessl Qt5::Core Qt5::Network)
