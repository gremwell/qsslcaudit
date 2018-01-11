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

list(APPEND unsafessl_HEADERS
    sslunsafecertificateextension.h
    sslunsafecertificateextension_p.h
    sslunsafecertificate.h
    sslunsafecertificate_p.h
    sslunsafecipher.h
    sslunsafecipher_p.h
    sslunsafeconfiguration.h
    sslunsafeconfiguration_p.h
    sslunsafecontext_openssl_p.h
    sslunsafediffiehellmanparameters.h
    sslunsafediffiehellmanparameters_p.h
    sslunsafeellipticcurve.h
    sslunsafeerror.h
    sslunsafekey.h
    sslunsafekey_p.h
    sslunsafemutexpool_p.h
    sslunsafepresharedkeyauthenticator.h
    sslunsafepresharedkeyauthenticator_p.h
    sslunsaferingbuffer_p.h
    sslunsafesocket.h
    sslunsafesocket_openssl_p.h
    sslunsafesocket_openssl_symbols_p.h
    sslunsafesocket_p.h
)

include_directories(${unsafessl_INCLUDE_DIRECTORIES})
add_library(unsafessl STATIC ${unsafessl_SOURCES} ${unsafessl_HEADERS})
set_target_properties(
    unsafessl
        PROPERTIES
            AUTOMOC TRUE
)
target_link_libraries(unsafessl Qt5::Core Qt5::Network)
