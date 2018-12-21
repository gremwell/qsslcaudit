project(unsafessl)

list(APPEND unsafessl_INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_BINARY_DIR}
)

list(APPEND unsafessl_SOURCES
    sslunsafe.cpp
    sslunsafeasn1element.cpp
    sslunsafecertificate.cpp
    sslunsafecertificate_openssl.cpp
    sslunsafecertificateextension.cpp
    sslunsafecipher.cpp
    sslunsafecontext_openssl.cpp
    sslunsafeconfiguration.cpp
    sslunsafediffiehellmanparameters.cpp
    sslunsafediffiehellmanparameters_openssl.cpp
    sslunsafeerror.cpp
    sslunsafeellipticcurve.cpp
    sslunsafeellipticcurve_openssl.cpp
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
    sslunsafe.h
    sslunsafe_p.h
    sslunsafeasn1element_p.h
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
    sslunsafenetworkglobal.h
    sslunsafepresharedkeyauthenticator.h
    sslunsafepresharedkeyauthenticator_p.h
    sslunsaferingbuffer_p.h
    sslunsafesocket.h
    sslunsafesocket_openssl_p.h
    sslunsafesocket_openssl_symbols_p.h
    sslunsafesocket_p.h
)

if (OPENSSL11_FOUND)
    list(APPEND unsafessl_SOURCES
        sslunsafecontext_openssl11.cpp
        sslunsafesocket_openssl11.cpp
        )
    list(APPEND unsafessl_HEADERS
        sslunsafesocket_openssl11_symbols_p.h
        )
else()
    list(APPEND unsafessl_SOURCES
        sslunsafecontext_opensslpre11.cpp
        sslunsafesocket_opensslpre11.cpp
        )
    list(APPEND unsafessl_HEADERS
        sslunsafesocket_opensslpre11_symbols_p.h
        )
endif()

include_directories(${unsafessl_INCLUDE_DIRECTORIES})
add_library(unsafessl STATIC ${unsafessl_SOURCES} ${unsafessl_HEADERS})
set_target_properties(unsafessl PROPERTIES AUTOMOC TRUE)

if(UNSAFE_MODE)
  target_link_libraries(unsafessl OpenSSLUnsafe::SSL OpenSSLUnsafe::Crypto)
else()
  target_link_libraries(unsafessl OpenSSL::SSL OpenSSL::Crypto)
endif()

target_link_libraries(unsafessl Qt5::Core Qt5::Network)
