set(APPLICATION_TARGET qsslcaudit.bin)

set(qsslcauditSources
    sslcaudit.cpp
    sslserver.cpp
    sslcertgen.cpp
    ssltest.cpp
    ssltests.cpp
    sslusersettings.cpp
    starttls.cpp
    main.cpp
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

add_subdirectory(unsafessl)

set(THIRDPARTY_DIR "${CMAKE_SOURCE_DIR}/thirdparty")
set(UNSAFESSL_DIR "${CMAKE_SOURCE_DIR}/src/unsafessl")

include_directories(
    .
    ${CMAKE_CURRENT_BINARY_DIR}
    ${THIRDPARTY_DIR}/qt-certificate-addon/src/certificate
    ${UNSAFESSL_DIR}
    )

add_executable(${APPLICATION_TARGET} ${qsslcauditSources} ${qsslcauditHeaders})
set_target_properties(${APPLICATION_TARGET} PROPERTIES AUTOMOC TRUE)

target_link_libraries(${APPLICATION_TARGET} Qt5::Core Qt5::Network)

target_link_libraries(${APPLICATION_TARGET}
    qtcertificateaddon
    unsafessl
    ${GNUTLS_LIBRARIES}
    )

install(TARGETS ${APPLICATION_TARGET} RUNTIME DESTINATION bin)
