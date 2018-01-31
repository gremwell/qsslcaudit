
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

include_directories(${qtcertificateaddon_INCLUDE_DIRECTORIES} ${GNUTLS_INCLUDE_DIR})
add_library(qtcertificateaddon STATIC ${qtcertificateaddon_SOURCES} ${qtcertificateaddon_HEADERS})
set_target_properties(qtcertificateaddon PROPERTIES AUTOMOC TRUE)
target_link_libraries(qtcertificateaddon Qt5::Core Qt5::Network ${GNUTLS_LIBRARIES})
