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

add_definitions(-DUNSAFE)

include_directories(${qtcertificateaddon_INCLUDE_DIRECTORIES} ${GNUTLS_INCLUDE_DIR})
add_library(qtcertificateaddon STATIC ${qtcertificateaddon_SOURCES})
set_target_properties(
    qtcertificateaddon
        PROPERTIES
            AUTOMOC TRUE
)
target_link_libraries(qtcertificateaddon Qt5::Core Qt5::Network)
