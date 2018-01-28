project(qsslcaudit)

cmake_minimum_required(VERSION 2.8.11)

find_package(Qt5Core QUIET)
if( Qt5Core_DIR )
    message(STATUS "Found Qt5!")
    find_package(Qt5Core REQUIRED)
    find_package(Qt5Network REQUIRED)

    if (Qt5Core_VERSION VERSION_LESS 5.9.1)
        set(OLDQT_FOUND "yes")
    endif()
endif()
if( NOT Qt5Core_DIR )
    message(STATUS "Could not find Qt5!")
endif()

find_package(GnuTLS REQUIRED)

# check for openssl library version
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    if (OPENSSL_VERSION VERSION_GREATER 1.0.99)
        set(OPENSSL11_FOUND "yes")
        add_definitions(-DQT_FEATURE_opensslv11=1)
    endif()
endif()

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


if (OLDQT_FOUND)
    add_definitions(-DOLDQT)
endif()

add_definitions(-fPIC)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")


add_subdirectory(thirdparty)
add_subdirectory(src)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/tools/qsslcaudit" DESTINATION bin
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_READ WORLD_EXECUTE)
