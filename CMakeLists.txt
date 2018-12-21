project(qsslcaudit)

cmake_minimum_required(VERSION 2.8.11)

set(QSSLC_VERSION_MAJOR 0)
set(QSSLC_VERSION_MINOR 1)
set(QSSLC_VERSION_PATCH 0)
set(QSSLC_VERSION "${QSSLC_VERSION_MAJOR}.${QSSLC_VERSION_MINOR}.${QSSLC_VERSION_PATCH}")

find_package(Qt5Core REQUIRED)
find_package(Qt5Network REQUIRED)
if (Qt5Core_VERSION VERSION_LESS 5.9.1)
  add_definitions(-DOLDQT)
endif()

find_package(GnuTLS REQUIRED)

# attempt to find unsafe openssl
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}")
find_package(OpenSSLUnsafe)
if(OPENSSLUNSAFE_FOUND)
  message(STATUS "OpenSSL unsafe version " ${OPENSSL_UNSAFE_VERSION} " found, will use this version")

  include_directories(${OPENSSL_UNSAFE_INCLUDE_DIR})

  if (OPENSSL_UNSAFE_VERSION VERSION_GREATER 1.0.99)
    message(STATUS "OpenSSL unsafe version 1.1 is used")
    set(OPENSSL11_FOUND "yes")
    add_definitions(-DQT_FEATURE_opensslv11=1)
    add_definitions(-DOPENSSLV11=1)
  else()
    message(STATUS "OpenSSL unsafe version prior to 1.1 is used")
    set(OPENSSL10_FOUND "yes")
    add_definitions(-DOPENSSLV10=1)
  endif()

  set(UNSAFE_MODE "yes")
endif()

# in some cases we need native version too
find_package(OpenSSL)
if(OPENSSL_FOUND)
  message(STATUS "OpenSSL native version " ${OPENSSL_VERSION} " found")

  if(NOT UNSAFE_MODE)
    if (OPENSSL_VERSION VERSION_GREATER 1.0.99)
      message(STATUS "OpenSSL version 1.1 is used")
      set(OPENSSL11_FOUND "yes")
      add_definitions(-DQT_FEATURE_opensslv11=1)
      add_definitions(-DOPENSSLV11=1)
    else()
      message(STATUS "OpenSSL version prior to 1.1 is used")
      set(OPENSSL10_FOUND "yes")
      add_definitions(-DOPENSSLV10=1)
    endif()
  endif()
endif()

if(UNSAFE_MODE)
  add_definitions(-DUNSAFE)
  add_definitions(-DXSsl=SslUnsafe)
  add_definitions(-DXSslConfiguration=SslUnsafeConfiguration)
  add_definitions(-DXSslSocket=SslUnsafeSocket)
  add_definitions(-DXSslCertificate=SslUnsafeCertificate)
  add_definitions(-DXSslKey=SslUnsafeKey)
  add_definitions(-DXSslCipher=SslUnsafeCipher)
  add_definitions(-DXSslEllipticCurve=SslUnsafeEllipticCurve)
  add_definitions(-DXSslError=SslUnsafeError)
else()
  add_definitions(-DXSsl=QSsl)
  add_definitions(-DXSslConfiguration=QSslConfiguration)
  add_definitions(-DXSslSocket=QSslSocket)
  add_definitions(-DXSslCertificate=QSslCertificate)
  add_definitions(-DXSslKey=QSslKey)
  add_definitions(-DXSslCipher=QSslCipher)
  add_definitions(-DXSslEllipticCurve=QSslEllipticCurve)
  add_definitions(-DXSslError=QSslError)
endif()

add_definitions(-fPIC)

add_definitions(-DQSSLC_VERSION="${QSSLC_VERSION}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")

set(THIRDPARTY_DIR "${CMAKE_SOURCE_DIR}/thirdparty")
set(UNSAFESSL_DIR "${CMAKE_SOURCE_DIR}/src/unsafessl")
set(QSSLCAUDIT_DIR "${CMAKE_SOURCE_DIR}/src/qsslcaudit")

add_subdirectory(thirdparty)
add_subdirectory(src)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/tools/qsslcaudit" DESTINATION bin
  PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_READ WORLD_EXECUTE)

if(WITH_TESTS)
  add_subdirectory(tests)
endif()
