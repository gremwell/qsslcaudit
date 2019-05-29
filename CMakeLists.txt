project(qsslcaudit)

cmake_minimum_required(VERSION 2.8.11)

set(QSSLC_VERSION_MAJOR 0)
set(QSSLC_VERSION_MINOR 5)
set(QSSLC_VERSION_PATCH 0)
set(QSSLC_VERSION "${QSSLC_VERSION_MAJOR}.${QSSLC_VERSION_MINOR}.${QSSLC_VERSION_PATCH}")
# version formatting stolen from KeepAssXC's CMakeLists.txt :-)
set(OVERRIDE_VERSION "" CACHE STRING "Override the qsslcaudit Version for Snapshot builds")

set(QSSLC_BUILD_TYPE "Snapshot" CACHE STRING "Set qsslcaudit build type to distinguish between stable releases and snapshots")
set_property(CACHE QSSLC_BUILD_TYPE PROPERTY STRINGS Snapshot Release PreRelease)

# Retrieve git HEAD revision hash
set(GIT_HEAD_OVERRIDE "" CACHE STRING "Manually set the Git HEAD hash when missing (eg, when no .git folder exists)")
execute_process(COMMAND git rev-parse --short=7 HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_HEAD
        ERROR_QUIET)
string(STRIP "${GIT_HEAD}" GIT_HEAD)
if(GIT_HEAD STREQUAL "" AND NOT GIT_HEAD_OVERRIDE STREQUAL "")
    string(SUBSTRING "${GIT_HEAD_OVERRIDE}" 0 7 GIT_HEAD)
elseif(EXISTS ${CMAKE_SOURCE_DIR}/.gitrev)
    file(READ ${CMAKE_SOURCE_DIR}/.gitrev GIT_HEAD)
endif()
message(STATUS "Found Git HEAD Revision: ${GIT_HEAD}\n")

# Check if on a tag, if so build as a release
execute_process(COMMAND git tag --points-at HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_TAG
        ERROR_QUIET)
if(GIT_TAG)
    string(STRIP "${GIT_TAG}" GIT_TAG)
    set(OVERRIDE_VERSION ${GIT_TAG})
elseif(EXISTS ${CMAKE_SOURCE_DIR}/.version)
    file(READ ${CMAKE_SOURCE_DIR}/.version OVERRIDE_VERSION)
endif()

string(REGEX REPLACE "(\r?\n)+" "" OVERRIDE_VERSION "${OVERRIDE_VERSION}")
string(REGEX REPLACE "v" "" OVERRIDE_VERSION "${OVERRIDE_VERSION}")
if(OVERRIDE_VERSION)
    if(OVERRIDE_VERSION MATCHES "^[\\.0-9]+-(alpha|beta)[0-9]+$")
        set(QSSLC_BUILD_TYPE PreRelease)
        set(QSSLC_VERSION ${OVERRIDE_VERSION})
    elseif(OVERRIDE_VERSION MATCHES "^[\\.0-9]+$")
        set(QSSLC_BUILD_TYPE Release)
        set(QSSLC_VERSION ${OVERRIDE_VERSION})
    else()
        set(QSSLC_BUILD_TYPE Snapshot)
        set(QSSLC_VERSION ${OVERRIDE_VERSION})
    endif()
else()
    if(QSSLC_BUILD_TYPE STREQUAL "PreRelease")
        set(QSSLC_VERSION "${QSSLC_VERSION}-preview")
    elseif(QSSLC_BUILD_TYPE STREQUAL "Snapshot")
        set(QSSLC_VERSION "${QSSLC_VERSION}-snapshot")
    endif()
endif()

if(QSSLC_BUILD_TYPE STREQUAL "Release")
    set(QSSLC_BUILD_TYPE_RELEASE ON)
elseif(QSSLC_BUILD_TYPE STREQUAL "PreRelease")
    set(QSSLC_BUILD_TYPE_PRE_RELEASE ON)
else()
    set(QSSLC_BUILD_TYPE_SNAPSHOT ON)
endif()

message(STATUS "Setting up build for qsslcaudit v${QSSLC_VERSION}\n")

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

  add_definitions(-DUNSAFE)
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

set(UNSAFE_QSSL "yes")
if(UNSAFE_QSSL)
  add_definitions(-DUNSAFE_QSSL)
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
set(LIBQSSLCAUDIT_DIR "${CMAKE_SOURCE_DIR}/src/libqsslcaudit")

add_subdirectory(thirdparty)
add_subdirectory(src)

if(WITH_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
