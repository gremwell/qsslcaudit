project(qsslcaudit)

cmake_minimum_required(VERSION 2.8.11)

find_package(Qt5Core QUIET)
if( Qt5Core_DIR )
    message(STATUS "Found Qt5!")
    find_package(Qt5Core REQUIRED)
    find_package(Qt5Network REQUIRED)
endif()
if( NOT Qt5Core_DIR )
    message(STATUS "Could not find Qt5!")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

find_package(GnuTLS REQUIRED)

add_subdirectory(thirdparty)
add_subdirectory(src)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/tools/qsslcaudit" DESTINATION bin
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_READ WORLD_EXECUTE)
