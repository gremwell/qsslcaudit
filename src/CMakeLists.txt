project(qsslcaudit.bin)

if(UNSAFE_QSSL)
  add_subdirectory(unsafessl)
endif()

add_subdirectory(libqsslcaudit)

include_directories(${LIBQSSLCAUDIT_DIR})

if(UNSAFE_QSSL)
  include_directories(${UNSAFESSL_DIR})
endif()

add_executable(qsslcaudit main.cpp)
set_target_properties(qsslcaudit PROPERTIES AUTOMOC TRUE)

target_link_libraries(qsslcaudit qsslcaudit_lib)

install(TARGETS qsslcaudit RUNTIME DESTINATION bin)
