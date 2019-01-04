project(qsslcaudit.bin)

if(UNSAFE_MODE)
  add_subdirectory(unsafessl)
endif()

add_subdirectory(libqsslcaudit)

include_directories(${LIBQSSLCAUDIT_DIR})

if(UNSAFE_MODE)
  include_directories(${UNSAFESSL_DIR})
endif()

add_executable(qsslcaudit main.cpp)
set_target_properties(qsslcaudit PROPERTIES AUTOMOC TRUE)

target_link_libraries(qsslcaudit qsslcaudit_lib)

install(TARGETS qsslcaudit RUNTIME DESTINATION bin)
