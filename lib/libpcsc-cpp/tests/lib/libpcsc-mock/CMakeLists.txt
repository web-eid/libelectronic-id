cmake_minimum_required(VERSION 3.8.0)
if(POLICY CMP0092)
  cmake_policy(SET CMP0092 NEW)
endif()

project(pcsc-mock)

# The pcsc-mock library itself.

add_library(${PROJECT_NAME}
  STATIC
  include/${PROJECT_NAME}/${PROJECT_NAME}.hpp
  src/${PROJECT_NAME}.cpp
)

target_compile_options(${PROJECT_NAME} PUBLIC
  $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
  $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -pedantic -Werror>
)

target_compile_definitions(${PROJECT_NAME} PUBLIC
  $<$<CXX_COMPILER_ID:MSVC>:WIN32_LEAN_AND_MEAN;UNICODE>
)

target_include_directories(${PROJECT_NAME}
  PUBLIC
  include
)

target_compile_features(${PROJECT_NAME}
  PUBLIC
  cxx_std_17
)

# PC/SC API dependencies.

if(MSVC)
  # no extra includes required
elseif(APPLE)
  # no extra includes required
else()
  find_package(PkgConfig)
  pkg_check_modules(PCSC libpcsclite)
  target_include_directories(${PROJECT_NAME} PUBLIC ${PCSC_INCLUDE_DIRS})
endif()

# Tests with Google Test.

enable_testing()

find_package(GTest REQUIRED)

set(TEST_EXE lib${PROJECT_NAME}-test)

add_executable(${TEST_EXE}
  tests/${PROJECT_NAME}-test.cpp
)

target_link_libraries(${TEST_EXE}
  ${PROJECT_NAME}
  GTest::Main
)

add_test(${TEST_EXE} ${TEST_EXE})
