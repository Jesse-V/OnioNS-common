cmake_minimum_required(VERSION 2.8)

project(onions-common)

# common: major.minor.patch : only current and last release are supported
# protocol: major.minor : major-1 and all .minor are supported (3.9 works with 2.0, but not 1.9)
  # major increments after 10 minor releases
set(MAJOR_VERSION 0)
set(MINOR_VERSION 7)
set(PATCH_VERSION 0)
set(SO_VERSION    0)

# define compiler options for Clang and GCC/G++
SET(COMMON_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++11 -DED25519_CUSTOMHASH -DED25519_CUSTOMRANDOM -fstack-protector -D_FORTIFY_SOURCE=1")
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} -Wno-c++98-compat-pedantic -pedantic -Weverything -Wno-exit-time-destructors -Wno-weak-vtables -Wno-padded -Wno-deprecated -Wno-documentation -Wno-documentation-unknown-command -Wno-reserved-id-macro -Wno-missing-noreturn -Wno-sign-conversion -Wno-shadow")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} -Wall -Wextra -pedantic -Wdouble-promotion -Wfloat-equal -Wunsafe-loop-optimizations")
endif()

# define special compile flags for JsonCpp
#https://stackoverflow.com/questions/13638408/cmake-override-compile-flags-for-single-files
SET(JSONCPP_CPP libs/jsoncpp/jsoncpp.cpp)
set_source_files_properties(${JSONCPP_CPP} PROPERTIES COMPILE_FLAGS -w)

# define sources for the JsonCpp target
add_library(onions-jsoncpp SHARED
  ${JSONCPP_CPP}
)

# build our JSON-RPC library
add_custom_target(onions-json-rpc # todo: there's probably a better way
  COMMAND # do an out-of-source build
    mkdir -p build &&
    cd build &&
    cmake -DJSONCPP_INCLUDE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/libs/jsoncpp -DJSONCPP_LIBRARY=${CMAKE_CURRENT_BINARY_DIR}/libonions-jsoncpp.so -DCOMPILE_TESTS=NO -DCOMPILE_EXAMPLES=NO -DUNIX_DOMAIN_SOCKET_SERVER=NO -DUNIX_DOMAIN_SOCKET_CLIENT=NO -DCATCH_INCLUDE_DIR=/dev/null .. &&
    make
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/libjson-rpc-cpp/
  VERBATIM
)

# define sources for our main target
add_library(onions-common SHARED
  main.cpp
)

# define our chain of dependencies
add_dependencies(onions-json-rpc onions-jsoncpp)
add_dependencies(onions-common onions-json-rpc)

# set versions so that sonames are properly set
set_target_properties(onions-common     PROPERTIES VERSION 0)
set_target_properties(onions-jsoncpp    PROPERTIES VERSION 1.6.5)

# /etc/ld.so.conf.d/onions-common.conf, # https://fedoraproject.org/wiki/Packaging:Guidelines#Alternatives_to_Rpath


