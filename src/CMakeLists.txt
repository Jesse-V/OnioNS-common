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

# define our JsonCpp target
add_library(onions-jsoncpp SHARED
  ${JSONCPP_CPP}
)

# define our JSON-RPC library
add_custom_target(onions-json-rpc # todo: there's probably a better way
  COMMAND # do an out-of-source build
    mkdir -p build &&
    cd build &&
    cmake -DJSONCPP_INCLUDE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/libs/jsoncpp -DJSONCPP_LIBRARY=${CMAKE_CURRENT_BINARY_DIR}/libonions-jsoncpp.so -DCOMPILE_TESTS=NO -DCOMPILE_EXAMPLES=NO -DUNIX_DOMAIN_SOCKET_SERVER=NO -DUNIX_DOMAIN_SOCKET_CLIENT=NO -DCATCH_INCLUDE_DIR=/dev/null .. &&
    make
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/libjson-rpc-cpp/
  VERBATIM
)

# define libscrypt library
add_custom_target(onions-libscrypt
  COMMAND make
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/libscrypt/
)

# define the CyoEncode 
add_library(onions-cyoencode SHARED
  libs/CyoEncode/CyoDecode.c
  libs/CyoEncode/CyoEncode.c
)

# define sources for our main target
add_library(onions-common SHARED
  Common.cpp
  Config.cpp
  Log.cpp
  Utils.cpp

  containers/Cache.cpp
  containers/MerkleTree.cpp
  containers/records/Record.cpp
  containers/records/CreateR.cpp
  
  spec/AbstractSpecClient.h
  spec/AbstractSpecServer.h
  
  crypto/ed25519.cpp
)

# define our chain of dependencies
add_dependencies(onions-json-rpc onions-jsoncpp)
add_dependencies(onions-common onions-json-rpc onions-cyoencode onions-libscrypt)

# set library versions so that sonames are properly set
set_target_properties(onions-common     PROPERTIES VERSION 0)
set_target_properties(onions-jsoncpp    PROPERTIES VERSION 1.6.5)
set_target_properties(onions-libscrypt  PROPERTIES VERSION 1.20)
set_target_properties(onions-cyoencode  PROPERTIES VERSION 1.1.1)

# set the list of directories that contain headers
include_directories(libs libs/jsoncpp /usr/include/botan-1.10)

# set the INSTALL_PREFIX pre-processor directive, distinguishes /usr/bin/ from /usr/local/bin/
add_definitions(-DINSTALL_PREFIX=std::string\("${CMAKE_INSTALL_PREFIX}"\))

# define linking
SET(LIBSCRYPT_LIB ${CMAKE_CURRENT_SOURCE_DIR}/libs/libscrypt/libscrypt.so.0)
target_link_libraries(onions-common pthread botan-1.10)

# define library path for Linux's load linker
# https://fedoraproject.org/wiki/Packaging:Guidelines#Alternatives_to_Rpath
file(WRITE onions-common.conf ${CMAKE_INSTALL_PREFIX}/onions-common)

# install libraries
install(TARGETS onions-common     LIBRARY  DESTINATION lib/onions-common/)
install(TARGETS onions-jsoncpp    LIBRARY  DESTINATION lib/onions-common/)
install(TARGETS onions-cyoencode  LIBRARY  DESTINATION lib/onions-common/)
install(FILES   ${LIBSCRYPT_LIB}           DESTINATION lib/onions-common/)

# install load linker file
install(FILES   onions-common.conf           DESTINATION /etc/ld.so.conf.d/)

# install headers
set(HEADERS "include/onions-common/")
install(FILES Common.hpp                      DESTINATION ${HEADERS})
install(FILES Config.hpp                      DESTINATION ${HEADERS})
install(FILES Constants.hpp                   DESTINATION ${HEADERS})
install(FILES Log.hpp                         DESTINATION ${HEADERS})
install(FILES Utils.hpp                       DESTINATION ${HEADERS})
install(FILES containers/MerkleTree.hpp       DESTINATION ${HEADERS}/containers)
install(FILES containers/records/Record.hpp   DESTINATION ${HEADERS}/containers/records)
install(FILES containers/records/CreateR.hpp  DESTINATION ${HEADERS}/containers/records)
install(FILES spec/AbstractSpecClient.h       DESTINATION ${HEADERS}/spec)
install(FILES spec/AbstractSpecServer.h       DESTINATION ${HEADERS}/spec)
install(FILES crypto/ed25519.h                DESTINATION ${HEADERS}/crypto)

# install resources
set(ASSETS "${CMAKE_CURRENT_SOURCE_DIR}/assets")
install(FILES ${ASSETS}/mirrors.json      DESTINATION share/onions-common/)
install(FILES ${ASSETS}/quorum.json       DESTINATION share/onions-common/)

# setup uninstall target (use libjson-rpc-cpp's uninstall method)
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/libs/libjson-rpc-cpp/cmake/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY
)

# define the uninstall target
add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)

