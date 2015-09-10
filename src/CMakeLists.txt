cmake_minimum_required(VERSION 2.8)

project(onions-common)

find_package(Boost COMPONENTS system REQUIRED)

#compiler options for Clang and GCC/G++
SET(COMMON_FLAGS "-g -O3 --std=c++11 -DED25519_CUSTOMHASH -DED25519_CUSTOMRANDOM")
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} -Wno-c++98-compat-pedantic -pedantic -Weverything -Wno-exit-time-destructors -Wno-weak-vtables -Wno-padded -Wno-deprecated -Wno-documentation -Wno-documentation-unknown-command -Wno-reserved-id-macro -Wno-missing-noreturn")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} -Wall -Wextra -pedantic -Wdouble-promotion -Wfloat-equal -Wunsafe-loop-optimizations")
endif()

#include headers to satisfy dependencies
include_directories(libs /usr/include/botan-1.10 /usr/include/jsoncpp)

#libscrypt needs to be compiled into .so
add_custom_target(libscrypt
  COMMAND make
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/libscrypt/
)

add_library(onions-common SHARED
  Common.cpp
  Config.cpp
  Log.cpp
  Utils.cpp

  containers/Cache.cpp
  containers/MerkleTree.cpp
  containers/records/Record.cpp
  containers/records/CreateR.cpp

  tcp/TorStream.cpp
  tcp/socks5/Socks5.cpp
  tcp/socks5/Request.cpp
  tcp/socks5/Reply.cpp

  crypto/ed25519.cpp
)

add_library(onions-cyoencode SHARED
  libs/CyoEncode/CyoDecode.c
  libs/CyoEncode/CyoEncode.c
)

#link against built and existing dependencies
add_dependencies(onions-common libscrypt)
SET (LIBSCRYPT_LIB ${CMAKE_CURRENT_SOURCE_DIR}/libs/libscrypt/libscrypt.so.0)
target_link_libraries(onions-common onions-cyoencode ${LIBSCRYPT_LIB} popt pthread botan-1.10 ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_LIBRARIES})

#install library
install(TARGETS onions-common                     DESTINATION /usr/lib/)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libonions-cyoencode.so DESTINATION /usr/lib/)
install(FILES ${LIBSCRYPT_LIB}                    DESTINATION /usr/lib/)

#install headers
set(HEADERS "/usr/include/onions-common/")
install(FILES Common.hpp              DESTINATION ${HEADERS})
install(FILES Config.hpp              DESTINATION ${HEADERS})
install(FILES Constants.hpp           DESTINATION ${HEADERS})
install(FILES Log.hpp                 DESTINATION ${HEADERS})
install(FILES Utils.hpp               DESTINATION ${HEADERS})
install(FILES tcp/TorStream.hpp             DESTINATION ${HEADERS}/tcp)
install(FILES tcp/HandleAlloc.hpp           DESTINATION ${HEADERS}/tcp)
install(FILES tcp/MemAllocator.hpp          DESTINATION ${HEADERS}/tcp)
install(FILES tcp/socks5/Enums.hpp          DESTINATION ${HEADERS}/tcp/socks5)
install(FILES tcp/socks5/Reply.hpp          DESTINATION ${HEADERS}/tcp/socks5)
install(FILES tcp/socks5/Request.hpp        DESTINATION ${HEADERS}/tcp/socks5)
install(FILES tcp/socks5/Socks5.hpp         DESTINATION ${HEADERS}/tcp/socks5)
install(FILES containers/Cache.hpp          DESTINATION ${HEADERS}/containers)
install(FILES containers/MerkleTree.hpp     DESTINATION ${HEADERS}/containers)
install(FILES containers/records/Record.hpp   DESTINATION ${HEADERS}/containers/records)
install(FILES containers/records/CreateR.hpp  DESTINATION ${HEADERS}/containers/records)
install(FILES crypto/ed25519.h                DESTINATION ${HEADERS}/crypto)

#install resources
set(ASSETS "${CMAKE_CURRENT_SOURCE_DIR}/assets")
install(FILES ${ASSETS}/mirrors.json      DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/quorum.json       DESTINATION /var/lib/tor-onions/)

#http://www.itk.org/Wiki/CMake_FAQ#Can_I_do_.22make_uninstall.22_with_CMake.3F
