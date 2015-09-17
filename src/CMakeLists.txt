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

#JSONCPP needs special compile flags
#https://stackoverflow.com/questions/13638408/cmake-override-compile-flags-for-single-files
SET(JSONCPP_CPP libs/jsoncpp/jsoncpp.cpp)
set_source_files_properties(${JSONCPP_CPP} PROPERTIES COMPILE_FLAGS -w)

#include headers to satisfy dependencies
include_directories(libs libs/jsoncpp /usr/include/botan-1.10)

add_definitions(-DINSTALL_PREFIX=std::string\("${CMAKE_INSTALL_PREFIX}"\))

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

add_library(onions-jsoncpp SHARED
  ${JSONCPP_CPP}
)

add_custom_target(onions-libscrypt
  COMMAND make
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/libscrypt/
)

add_library(onions-cyoencode SHARED
  libs/CyoEncode/CyoDecode.c
  libs/CyoEncode/CyoEncode.c
)

#set versions so that sonames are properly set
set_target_properties(onions-common     PROPERTIES VERSION 0)
set_target_properties(onions-jsoncpp    PROPERTIES VERSION 1.6.5)
set_target_properties(onions-libscrypt  PROPERTIES VERSION 1.20)
set_target_properties(onions-cyoencode  PROPERTIES VERSION 1.1.1)

add_dependencies(onions-common onions-libscrypt)

#link against libraries
SET(LIBSCRYPT_LIB ${CMAKE_CURRENT_SOURCE_DIR}/libs/libscrypt/libscrypt.so.0)
target_link_libraries(onions-common popt pthread botan-1.10
  ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_LIBRARIES})

#install libraries
install(TARGETS onions-common     LIBRARY  DESTINATION lib/onions-common/)
install(TARGETS onions-jsoncpp    LIBRARY  DESTINATION lib/onions-common/)
install(TARGETS onions-cyoencode  LIBRARY  DESTINATION lib/onions-common/)
install(FILES   ${LIBSCRYPT_LIB}           DESTINATION lib/onions-common/)

#install headers
set(HEADERS "include/onions-common/")
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

#install library dependency headers
install(FILES libs/jsoncpp/json/json.h    DESTINATION ${HEADERS}/json)

#install resources
set(ASSETS "${CMAKE_CURRENT_SOURCE_DIR}/assets")
install(FILES ${ASSETS}/mirrors.json      DESTINATION lib/tor-onions/)
install(FILES ${ASSETS}/quorum.json       DESTINATION lib/tor-onions/)

#http://www.itk.org/Wiki/CMake_FAQ#Can_I_do_.22make_uninstall.22_with_CMake.3F
