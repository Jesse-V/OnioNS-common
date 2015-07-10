cmake_minimum_required(VERSION 2.8)

project(onions-common)

find_package(Boost COMPONENTS system REQUIRED)

#compiler options for Clang and GCC/G++
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "-g -O3 --std=c++11 -Wno-c++98-compat-pedantic -pedantic -Weverything -Wno-unused-parameter -Wno-global-constructors -Wno-exit-time-destructors -Wno-non-virtual-dtor -Wno-weak-vtables -Wno-padded -Wno-cast-align -Wno-gnu -Wno-nested-anon-types -Wno-documentation -Wno-documentation-unknown-command -Wno-unknown-pragmas -Wno-reserved-id-macro")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "-g -O3 --std=c++11 -Wall -Wextra -pedantic -Wdouble-promotion -Wfloat-equal -Wunsafe-loop-optimizations")
endif()

#JSONCPP needs special compile flags
#https://stackoverflow.com/questions/13638408/cmake-override-compile-flags-for-single-files
SET(JSONCPP_CPP libs/jsoncpp/jsoncpp.cpp)
set_source_files_properties(${JSONCPP_CPP} PROPERTIES COMPILE_FLAGS -w)

#include headers to satisfy dependencies
#libs/CyoEncode libs/jsoncpp
include_directories(libs libs/jsoncpp /usr/include/botan-1.10)

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

  tcp/SocksClient.cpp
  tcp/SocksRequest.cpp
  tcp/SocksReply.cpp
)

add_library(onions-jsoncpp SHARED
  ${JSONCPP_CPP}
)

add_library(onions-cyoencode SHARED
  libs/CyoEncode/CyoDecode.c
  libs/CyoEncode/CyoEncode.c
)

#link against built and existing dependencies
add_dependencies(onions-common libscrypt jsoncpp)
SET (LIBSCRYPT_LIB ${CMAKE_CURRENT_SOURCE_DIR}/libs/libscrypt/libscrypt.so.0)
target_link_libraries(onions-common pthread ${LIBSCRYPT_LIB} botan-1.10 ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_LIBRARIES})

#custom handling of output debug binary
set_target_properties(onions-common PROPERTIES DEBUG_POSTFIX "_d")

#install library
set(DEB_FOLDER "${CMAKE_CURRENT_SOURCE_DIR}/debian/extra_includes")
install(TARGETS onions-common                     DESTINATION /usr/lib/)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libonions-jsoncpp.so   DESTINATION /usr/lib/)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libonions-cyoencode.so DESTINATION /usr/lib/)
install(FILES ${LIBSCRYPT_LIB}                    DESTINATION /usr/lib/)

#install headers
set(HEADERS "/usr/include/onions-common/")
install(FILES Common.hpp              DESTINATION ${HEADERS})
install(FILES Config.hpp              DESTINATION ${HEADERS})
install(FILES Constants.hpp           DESTINATION ${HEADERS})
install(FILES Log.hpp                 DESTINATION ${HEADERS})
install(FILES Utils.hpp               DESTINATION ${HEADERS})
install(FILES tcp/HandleAlloc.hpp     DESTINATION ${HEADERS}/tcp)
install(FILES tcp/MemAllocator.hpp    DESTINATION ${HEADERS}/tcp)
install(FILES tcp/SocksClient.hpp     DESTINATION ${HEADERS}/tcp)
install(FILES tcp/SocksReply.hpp      DESTINATION ${HEADERS}/tcp)
install(FILES tcp/SocksRequest.hpp    DESTINATION ${HEADERS}/tcp)
install(FILES containers/Cache.hpp          DESTINATION ${HEADERS}/containers)
install(FILES containers/MerkleTree.hpp     DESTINATION ${HEADERS}/containers)
install(FILES containers/records/Record.hpp   DESTINATION ${HEADERS}/containers/records)
install(FILES containers/records/CreateR.hpp  DESTINATION ${HEADERS}/containers/records)

#install library dependency headers
install(FILES libs/jsoncpp/json/json.h    DESTINATION ${HEADERS}/include/json)

#install resources
set(ASSETS "${DEB_FOLDER}/assets")
install(FILES ${ASSETS}/example.key       DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/cache.json        DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/mirrors.json      DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/authority.json    DESTINATION /var/lib/tor-onions/)

#http://www.itk.org/Wiki/CMake_FAQ#Can_I_do_.22make_uninstall.22_with_CMake.3F
