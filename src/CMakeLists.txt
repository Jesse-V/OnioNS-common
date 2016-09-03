cmake_minimum_required(VERSION 2.8)

project(onions-common)

# common: major.minor.patch
set(MAJOR_VERSION 1)
set(MINOR_VERSION 1)
set(PATCH_VERSION 0)
set(SO_VERSION    0)

message(STATUS "Build type is ${CMAKE_BUILD_TYPE}")

# define compiler options for Clang and GCC/G++
# I'm aware of http://voices.canonical.com/jussi.pakkanen/2013/03/26/a-list-of-common-cmake-antipatterns/
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -std=c++11 -fstack-protector -D_FORTIFY_SOURCE=1")
SET(CLANG_DEBUG "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG} -Wno-c++98-compat-pedantic -pedantic -Weverything -Wno-exit-time-destructors -Wno-weak-vtables -Wno-padded -Wno-deprecated -Wno-documentation -Wno-documentation-unknown-command -Wno-reserved-id-macro -Wno-missing-noreturn -Wno-sign-conversion -Wno-shadow")
SET(GCC_DEBUG "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -pedantic -Wdouble-promotion -Wfloat-equal -Wunsafe-loop-optimizations")

# set compiler flags according to the type of compiler
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS_DEBUG "${CLANG_DEBUG}")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS_DEBUG "${GCC_DEBUG}")
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
add_custom_target(onions-json-rpc # I could make this a separate package, but this works
  COMMAND # do an out-of-source build
    mkdir -p build &&
    cd build &&
    cmake -DJSONCPP_INCLUDE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/libs/jsoncpp -DJSONCPP_LIBRARY=${CMAKE_CURRENT_BINARY_DIR}/libonions-jsoncpp.so -DCOMPILE_TESTS=NO -DCOMPILE_EXAMPLES=NO -DUNIX_DOMAIN_SOCKET_SERVER=NO -DUNIX_DOMAIN_SOCKET_CLIENT=NO -DCATCH_INCLUDE_DIR=/tmp .. &&
    make -j 2
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/libjson-rpc-cpp/
  VERBATIM
)

# generate our empty base classes for the JSON-RPC API
add_custom_target(onions-api
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libjson-rpc-cpp/build/bin/jsonrpcstub ${CMAKE_CURRENT_SOURCE_DIR}/api/network.json --cpp-server=NetworkServerInterface --cpp-client=NetworkClient &&
    mv -f networkserverinterface.h NetworkServerInterface.h &&
    mv -f networkclient.h NetworkClient.h &&

    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libjson-rpc-cpp/build/bin/jsonrpcstub ${CMAKE_CURRENT_SOURCE_DIR}/api/client-ipc.json --cpp-server=LocalServerInterface --cpp-client=LocalClient &&
    mv -f localserverinterface.h LocalServerInterface.h &&
    mv -f localclient.h LocalClient.h
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# define the CyoEncode library for base32 encoding
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

  bitcoin/HttpGet.cpp

  libs/ed25519-donna/ed25519.cpp
)

# define our chain of dependencies
add_dependencies(onions-json-rpc onions-jsoncpp)
add_dependencies(onions-api onions-json-rpc)
add_dependencies(onions-common onions-json-rpc onions-api onions-cyoencode)

# set library versions so that sonames are properly set
set_target_properties(onions-common     PROPERTIES VERSION ${MAJOR_VERSION}.${MINOR_VERSION})
set_target_properties(onions-jsoncpp    PROPERTIES VERSION 1.7.3)
set_target_properties(onions-cyoencode  PROPERTIES VERSION 1.1.1)

# set the list of directories that contain headers
include_directories(libs libs/jsoncpp /usr/include/botan-1.10)

# set the INSTALL_PREFIX pre-processor directive, distinguishes /usr/bin/ from /usr/local/bin/
add_definitions(-DINSTALL_PREFIX=std::string\("${CMAKE_INSTALL_PREFIX}"\))

# define linking
target_link_libraries(onions-common pthread botan-1.10 onions-cyoencode curl)

# define library path for Linux's load linker
# https://fedoraproject.org/wiki/Packaging:Guidelines#Alternatives_to_Rpath
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/onions-common.conf ${CMAKE_INSTALL_PREFIX}/onions-common)

# install libraries
SET(JSONRPC_LIB "libs/libjson-rpc-cpp/build/lib")
install(TARGETS onions-common     LIBRARY  DESTINATION lib/onions-common/)
install(TARGETS onions-jsoncpp    LIBRARY  DESTINATION lib/onions-common/)
install(TARGETS onions-cyoencode  LIBRARY  DESTINATION lib/onions-common/)
install(FILES
  ${JSONRPC_LIB}/libjsonrpccpp-common.so
  ${JSONRPC_LIB}/libjsonrpccpp-common.so.0
  ${JSONRPC_LIB}/libjsonrpccpp-common.so.0.7.0
  ${JSONRPC_LIB}/libjsonrpccpp-client.so
  ${JSONRPC_LIB}/libjsonrpccpp-client.so.0
  ${JSONRPC_LIB}/libjsonrpccpp-client.so.0.7.0
  ${JSONRPC_LIB}/libjsonrpccpp-server.so
  ${JSONRPC_LIB}/libjsonrpccpp-server.so.0
  ${JSONRPC_LIB}/libjsonrpccpp-server.so.0.7.0  DESTINATION lib/onions-common/)

# install load linker file
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/onions-common.conf DESTINATION /etc/ld.so.conf.d/)

# install headers
set(HEADERS "include/onions-common/")
install(FILES Common.hpp                                        DESTINATION ${HEADERS})
install(FILES Config.hpp                                        DESTINATION ${HEADERS})
install(FILES Constants.hpp                                     DESTINATION ${HEADERS})
install(FILES Log.hpp                                           DESTINATION ${HEADERS})
install(FILES Utils.hpp                                         DESTINATION ${HEADERS})
install(FILES containers/MerkleTree.hpp                         DESTINATION ${HEADERS}/containers)
install(FILES containers/records/Record.hpp                     DESTINATION ${HEADERS}/containers/records)
install(FILES containers/records/CreateR.hpp                    DESTINATION ${HEADERS}/containers/records)
install(FILES libs/ed25519-donna/ed25519.h                      DESTINATION ${HEADERS}/libs/ed25519-donna)

# install headers for our dependencies
install(FILES libs/jsoncpp/json/json.h                                DESTINATION ${HEADERS}/json/)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/NetworkServerInterface.h    DESTINATION ${HEADERS}/api)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/NetworkClient.h             DESTINATION ${HEADERS}/api)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/LocalServerInterface.h      DESTINATION ${HEADERS}/api)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/LocalClient.h               DESTINATION ${HEADERS}/api)

# install headers for json-rpc-cpp dependency
set(JSONRPC_BASE "libs/libjson-rpc-cpp/src/jsonrpccpp")
install(FILES ${JSONRPC_BASE}/client.h                              DESTINATION ${HEADERS}/jsonrpccpp/)
install(FILES ${JSONRPC_BASE}/server.h                              DESTINATION ${HEADERS}/jsonrpccpp/)
install(FILES ${JSONRPC_BASE}/common/exception.h                    DESTINATION ${HEADERS}/jsonrpccpp/common/)
install(FILES ${JSONRPC_BASE}/common/errors.h                       DESTINATION ${HEADERS}/jsonrpccpp/common/)
install(FILES ${JSONRPC_BASE}/common/procedure.h                    DESTINATION ${HEADERS}/jsonrpccpp/common/)
install(FILES ${JSONRPC_BASE}/common/specification.h                DESTINATION ${HEADERS}/jsonrpccpp/common/)
install(FILES libs/libjson-rpc-cpp/build/gen/jsonrpccpp/common/jsonparser.h DESTINATION ${HEADERS}/jsonrpccpp/common/)
install(FILES ${JSONRPC_BASE}/client/client.h                       DESTINATION ${HEADERS}/jsonrpccpp/client)
install(FILES ${JSONRPC_BASE}/client/iclientconnector.h             DESTINATION ${HEADERS}/jsonrpccpp/client)
install(FILES ${JSONRPC_BASE}/client/batchcall.h                    DESTINATION ${HEADERS}/jsonrpccpp/client)
install(FILES ${JSONRPC_BASE}/client/batchresponse.h                DESTINATION ${HEADERS}/jsonrpccpp/client)
install(FILES ${JSONRPC_BASE}/client/connectors/socks5client.h      DESTINATION ${HEADERS}/jsonrpccpp/client/connectors)
install(FILES ${JSONRPC_BASE}/server/abstractserver.h               DESTINATION ${HEADERS}/jsonrpccpp/server)
install(FILES ${JSONRPC_BASE}/server/abstractserverconnector.h      DESTINATION ${HEADERS}/jsonrpccpp/server)
install(FILES ${JSONRPC_BASE}/server/iclientconnectionhandler.h     DESTINATION ${HEADERS}/jsonrpccpp/server)
install(FILES ${JSONRPC_BASE}/server/iprocedureinvokationhandler.h  DESTINATION ${HEADERS}/jsonrpccpp/server)
install(FILES ${JSONRPC_BASE}/server/requesthandlerfactory.h        DESTINATION ${HEADERS}/jsonrpccpp/server)
install(FILES ${JSONRPC_BASE}/server/connectors/httpserver.h        DESTINATION ${HEADERS}/jsonrpccpp/server/connectors)

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
