cmake_minimum_required(VERSION 2.8)

project(onions-common)

# common: major.minor.patch : current and last release are supported
# protocol: major.minor : major-1 and all .minor are supported (3.9 works with 2.0, but not 1.9)
set(MAJOR_VERSION 0)
set(MINOR_VERSION 7)
set(PATCH_VERSION 0)
set(SO_VERSION    0)

# define compiler options for Clang and GCC/G++
SET(COMMON_FLAGS "${CMAKE_CXX_FLAGS} -O2 -std=c++11 -DED25519_CUSTOMHASH -DED25519_CUSTOMRANDOM -fstack-protector -D_FORTIFY_SOURCE=1")
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
add_custom_target(onions-json-rpc # I could make this a seperate package, but this works
  COMMAND # do an out-of-source build
    mkdir -p build &&
    cd build &&
    cmake -DJSONCPP_INCLUDE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/libs/jsoncpp -DJSONCPP_LIBRARY=${CMAKE_CURRENT_BINARY_DIR}/libonions-jsoncpp.so -DCOMPILE_TESTS=NO -DCOMPILE_EXAMPLES=NO -DUNIX_DOMAIN_SOCKET_SERVER=NO -DUNIX_DOMAIN_SOCKET_CLIENT=NO -DCATCH_INCLUDE_DIR=/tmp .. &&
    make
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/libjson-rpc-cpp/
  VERBATIM
)

# create a target that regenerates our specification hook classes for JSON-RPC
add_custom_target(onions-spec
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libjson-rpc-cpp/build/bin/jsonrpcstub ${CMAKE_CURRENT_SOURCE_DIR}/rpc_spec.json --cpp-server=AbstractSpecServer --cpp-client=AbstractSpecClient &&
    mv -f abstractspecserver.h AbstractSpecServer.h &&
    mv -f abstractspecclient.h AbstractSpecClient.h
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
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
  
  crypto/ed25519.cpp
)

# define our chain of dependencies
add_dependencies(onions-json-rpc onions-jsoncpp)
add_dependencies(onions-spec onions-json-rpc)
add_dependencies(onions-common onions-json-rpc onions-spec onions-cyoencode onions-libscrypt)

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
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/onions-common.conf ${CMAKE_INSTALL_PREFIX}/onions-common)

# install libraries
install(TARGETS onions-common     LIBRARY  DESTINATION lib/onions-common/)
install(TARGETS onions-jsoncpp    LIBRARY  DESTINATION lib/onions-common/)
install(TARGETS onions-cyoencode  LIBRARY  DESTINATION lib/onions-common/)
install(FILES   ${LIBSCRYPT_LIB}           DESTINATION lib/onions-common/)
SET(JSONRPC_LIB "libs/libjson-rpc-cpp/build/lib/")
install(FILES ${JSONRPC_LIB}/libjsonrpccpp-client.so        DESTINATION lib/onions-common/)
install(FILES ${JSONRPC_LIB}/libjsonrpccpp-client.so.0      DESTINATION lib/onions-common/)
install(FILES ${JSONRPC_LIB}/libjsonrpccpp-client.so.0.6.0  DESTINATION lib/onions-common/)
install(FILES ${JSONRPC_LIB}/libjsonrpccpp-common.so        DESTINATION lib/onions-common/)
install(FILES ${JSONRPC_LIB}/libjsonrpccpp-common.so.0      DESTINATION lib/onions-common/)
install(FILES ${JSONRPC_LIB}/libjsonrpccpp-common.so.0.6.0  DESTINATION lib/onions-common/)
install(FILES ${JSONRPC_LIB}/libjsonrpccpp-server.so        DESTINATION lib/onions-common/)
install(FILES ${JSONRPC_LIB}/libjsonrpccpp-server.so.0      DESTINATION lib/onions-common/)
install(FILES ${JSONRPC_LIB}/libjsonrpccpp-server.so.0.6.0  DESTINATION lib/onions-common/)

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
install(FILES crypto/ed25519.h                                  DESTINATION ${HEADERS}/crypto)

# install headers for our dependencies
install(FILES libs/jsoncpp/json/json.h                          DESTINATION ${HEADERS}/json/)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/AbstractSpecClient.h  DESTINATION ${HEADERS}/spec)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/AbstractSpecServer.h  DESTINATION ${HEADERS}/spec)

# install headers for json-rpc-cpp dependency
set(JSONRPC_BASE "libs/libjson-rpc-cpp/src/jsonrpccpp/")
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

