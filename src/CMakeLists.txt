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
SET (JSONCPP_CPP libs/jsoncpp/jsoncpp.cpp)
set_source_files_properties(${JSONCPP_CPP} PROPERTIES COMPILE_FLAGS -w)

#include headers to satisfy dependencies
#libs/CyoEncode libs/jsoncpp
include_directories(libs libs/jsoncpp /usr/include/botan-1.10)

#libscrypt needs to be compiled into .so
add_custom_target(libscrypt
   COMMAND make
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/libscrypt/
)

add_executable(onions-common
    main.cpp
    Flags.cpp
    Common.cpp

    containers/Cache.cpp
    containers/MerkleTree.cpp
    containers/records/Record.cpp
    containers/records/CreateR.cpp

    tcp/SocksClient.cpp
    tcp/SocksRequest.cpp
    tcp/SocksReply.cpp

    utils.cpp

    ${JSONCPP_CPP}

    libs/CyoEncode/CyoDecode.c
    libs/CyoEncode/CyoEncode.c
)

#link against built and existing dependencies
add_dependencies(onions-common libscrypt)
SET (LIBSCRYPT_LIB ${CMAKE_CURRENT_SOURCE_DIR}/libs/libscrypt/libscrypt.so.0)
target_link_libraries(onions-common pthread ${LIBSCRYPT_LIB} botan-1.10 ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_LIBRARIES})

#custom handling of output debug binary
set_target_properties(onions-common PROPERTIES DEBUG_POSTFIX "_d")

#installation of files
set(DEB_FOLDER "${CMAKE_CURRENT_SOURCE_DIR}/debian/extra_includes")
install(FILES ${LIBSCRYPT_LIB}           DESTINATION /usr/lib/)
install(FILES ${DEB_FOLDER}/onions.1.gz  DESTINATION /usr/share/man/man1)

set(ASSETS "${DEB_FOLDER}/assets")
install(FILES ${ASSETS}/example.key         DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/cache.txt           DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/cached-certs        DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/cached-microdesc-consensus  DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/cached-microdescs.new       DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/mirrors.txt                 DESTINATION /var/lib/tor-onions/)
install(FILES ${ASSETS}/quorum.txt                  DESTINATION /var/lib/tor-onions/)

#http://www.itk.org/Wiki/CMake_FAQ#Can_I_do_.22make_uninstall.22_with_CMake.3F