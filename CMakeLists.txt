# Copyright (c) 2018 Open Source Foundries Limited
#
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.5)

project(lmp-device-register)

option(STATIC_LINK "Statically link lmp-device-register" OFF)
option(DOCKER_COMPOSE_APP "Set to ON to compile with support for configuring compose-apps" OFF)

if(DOCKER_COMPOSE_APP)
    add_definitions(-DDOCKER_COMPOSE_APP)
    message(STATUS "Enabling compose-apps support")
endif(DOCKER_COMPOSE_APP)

option(PRODUCTION "Set to ON to add a production business category into a client certificate" OFF)
if(PRODUCTION)
    add_definitions(-DPRODUCTION)
    message(STATUS "Enabling production client certificates")
endif(PRODUCTION)

IF (NOT DEFINED HARDWARE_ID)
    message(FATAL_ERROR "Missing required value: HARDWARE_ID")
ENDIF()
ADD_DEFINITIONS(-DHARDWARE_ID="${HARDWARE_ID}")
message(STATUS "Setting HARDWARE_ID to ${HARDWARE_ID}")

IF (NOT DEFINED DEVICE_API)
    SET(DEVICE_API "https://api.foundries.io/ota/devices/")
ENDIF()
ADD_DEFINITIONS(-DDEVICE_API="${DEVICE_API}")
message(STATUS "Setting DEVICE_API to ${DEVICE_API}")

IF (NOT OAUTH_API)
    SET(OAUTH_API "https://app.foundries.io/oauth")
ENDIF()
ADD_DEFINITIONS(-DOAUTH_API="${OAUTH_API}")
message(STATUS "Setting OAUTH_API to ${OAUTH_API}")

IF (NOT DEFINED GIT_COMMIT)
    SET(GIT_COMMIT "unknown")
ENDIF()
ADD_DEFINITIONS(-DGIT_COMMIT="${GIT_COMMIT}")
message(STATUS "Setting GIT_COMMIT to ${GIT_COMMIT}")

IF (NOT DEFINED SOTA_CLIENT)
    SET(SOTA_CLIENT "aktualizr-lite")
ENDIF()
ADD_DEFINITIONS(-DSOTA_CLIENT="${SOTA_CLIENT}")
message(STATUS "Setting SOTA_CLIENT to ${SOTA_CLIENT}")

add_definitions('-g')
add_definitions('-Wall')

# find all required libraries
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost COMPONENTS filesystem iostreams program_options system REQUIRED)
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(OpenSSL 3.0.0 REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

# Use C++11, but without GNU or other extensions
set(CMAKE_CXX_STANDARD 11)

if(STATIC_LINK)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(BUILD_SHARED_LIBS OFF)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
endif(STATIC_LINK)

if(DISABLE_PKCS11)
add_executable(lmp-device-register src/main.cpp src/options.cpp src/auth.cpp src/pkcs11_stub.cpp src/openssl.cpp)

if(STATIC_LINK)
    target_link_libraries(lmp-device-register ${Boost_LIBRARIES} -lintl /usr/lib/libglib-2.0.a /usr/lib/libcurl.a /usr/lib/libcrypto.a /usr/lib/libnghttp2.a /usr/lib/libidn2.a /usr/lib/libunistring.a /usr/lib/libbrotlicommon.a /usr/lib/libbrotlidec.a /usr/lib/libcares.a /usr/lib/libpsl.a /usr/lib/libcurl.a /usr/lib/libssl.a)
else (STATIC_LINK)
    target_link_libraries(lmp-device-register ${CURL_LIBRARIES} ${Boost_LIBRARIES} ${GLIB_LDFLAGS} ${OPENSSL_LIBRARIES})
endif(STATIC_LINK)

else(DISABLE_PKCS11)

if(STATIC_LINK)
	message(FATAL_ERROR "STATIC_LINK not possible with PKCS11 enabled")
endif(STATIC_LINK)

pkg_check_modules(LIBP11 REQUIRED libp11)
add_executable(lmp-device-register src/main.cpp src/options.cpp src/auth.cpp src/pkcs11.cpp src/openssl.cpp)
target_link_libraries(lmp-device-register ${CURL_LIBRARIES} ${Boost_LIBRARIES} ${GLIB_LDFLAGS} ${OPENSSL_LIBRARIES} ${LIBP11_LIBRARIES})
endif(DISABLE_PKCS11)

target_include_directories(lmp-device-register PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc> ${GLIB_INCLUDE_DIRS})
install(TARGETS lmp-device-register RUNTIME DESTINATION bin)
