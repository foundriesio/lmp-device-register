# Copyright (c) 2018 Open Source Foundries Limited
#
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.5)

project(lmp-device-register)

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

IF (NOT DEFINED DEVICE_FACTORY)
    IF(NOT DEFINED DEVICE_STREAMS)
        message(FATAL_ERROR "Missing required value: DEVICE_FACTORY or DEVICE_STREAMS")
    ENDIF()
    message(STATUS "Using DEVICE_STREAMS as DEVICE_FACTORY value (${DEVICE_STREAMS})")
    SET(DEVICE_FACTORY ${DEVICE_STREAMS})
ENDIF()
ADD_DEFINITIONS(-DDEVICE_FACTORY="${DEVICE_FACTORY}")
message(STATUS "Setting DEVICE_FACTORY to ${DEVICE_FACTORY}")

IF (NOT DEFINED DEVICE_API)
    SET(DEVICE_API "https://api.foundries.io/ota/devices/")
ENDIF()
ADD_DEFINITIONS(-DDEVICE_API="${DEVICE_API}")
message(STATUS "Setting DEVICE_API to ${DEVICE_API}")

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

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-modules)

# find all required libraries
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost COMPONENTS filesystem iostreams program_options system REQUIRED)
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

# Use C++11, but without GNU or other extensions
set(CMAKE_CXX_STANDARD 11)

add_executable(lmp-device-register src/main.cpp)
target_include_directories(lmp-device-register PRIVATE ${GLIB_INCLUDE_DIRS})
target_link_libraries(lmp-device-register ${CURL_LIBRARIES} ${Boost_LIBRARIES} ${GLIB_LDFLAGS})
install(TARGETS lmp-device-register RUNTIME DESTINATION bin)
