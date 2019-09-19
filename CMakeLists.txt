# Copyright (c) 2018 Open Source Foundries Limited
#
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.5)

project(lmp-device-register)

option(AKLITE_TAGS "Set to ON to compile with support of aktualizr-lite tag filtering" OFF)
if(AKLITE_TAGS)
    add_definitions(-DAKLITE_TAGS)
    message(STATUS "Enabling aktualir-lite tag support")
endif(AKLITE_TAGS)

option(DOCKER_APPS "Set to ON to compile with support for configuring docker-apps" OFF)
if(DOCKER_APPS)
    add_definitions(-DDOCKER_APPS)
    message(STATUS "Enabling docker-apps support")
endif(DOCKER_APPS)

IF (NOT DEFINED HARDWARE_ID)
    message(FATAL_ERROR "Missing required value: HARDWARE_ID")
ENDIF()
ADD_DEFINITIONS(-DHARDWARE_ID="${HARDWARE_ID}")
message(STATUS "Setting HARDWARE_ID to ${HARDWARE_ID}")

IF (NOT DEFINED DEVICE_STREAMS)
    SET(DEVICE_STREAMS "release,premerge")
ENDIF()
ADD_DEFINITIONS(-DDEVICE_STREAMS="${DEVICE_STREAMS}")
message(STATUS "Setting DEVICE_STREAMS to ${DEVICE_STREAMS}")

IF (NOT DEFINED DEVICE_API)
    SET(DEVICE_API "https://api.foundries.io/lmp/devices/")
ENDIF()
ADD_DEFINITIONS(-DDEVICE_API="${DEVICE_API}")
message(STATUS "Setting DEVICE_API to ${DEVICE_API}")

IF (NOT DEFINED GIT_COMMIT)
    SET(GIT_COMMIT "unknown")
ENDIF()
ADD_DEFINITIONS(-DGIT_COMMIT="${GIT_COMMIT}")
message(STATUS "Setting GIT_COMMIT to ${GIT_COMMIT}")

add_definitions('-g')
add_definitions('-Wall')

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-modules)

# find all required libraries
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost COMPONENTS filesystem program_options system REQUIRED)
find_package(CURL REQUIRED)
find_package(OSTree REQUIRED)
include_directories(${LIBOSTREE_INCLUDE_DIRS})

# Use C++11, but without GNU or other extensions
set(CMAKE_CXX_STANDARD 11)

add_executable(lmp-device-register src/main.cpp)
target_link_libraries(lmp-device-register ${CURL_LIBRARIES} ${Boost_LIBRARIES} ${GLIB2_LIBRARIES} ${LIBOSTREE_LIBRARIES})
install(TARGETS lmp-device-register RUNTIME DESTINATION bin)
