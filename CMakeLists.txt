cmake_minimum_required (VERSION 3.5)

project(lmp-device-register)

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
