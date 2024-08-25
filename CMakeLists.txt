cmake_minimum_required(VERSION 3.25)

project(net-stress)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)

set(ENV{PKG_CONFIG_PATH} "/usr/local/dpdk/lib/x86_64-linux-gnu/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(DPDK REQUIRED libdpdk)

if(DPDK_FOUND)
    include_directories(${DPDK_INCLUDE_DIRS})
    link_directories(${DPDK_LIBRARY_DIRS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${DPDK_CFLAGS}")
else()
    message(FATAL_ERROR "DPDK not found")
endif()


add_executable(net-stress main.cc)
target_link_libraries(net-stress PRIVATE ${DPDK_LIBRARIES})
