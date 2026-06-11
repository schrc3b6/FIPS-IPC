cmake_minimum_required(VERSION 3.29)

# add cmake modules
include(FetchContent)

FetchContent_Declare(
  libbpf_bootstrap
  GIT_REPOSITORY https://github.com/libbpf/libbpf-bootstrap.git
  GIT_TAG master  # or specific commit/branch/tag
)

FetchContent_MakeAvailable(libbpf_bootstrap)

list(APPEND CMAKE_MODULE_PATH "${libbpf_bootstrap_SOURCE_DIR}/tools/cmake")

project("FIPS_IPC")
list(PREPEND CMAKE_MODULE_PATH "/opt/grpc/lib/cmake")
list(APPEND CMAKE_PREFIX_PATH "/opt/grpc/lib/cmake")

#set(CMAKE_LINKER_TYPE "LLD")
include(${PROJECT_SOURCE_DIR}/cmake/common.cmake)

include(CMakePrintHelpers)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_BUILD_TYPE Release)

option(WRITEV "Use writev as function" OFF)
option(ZERO_COPY "Use zero copy implementation" ON)
option(GRPC "Use String as Hashmap Keys" OFF)


add_compile_options(-Wall -Wextra -march=native -O3 -Wno-missing-field-initializers -Wno-unused-variable -Wno-unused-parameter)
#-march=native -O3 -pipe -mllvm -polly -flto
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Building in Release mode")
    add_compile_options(-fPIC)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Building in Debug mode")
    add_compile_options(-fPIC -g)
endif()


# System dependencies (liburing and pthread)
find_library(uring NAMES liburing PATHS /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/local/lib64 /usr/local/lib)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCONFIG REQUIRED libconfig)

# Local libraries
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  GIT_REPOSITORY https://github.com/libbpf/libbpf.git
  GIT_TAG master
  SOURCE_SUBDIR src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/libbpf
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  GIT_REPOSITORY https://github.com/libbpf/bpftool.git 
  GIT_TAG v7.5.0
  SOURCE_SUBDIR src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/bpftool
  STEP_TARGETS build
)

# FetchContent_Declare(fips-grpc
#     GIT_REPOSITORY git@gitup.uni-potsdam.de:fips/grpc.git
#     GIT_TAG main
#     GIT_PROGRESS TRUE
#     SOURCE_SUBDIR  "ips-action/"
#     )
#
# FetchContent_MakeAvailable(fips-grpc)

add_subdirectory(src)

set(CMAKE_INSTALL_PREFIX /opt/fips)
set(target1 fips_buf)
set(target2 config)
install(TARGETS shm_ringbuf fips_buf 
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include)

configure_file(my_package.pc.in fips.pc @ONLY)
