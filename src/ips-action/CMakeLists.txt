# Copyright 2018 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# modified cmake build file from official C++ helloworld example.
# Assumes protobuf and gRPC have been installed using cmake.

cmake_minimum_required(VERSION 3.23)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED libelf)
# pkg_check_modules(LIBBPF REQUIRED libbpf)

ExternalProject_Get_Property(libbpf install_dir)
set(LIBBPF_INCLUDE_DIRS ${install_dir})
set(LIBBPF_LIBRARIES ${install_dir}/libbpf.a)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Building in Release mode")
    add_compile_options(-fPIC)
else()
    message(STATUS "Building in Debug mode")
    add_compile_options(-fPIC -g)
endif()

# SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
# SET(BUILD_SHARED_LIBRARIES OFF)
# SET(CMAKE_EXE_LINKER_FLAGS "-static")

# Proto file
get_filename_component(intervention_proto "./intervention.proto" ABSOLUTE)
get_filename_component(intervention_proto_path "${intervention_proto}" PATH)


# Generated sources
set(intervention_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/intervention.pb.cc")
set(intervention_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/intervention.pb.h")
set(intervention_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/intervention.grpc.pb.cc")
set(intervention_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/intervention.grpc.pb.h")
add_custom_command(
      OUTPUT "${intervention_proto_srcs}" "${intervention_proto_hdrs}" "${intervention_grpc_srcs}" "${intervention_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${intervention_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${intervention_proto}"
      DEPENDS "${intervention_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# intervention_grpc_proto
add_library(intervention_grpc_proto
  ${intervention_grpc_srcs}
  ${intervention_grpc_hdrs}
  ${intervention_proto_srcs}
  ${intervention_proto_hdrs})
target_link_libraries(intervention_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})


  
# Targets (client|server)
# foreach(_target client server)
foreach(_target server server_dummy)
  add_executable(${_target} "server.cc")
  target_include_directories(${_target} PRIVATE ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(${_target}
  intervention_grpc_proto
  absl::flags
  absl::flags_parse
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})
target_link_libraries(${_target} ${LIBELF_LIBRARIES} ${LIBBPF_LIBRARIES} zstd)
endforeach()
  
target_compile_definitions(server PUBLIC "EBPF")

# for C wrapper of gRPC
# include_directories("/root/.local/include/")
add_library(fips_grpc SHARED client_wrapper.cc client_implementation.cc)
target_link_libraries(fips_grpc 
  intervention_grpc_proto)

# build the tool for local ip managing
# add_executable(local-ip-manager local-ip-manager.cc)
# target_link_libraries(local-ip-manager ${LIBELF_LIBRARIES} ${LIBBPF_LIBRARIES} zstd z)


# build a test client for checking whether the wrapper works in general
# add_executable(test_client wrapped_test_client.c)
# target_link_libraries(test_client fips_grpc)
  
# build a batch tester for checking whether batch blocking/unblocking works
# add_executable(batch_tester batch_tester.cc)
# target_link_libraries(batch_tester intervention_grpc_proto absl::flags absl::flags_parse ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

# build a wrapped batch tester for checking whether the wrapper works with batch blocking/unblocking
# add_executable(wrapped_batch_tester wrapped_batch_tester.c)
# target_link_libraries(wrapped_batch_tester fips_grpc)
