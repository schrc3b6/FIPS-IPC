
find_library(uring NAMES liburing PATH /usr/lib/x86_64-linux-gnu /usr/lib /usr/lib64 /usr/local/lib)

# BPF Setup

ExternalProject_Get_Property(bpftool install_dir)
set(BPFOBJECT_BPFTOOL_EXE ${install_dir}/bootstrap/bpftool)
ExternalProject_Get_Property(libbpf install_dir)
set(LIBBPF_INCLUDE_DIRS ${install_dir})
set(LIBBPF_LIBRARIES ${install_dir}/libbpf.a)

add_custom_target(VMLINUXHEADERGENERATION ALL
    COMMAND ${CMAKE_COMMAND} -E echo "Generating vmlinux.h from BTF..."
)
add_dependencies(VMLINUXHEADERGENERATION bpftool)
set(GENERATED_VMLINUX_DIR ${CMAKE_BINARY_DIR})
set(BPFOBJECT_VMLINUX_H ${GENERATED_VMLINUX_DIR}/vmlinux.h)
add_custom_command(TARGET VMLINUXHEADERGENERATION
  COMMAND ${BPFOBJECT_BPFTOOL_EXE} btf dump file /sys/kernel/btf/vmlinux format c > ${BPFOBJECT_VMLINUX_H}
  COMMENT "Generating vmlinux.h from BTF..."
)
# execute_process(COMMAND ${BPFOBJECT_BPFTOOL_EXE} btf dump file /sys/kernel/btf/vmlinux format c
#   OUTPUT_FILE ${BPFOBJECT_VMLINUX_H}
#   ERROR_VARIABLE VMLINUX_error
#   RESULT_VARIABLE VMLINUX_result)
# if(${VMLINUX_result} EQUAL 0)
#   set(VMLINUX ${BPFOBJECT_VMLINUX_H})
# else()
#   message(FATAL_ERROR "Failed to dump vmlinux.h from BTF: ${VMLINUX_error}")
# endif()

find_package(BpfObject REQUIRED)

bpf_object(ip_blacklist ip_blacklist.bpf.c)
add_dependencies(ip_blacklist_skel libbpf-build bpftool VMLINUXHEADERGENERATION)

add_library(ebpf_utils ebpf_utils.c)

target_include_directories(ebpf_utils 
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}include
    PUBLIC ${CMAKE_SOURCE_DIR}/external/libbpf/src    )

target_link_libraries(ebpf_utils ip_blacklist_skel)


add_compile_options(-g)

option(GRPC "Use string as key in hashtable and ip list" OFF)
option(ZERO_COPY_DEBUG "Add additional output for zero copy with pointer offset" OFF)


add_library(ip_hashtable STATIC ip_hashtable.c)
add_library(ip_to_str STATIC ip_to_str.c)
add_library(ip_llist STATIC ip_llist.c)
add_library(shm_ringbuf STATIC shm_ringbuf.c)
add_library(fips_buf STATIC fips_buf.c)
add_library(uring_getline STATIC uring_getline.c)
# add_library(spookyc STATIC spooky-c.c)


# get_target_property(target_cxx_flags fips_buf COMPILE_OPTIONS) 
# message(STATUS "target_cxx_flags: ${target_cxx_flags}")
# set_target_properties(fips_buf PROPERTIES COMPILE_OPTIONS -Wall -Wextra -O2 -g)

target_compile_options(fips_buf PUBLIC -Wall -Wextra -O3 -fPIC)
target_compile_options(shm_ringbuf PUBLIC -Wall -Wextra -O3 -fPIC)
set_target_properties(fips_buf PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/fips_buf.h")
set_target_properties(shm_ringbuf PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/shm_ringbuf.h")

target_include_directories(uring_getline PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ip_hashtable PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ip_to_str PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(ip_llist PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(shm_ringbuf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(fips_buf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# target_include_directories(spookyc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(uring_getline uring)

target_include_directories(fips_buf PUBLIC ${LIBCONFIG_INCLUDE_DIRS})
target_link_libraries(fips_buf PUBLIC ${LIBCONFIG_LIBRARIES})
target_compile_options(fips_buf PUBLIC ${LIBCONFIG_CFLAGS_OTHER})
# target_link_libraries(fips_buf ${LIBCONFIG_LOCATION})
# target_link_libraries(ip_hashtable spookyc)

if(GRPC)
    target_compile_definitions(ip_hashtable PRIVATE "GRPC")
    target_compile_definitions(ip_llist PRIVATE "GRPC")
endif()

if(ZERO_COPY_DEBUG)
    message(STATUS "Debug build")
    target_compile_definitions(fips_buf PRIVATE
      $<$<CONFIG:Debug>:DEBUG>
    )
endif()

# from hannes signers code

add_library(fips_ipc SHARED syslog.c)

if(WRITEV)
    target_compile_definitions(fips_ipc PRIVATE "WRITEV")
endif()

if (ZERO_COPY)
    target_compile_definitions(fips_ipc PRIVATE "ZERO_COPY")
endif()
target_compile_definitions(fips_ipc PRIVATE "ZERO_COPY")

add_compile_options(-luring -g)

target_include_directories(fips_ipc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include) # fips_ips is library name

# target_include_directories(fips_ipc PRIVATE "$<TARGET_PROPERTY:shm_ringbuf,INCLUDE_DIRECTORIES>")

target_link_libraries(fips_ipc 
    shm_ringbuf
    fips_buf)
