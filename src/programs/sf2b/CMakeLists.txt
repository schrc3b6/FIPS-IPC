
set(string_variants
disk.c
fips_buf.c
posix_io.c
shmrbuf.c
)

foreach(variant IN LISTS string_variants)
get_filename_component(variant_name ${variant} NAME_WE)
add_executable(simplefail2ban_${variant_name}_local main.c string.c hs.c ${variant})
target_include_directories(simplefail2ban_${variant_name}_local
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC /usr/include/hs)
target_link_libraries(simplefail2ban_${variant_name}_local
    PUBLIC stdc++
    PUBLIC stdc++
    PRIVATE ip_blacklist_skel
    PUBLIC ebpf_utils
    PUBLIC uring_getline
    PUBLIC ip_hashtable
    PUBLIC ip_llist
    PUBLIC ip_to_str
    PUBLIC shm_ringbuf
    PUBLIC hs
    PUBLIC uring
    PUBLIC Threads::Threads
    PUBLIC fips_buf
)

add_executable(simplefail2ban_${variant_name}_grpc main.c string.c hs.c ${variant})
target_include_directories(simplefail2ban_${variant_name}_grpc
    PUBLIC /usr/include/hs
    PUBLIC ${CMAKE_SOURCE_DIR}/src/ips-action
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC "${CMAKE_BINARY_DIR}/_deps/fips-grpc-src/ips-action/src")
target_link_libraries(simplefail2ban_${variant_name}_grpc
    PUBLIC stdc++
    PUBLIC stdc++
    PRIVATE ip_blacklist_skel
    PUBLIC ebpf_utils
    PUBLIC uring_getline
    PUBLIC ip_hashtable
    PUBLIC ip_llist
    PUBLIC ip_to_str
    PUBLIC shm_ringbuf
    PUBLIC hs
    PUBLIC uring
    PUBLIC Threads::Threads
    PUBLIC fips_buf
    PUBLIC fips_grpc
)

target_compile_options(simplefail2ban_${variant_name}_grpc PUBLIC -pipe -mllvm -polly -flto)
target_compile_options(simplefail2ban_${variant_name}_local PUBLIC -pipe -mllvm -polly -flto)
set_property(TARGET simplefail2ban_${variant_name}_grpc PROPERTY LINKER_TYPE "LLD")
set_property(TARGET simplefail2ban_${variant_name}_local PROPERTY LINKER_TYPE "LLD")
target_compile_definitions(simplefail2ban_${variant_name}_grpc PUBLIC "GRPC")
endforeach()

add_executable(simplefail2ban_fips_buf_binary_local main.c binary.c fips_buf.c)
target_include_directories(simplefail2ban_fips_buf_binary_local
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC /usr/include/hs)
target_link_libraries(simplefail2ban_fips_buf_binary_local
    PUBLIC stdc++
    PUBLIC stdc++
    PRIVATE ip_blacklist_skel
    PUBLIC ebpf_utils
    PUBLIC uring_getline
    PUBLIC ip_hashtable
    PUBLIC ip_llist
    PUBLIC ip_to_str
    PUBLIC shm_ringbuf
    PUBLIC hs
    PUBLIC uring
    PUBLIC Threads::Threads
    PUBLIC fips_buf
)

add_executable(simplefail2ban_fips_buf_binary_grpc main.c binary.c fips_buf.c)
target_include_directories(simplefail2ban_fips_buf_binary_grpc 
    PUBLIC /usr/include/hs PUBLIC ${CMAKE_SOURCE_DIR}/src/ips-action
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC "${CMAKE_BINARY_DIR}/_deps/fips-grpc-src/ips-action/src")
target_link_libraries(simplefail2ban_fips_buf_binary_grpc 
    PUBLIC stdc++
    PUBLIC stdc++
    PRIVATE ip_blacklist_skel
    PUBLIC ebpf_utils
    PUBLIC uring_getline
    PUBLIC ip_hashtable
    PUBLIC ip_llist
    PUBLIC ip_to_str
    PUBLIC shm_ringbuf
    PUBLIC hs
    PUBLIC uring
    PUBLIC Threads::Threads
    PUBLIC fips_buf
    PUBLIC fips_grpc
)

target_compile_definitions(simplefail2ban_fips_buf_binary_grpc PUBLIC "GRPC")
target_compile_options(simplefail2ban_fips_buf_binary_grpc PUBLIC -pipe -mllvm -polly -flto)
target_compile_options(simplefail2ban_fips_buf_binary_local PUBLIC -pipe -mllvm -polly -flto)
set_property(TARGET simplefail2ban_fips_buf_binary_grpc PROPERTY LINKER_TYPE "LLD")
set_property(TARGET simplefail2ban_fips_buf_binary_local PROPERTY LINKER_TYPE "LLD")
