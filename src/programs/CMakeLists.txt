# UDP Server Programm
add_executable(udp_server udp_server.c)
target_include_directories(udp_server
    PUBLIC ${CMAKE_SOURCE_DIR}/src/lib/include
)
target_link_libraries(udp_server
    PUBLIC ip_to_str
    PUBLIC Threads::Threads
    PUBLIC shm_ringbuf
    PUBLIC fips_buf
    PUBLIC uring
)

# SimpleLogstash Programm
add_executable(simplelogstash simplelogstash.c)

target_include_directories(simplelogstash
    PUBLIC ${CMAKE_SOURCE_DIR}/src/lib/include
)

target_link_libraries(simplelogstash 
    PUBLIC Threads::Threads
    PUBLIC shm_ringbuf
    PUBLIC uring
)

#nsyslog
add_executable(nsyslog nsyslog.c)

target_include_directories(nsyslog
    PUBLIC ${CMAKE_SOURCE_DIR}/src/lib/include
)

target_link_libraries(nsyslog 
    PUBLIC Threads::Threads
    PUBLIC shm_ringbuf
    PUBLIC uring
)

# SimpleFail2ban Programm
# add_executable(simplefail2ban simplefail2ban.c)
# add_executable(simplefail2ban_signer ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/simplefail2ban_signer.c)
# add_executable(test_grpc ${CMAKE_CURRENT_SOURCE_DIR}/src/programs/test_grpc.c)                                                         



# target_include_directories(simplefail2ban
#     # PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/external/libbpf/src            
#     PUBLIC ${CMAKE_SOURCE_DIR}/src/lib/include
#     PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
#     PUBLIC /usr/include/hs
# ) 
#
# target_link_libraries(simplefail2ban
#     PUBLIC ebpf_utils
#     PUBLIC uring_getline
#     PUBLIC ip_hashtable
#     PUBLIC ip_llist
#     PUBLIC ip_to_str
#     PUBLIC shm_ringbuf
#     PUBLIC hs
#     PUBLIC uring
#     PUBLIC Threads::Threads
#     ) 
#

add_executable(shm_reader shm_reader.c )
add_executable(shm_reader-bin-to-str shm_reader.c)
target_compile_definitions(shm_reader-bin-to-str PUBLIC BIN_TO_STRING)
#target_compile_options(shm_reader PUBLIC -pipe -mllvm -polly -flto)
#target_compile_options(shm_reader-bin-to-str PUBLIC -pipe -mllvm -polly -flto)
#set_property(TARGET shm_reader PROPERTY LINKER_TYPE "LLD")
#set_property(TARGET shm_reader-bin-to-str PROPERTY LINKER_TYPE "LLD")

add_executable(shm_reader_zero shm_reader.c)
add_executable(shm_reader_zero-bin-to-str shm_reader.c)
target_compile_definitions(shm_reader_zero-bin-to-str PUBLIC BIN_TO_STRING)
#target_compile_options(shm_reader_zero PUBLIC -pipe -mllvm -polly -flto)
#target_compile_options(shm_reader_zero-bin-to-str PUBLIC -pipe -mllvm -polly -flto)
#set_property(TARGET shm_reader_zero PROPERTY LINKER_TYPE "LLD")
#set_property(TARGET shm_reader_zero-bin-to-str PROPERTY LINKER_TYPE "LLD")

# target_include_directories(test_reader PRIVATE "$<TARGET_PROPERTY:shm_ringbuf,INCLUDE_DIRECTORIES>")


target_link_libraries(shm_reader_zero-bin-to-str 
    shm_ringbuf 
    liburing.a
    pthread
    fips_buf)
target_link_libraries(shm_reader_zero 
    shm_ringbuf 
    liburing.a
    pthread
    fips_buf)


target_link_libraries(shm_reader-bin-to-str 
    shm_ringbuf 
    liburing.a
    pthread
    fips_buf)
target_link_libraries(shm_reader 
    shm_ringbuf 
    liburing.a
    pthread
    fips_buf)

target_compile_definitions(shm_reader_zero PUBLIC "ZERO_COPY")
target_compile_definitions(shm_reader_zero-bin-to-str PUBLIC "ZERO_COPY")

add_subdirectory(sf2b)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Debug build")
    target_compile_definitions(shm_reader PRIVATE
      $<$<CONFIG:Debug>:DEBUG>
    )
endif()


