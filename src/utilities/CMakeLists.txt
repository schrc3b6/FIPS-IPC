
# Poll_rbuf utility
add_executable(poll_rbuf poll_rbuf.c)
target_include_directories(poll_rbuf
    PUBLIC ${CMAKE_SOURCE_DIR}/src/lib/include
)

target_link_libraries(poll_rbuf 
    PUBLIC shm_ringbuf
    PUBLIC Threads::Threads
)

# Benchmarks
add_executable(ip_string_benchmark ip_string_benchmark.c)
target_include_directories(ip_string_benchmark
    PUBLIC ${CMAKE_SOURCE_DIR}/src/lib/include
)

target_link_libraries(ip_string_benchmark 
    PUBLIC ip_to_str
)

# Benchmarks
# add_executable(hashfunc_benchmark hashfunc_benchmark.c)
# target_include_directories(hashfunc_benchmark
#     PUBLIC ${CMAKE_SOURCE_DIR}/src/lib/include
# )
#
# target_link_libraries(hashfunc_benchmark 
#     PUBLIC ip_hashtable
# )

