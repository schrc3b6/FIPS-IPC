# Set C++ standard
# Add executable
add_executable(google_bench_orig google_bench_v3.cpp ip_hashtable.c spooky-c.c)

# Include directories for ip_hashtable.h
include_directories(${CMAKE_CURRENT_LIST_DIR})

# Link libraries
target_link_libraries(google_bench_orig benchmark::benchmark pthread)

