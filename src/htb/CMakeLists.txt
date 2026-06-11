cmake_minimum_required(VERSION 3.10)

project(google_bench_htb)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the benchmark library
find_package(benchmark REQUIRED)

# Add pthread library
find_package(Threads REQUIRED)

add_subdirectory(v3)
add_subdirectory(orig)
