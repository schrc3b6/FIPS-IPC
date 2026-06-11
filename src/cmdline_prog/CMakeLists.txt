find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED libelf)

ExternalProject_Get_Property(libbpf install_dir)
set(LIBBPF_INCLUDE_DIRS ${install_dir}/bpf)
set(LIBBPF_LIBRARIES ${install_dir}/libbpf.a)
message(STATUS "Using libbpf from: ${LIBBPF_INCLUDE_DIRS}")

#set(ZLIB_USE_STATIC_LIBS "ON")
find_package(ZLIB REQUIRED)

add_executable(ebpf_cmdline ./xdp_ddos01_blacklist_cmdline.c)
target_include_directories(ebpf_cmdline PUBLIC ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(ebpf_cmdline ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} ZLIB::ZLIB)
