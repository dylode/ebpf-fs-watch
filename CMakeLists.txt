cmake_minimum_required(VERSION 3.22.1)

project(ebpf-fs-watch C)

set(CMAKE_C_COMPILER "clang-15")


include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libbpf/src
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
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

set(GENERATED_VMLINUX_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(BPFOBJECT_VMLINUX_H ${GENERATED_VMLINUX_DIR}/vmlinux.h)
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)

execute_process(COMMAND ${BPFOBJECT_BPFTOOL_EXE} btf dump file /sys/kernel/btf/vmlinux format c
  OUTPUT_FILE ${BPFOBJECT_VMLINUX_H}
  ERROR_VARIABLE VMLINUX_error
  RESULT_VARIABLE VMLINUX_result)
if(${VMLINUX_result} EQUAL 0)
  set(VMLINUX ${BPFOBJECT_VMLINUX_H})
else()
  message(FATAL_ERROR "Failed to dump vmlinux.h from BTF: ${VMLINUX_error}")
endif()

set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)

set(BPF_C_FILE ${CMAKE_CURRENT_SOURCE_DIR}/watch.bpf.c)
set(BPF_O_FILE ${CMAKE_CURRENT_BINARY_DIR}/watch.bpf.o)

add_custom_target(watch-ebpf 
  COMMAND clang-15 -g -O2 -target bpf
          -I ${LIBBPF_INCLUDE_DIRS} -c ${BPF_C_FILE} -o ${BPF_O_FILE}
  VERBATIM 
)

set(BPF_SKEL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/watch_skel.h)
add_custom_target(watch-ebpf-skel
  COMMAND bash -c "${BPFOBJECT_BPFTOOL_EXE} gen skeleton ${BPF_O_FILE} > ${BPF_SKEL_FILE}"
  VERBATIM 
)

add_executable(${PROJECT_NAME} watch.c)
target_include_directories(${PROJECT_NAME} PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBBPF_LIBRARIES} -lelf -lz)