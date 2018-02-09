cmake_minimum_required(VERSION 2.8)
project(libhsk)
set(HSK_VERSION_MAJOR 0)
set(HSK_VERSION_MINOR 0)

configure_file (
  "${PROJECT_SOURCE_DIR}/src/config.h.in"
  "${PROJECT_BINARY_DIR}/config.h"
)

include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories("${PROJECT_SOURCE_DIR}/c-ares")

set(hsk_SRCS
  src/b64.c
  src/blake2b.c
  src/cuckoo.c
  src/dns.c
  src/proof.c
  src/record.c
  src/siphash.c
  src/main.c
)

add_executable(hsk ${hsk_SRCS})

option(CARES_STATIC "" ON)
option(CARES_SHARED "" OFF)
option(CARES_INSTALL "" OFF)
option(CARES_STATIC_PIC "" OFF)
add_subdirectory(c-ares)
target_link_libraries(hsk cares)
