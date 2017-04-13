cmake_minimum_required(VERSION 3.6)
project(clionpro)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fpermissive -fvisibility=hidden -Wall -std=c++11" )

add_definitions(-DBINDIR='"$(bindir)"')

add_subdirectory(zlib)

set(CMAKE_CXX_STANDARD 11)

MESSAGE("make files")

set(SOURCE_READELF
        libiberty/argv.c
        libiberty/xexit.c
        libiberty/xstrdup.c
        libiberty/lbasename.c
        libiberty/xmalloc.c
        libiberty/dwarfnames.c
        libiberty/safe-ctype.c
        binutils/readelf.c
        binutils/dwarf.c
        binutils/elfcomm.c
        binutils/unwind-ia64.c
        binutils/version.c)
INCLUDE_DIRECTORIES(include zlib src bfd include/elf)

add_executable(readelf ${SOURCE_READELF})

target_link_libraries(readelf zlibstatic)



#target_link_libraries()