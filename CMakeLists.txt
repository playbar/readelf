cmake_minimum_required(VERSION 3.6)
project(clionpro)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES src/main.cpp src/CTest.cpp src/CTest.h parseso/ParseSo.cpp)
add_executable(CLionTest ${SOURCE_FILES})

MESSAGE("make files")


set(SOURCE_FILES1 src/main2.cpp src/CTest.cpp )
add_executable(CLionTest2 ${SOURCE_FILES1})

set(SOURCE_PARSESO parseso/ParseSo.cpp parseso/elf.h)
add_executable(ParseSo ${SOURCE_PARSESO})

# UnityConfig
set(UnityFile  unity/UnityConfigFile.cpp unity/UnityConfigFile.h unity/UnityConfig.cpp)
add_executable(UnityConfig ${UnityFile})

#target_link_libraries()