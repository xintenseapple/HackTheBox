project(KernelAdventuresPt1 C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")

add_executable(exploit exploit.c)
add_executable(dump_hashes dump_hashes.c)