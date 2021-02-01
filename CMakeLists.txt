cmake_minimum_required(VERSION 3.10)

project(mariatds)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

find_package(Threads REQUIRED)
find_package(fmt REQUIRED)

set(SRC_FILES
	src/mariatds.cpp
	src/client_thread.cpp)

add_executable(mariatds ${SRC_FILES})

if(NOT MSVC)
	target_compile_options(mariatds PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
endif()

target_link_libraries(mariatds PRIVATE Threads::Threads)
target_link_libraries(mariatds PRIVATE fmt::fmt-header-only)
