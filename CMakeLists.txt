cmake_minimum_required(VERSION 3.10)

project(mariatds)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(SRC_FILES
	src/mariatds.cpp)

add_executable(mariatds ${SRC_FILES})

if(NOT MSVC)
	target_compile_options(mariatds PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
endif()
