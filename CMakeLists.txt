cmake_minimum_required(VERSION 3.10)

project(hello_world LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb -O0 -Wall -Wextra -nostdlib -static -fPIE")

add_executable(hello_world main.cpp)