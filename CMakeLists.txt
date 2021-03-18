cmake_minimum_required(VERSION 3.19)
project(profitapi)

set(CMAKE_CXX_STANDARD 17)

add_executable(profitapi source/main.cpp source/api/profitapi.h)

target_link_libraries(profitapi ssl)
target_link_libraries(profitapi crypto)
target_link_libraries(profitapi curl)