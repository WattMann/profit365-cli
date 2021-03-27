cmake_minimum_required(VERSION 3.19)
project(profitapi-cli)

set(CMAKE_CXX_STANDARD 17)

add_executable(profitapi-cli source/main.cpp)

target_link_libraries(profitapi-cli profitapi)
target_link_libraries(profitapi-cli curl)
target_link_libraries(profitapi-cli ssl)
target_link_libraries(profitapi-cli crypto)
target_link_libraries(profitapi-cli fmt)