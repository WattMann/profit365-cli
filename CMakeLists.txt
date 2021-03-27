cmake_minimum_required(VERSION 3.19)
project(profit365-cli)

set(CMAKE_CXX_STANDARD 17)

add_executable(profitapi-cli source/main.cpp)

target_link_libraries(profit365-cli profitapi)
target_link_libraries(profit365-cli curl)
target_link_libraries(profit365-cli ssl)
target_link_libraries(profit365-cli crypto)
target_link_libraries(profit365-cli fmt)
