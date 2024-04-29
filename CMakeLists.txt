#! CMAKE 
cmake_minimum_required(VERSION 3.25)
project(netracer) 
set(CMAKE_BUILD_TYPE  Debug)

add_executable(${PROJECT_NAME} main.c net.c)

target_link_libraries(${PROJECT_NAME}  pcap) 
