#! CMAKE 
cmake_minimum_required(VERSION 3.25)
project(netracer VERSION 1.0 DESCRIPTION "Simple network packet tracer") 

set(CMAKE_BUILD_TYPE  Debug)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)  
add_executable(${PROJECT_NAME} main.c net.c)

target_link_libraries(${PROJECT_NAME}  pcap) 
