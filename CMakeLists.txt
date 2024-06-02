#! CMAKE 
cmake_minimum_required(VERSION 3.25)
project(netracer VERSION 1.0 DESCRIPTION "Simple network packet tracer") 


if(${CMAKE_BUILD_TYPE}  MATCHES "[Rr]elease") 
  message(STATUS "BUILD TYPE RELEASE VERSION ${PROJECT_VERSION}") 
  add_compile_options(-Wall -Wextra  -O2 ) 
else () 
  message(STATUS "Debug Build")
  set(CMAKE_BUILD_TYPE  Debug)
endif() 

include_directories(include) 

set(src  main.c  netracer.c  ifnetdevs_manip.c)  
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)  
add_executable(${PROJECT_NAME} ${src})
target_link_libraries(${PROJECT_NAME}  pcap) 
