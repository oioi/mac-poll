cmake_minimum_required(VERSION 2.8)
project(macc)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic --std=c++11 -g")

set (HEADERS buffer.h aux_log.h prog_config.h main.h)
set (SOURCES buffer.cpp aux_log.cpp config.cpp main.cpp)

add_executable(macc ${SOURCES} ${HEADERS})
target_link_libraries(macc confuse rt netsnmp)
