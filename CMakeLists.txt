cmake_minimum_required(VERSION 4.0)

project(netflow)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED 17)

add_executable(netflow
    main.cpp
)

target_compile_options(netflow PRIVATE
        -Wall
        -Wextra
        -Werror
)

target_link_libraries(netflow PRIVATE
        pcap
)