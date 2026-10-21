cmake_minimum_required(VERSION 3.30)

project(netflow)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED 17)

enable_testing()
find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_executable(netflow
        main.cpp
        src/PacketParser.cpp
)

target_compile_options(netflow PRIVATE
        -Wall
        -Wextra
)

target_link_libraries(netflow PRIVATE
        pcap
)

add_test(NAME feature_read_missing
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/test/feature_read.py
                $<TARGET_FILE:netflow>
                ${CMAKE_BINARY_DIR}/missing.pcap
)
