CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

include_directories(include)

set(CMAKE_CXX_FLAGS "-std=c++11 -O2")

add_executable(server
		src/server.cpp)

add_executable(client
		src/client.cpp)

target_link_libraries(server pthread)
