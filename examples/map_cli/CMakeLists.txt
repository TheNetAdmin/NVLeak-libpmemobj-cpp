# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2020, Intel Corporation

cmake_minimum_required(VERSION 3.4)
project(map_cli CXX)

set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)

include(FindThreads)

if(NOT WIN32)
	find_package(PkgConfig QUIET)
endif()

if(PKG_CONFIG_FOUND)
	pkg_check_modules(LIBPMEMOBJ++ REQUIRED libpmemobj++)
else()
	find_package(LIBPMEMOBJ++ REQUIRED)
endif()

link_directories(${LIBPMEMOBJ++_LIBRARY_DIRS})

add_executable(map_cli map_cli.cpp)
target_include_directories(map_cli PUBLIC ${LIBPMEMOBJ++_INCLUDE_DIRS} . ..)
target_link_libraries(map_cli ${LIBPMEMOBJ++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

add_executable(map_cli_sec map_cli.cpp)
target_compile_definitions(map_cli_sec PUBLIC NVLEAK_SECURE)
target_include_directories(map_cli_sec PUBLIC ${LIBPMEMOBJ++_INCLUDE_DIRS} . ..)
target_link_libraries(map_cli_sec ${LIBPMEMOBJ++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
