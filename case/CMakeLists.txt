cmake_minimum_required(VERSION 2.8.11)
project("AES")

set(TESTS
  ${CMAKE_SOURCE_DIR}/../AES.h
  ${CMAKE_SOURCE_DIR}/../AES.cpp
  ${CMAKE_SOURCE_DIR}/test.cpp
)


add_executable(AES_TEST 
  ${TESTS}
)
