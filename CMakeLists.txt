cmake_minimum_required(VERSION 3.15)
project(FaceAuthPam)

set(CMAKE_CXX_STANDARD 11)

add_library(FaceAuthPam SHARED FaceAuthPamBridge.cpp)