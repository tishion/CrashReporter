cmake_minimum_required(VERSION 3.4)

project(CrashReporter)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Source files
file(GLOB src_GROUP
  *.cpp
  *.h
  *.hpp
)
source_group("src" FILES ${src_GROUP})

# Output
add_executable(${PROJECT_NAME}
    ${src_GROUP}
)

# Dependencies
find_package(cpprestsdk REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE
  version
  OpenSSL::SSL
  ZLIB::ZLIB
  cpprestsdk::cpprest 
  cpprestsdk::cpprestsdk_zlib_internal 
  cpprestsdk::cpprestsdk_boost_internal 
  cpprestsdk::cpprestsdk_openssl_internal
)