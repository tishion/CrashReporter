cmake_minimum_required(VERSION 3.4)

project(CrashReporter)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

###############################################
# Global definitions
add_definitions(-DUNICODE)
add_definitions(-D_UNICODE)

###############################################
# Source and resource files  
file(GLOB src_GROUP
  *.cpp
  *.h
  *.hpp
)
source_group("src" FILES ${src_GROUP})

file(GLOB res_GROUP
  *.rc
  *.ico
)
source_group("res" FILES ${res_GROUP})

# Output
add_executable(${PROJECT_NAME} WIN32
  ${src_GROUP}
  ${res_GROUP}
)

###############################################
# Dependencies
set(depend_LIST 
)

if (USE_CPPREST_SDK)
  add_definitions(-DUSE_CPPREST_SDK)

  # Find dependecy packages
  find_package(cpprestsdk CONFIG REQUIRED)

  # Add dependencies
  list(APPEND depend_LIST
    cpprestsdk::cpprest 
    cpprestsdk::cpprestsdk_zlib_internal 
    cpprestsdk::cpprestsdk_boost_internal 
    cpprestsdk::cpprestsdk_openssl_internal
  )
endif()

# Add dependencies
target_link_libraries(${PROJECT_NAME} PRIVATE
  ${depend_LIST}
)
