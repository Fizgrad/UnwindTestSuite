cmake_minimum_required(VERSION 3.16)
project(unwind_testsuite LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(unwind_cfi_cases SHARED
  src/cfi_unwind_basic_cases.cpp
  src/cfi_unwind_stress_cases.cpp
  src/cfi_unwind_deep_cases.cpp
  src/cfi_unwind_candidate_cases.cpp
  src/cfi_unwind_extended_candidate_cases.cpp
)
target_include_directories(unwind_cfi_cases PRIVATE include)
target_compile_options(unwind_cfi_cases PRIVATE
  -O2
  -g
  -fno-omit-frame-pointer
  -fexceptions
  -funwind-tables
  -fasynchronous-unwind-tables
  -pthread
  -fvisibility=hidden
  -Wall
  -Wextra
)
target_link_libraries(unwind_cfi_cases PRIVATE dl pthread)

add_library(unwind_cfi_plugin SHARED src/cfi_unwind_plugin_cases.cpp)
target_include_directories(unwind_cfi_plugin PRIVATE include)
target_compile_options(unwind_cfi_plugin PRIVATE
  -O2
  -g
  -fno-omit-frame-pointer
  -fexceptions
  -funwind-tables
  -fasynchronous-unwind-tables
  -pthread
  -fvisibility=hidden
  -Wall
  -Wextra
)
target_link_libraries(unwind_cfi_plugin PRIVATE dl pthread)

add_executable(unwind_driver src/driver.cpp)
target_include_directories(unwind_driver PRIVATE include)
target_compile_options(unwind_driver PRIVATE
  -O2
  -g
  -fno-omit-frame-pointer
  -fexceptions
  -funwind-tables
  -fasynchronous-unwind-tables
  -pthread
  -Wall
  -Wextra
)
target_link_libraries(unwind_driver PRIVATE dl pthread)

set_target_properties(unwind_driver PROPERTIES
  BUILD_RPATH "$ORIGIN"
  INSTALL_RPATH "$ORIGIN"
)
