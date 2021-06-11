cmake_minimum_required(VERSION 3.13)

project(TestBinaries)

add_executable(Target Executables/Target.cpp)

add_library(Basic SHARED Libraries/Basic.cpp)
add_library(Exception SHARED Libraries/Exception.cpp)
add_library(TlsCallback SHARED Libraries/TlsCallback.cpp)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_BUILD_TYPE Release)

# /guard:cf - Enables control flow guard
# /GL       - Enables cross module optimisations by delaying code generation to link time
# /GS       - Adds a security check to help detect stack buffer overruns
# /Oi       - Enables intrinsic functions
# /Oy       - Suppresses creation of frame pointers on the call stack
# /O2       - Maximum optimisation

set(MSVC_COMPILE_FLAGS /guard:cf /GL /GS /Oi /Oy /O2)

target_compile_options(Target PUBLIC ${MSVC_COMPILE_FLAGS})

target_compile_options(Basic PUBLIC ${MSVC_COMPILE_FLAGS})
target_compile_options(Exception PUBLIC ${MSVC_COMPILE_FLAGS})
target_compile_options(TlsCallback PUBLIC ${MSVC_COMPILE_FLAGS})

# /INCREMENTAL:NO    - Disables incremental linking
# /LARGEADDRESSAWARE - Tells the linker that the application can handle addresses larger than 2 gigabytes
# /LTCG              - Uses link time code generation
# /OPT:ICF           - Performs identical COMDAT folding
# /OPT:REF           - Eliminates functions and/or data that are never referenced

set(MSVC_LINKER_FLAGS /INCREMENTAL:NO /LARGEADDRESSAWARE /LTCG /OPT:ICF /OPT:REF)

target_link_options(Target PUBLIC ${MSVC_LINKER_FLAGS})

target_link_options(Basic PUBLIC ${MSVC_LINKER_FLAGS})
target_link_options(Exception PUBLIC ${MSVC_LINKER_FLAGS})
target_link_options(TlsCallback PUBLIC ${MSVC_LINKER_FLAGS})