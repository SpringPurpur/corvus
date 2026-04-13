cmake_minimum_required(VERSION 3.18)
project(ids_capture C ASM_NASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enable NASM
enable_language(ASM_NASM)
set(CMAKE_ASM_NASM_FLAGS "-f elf64")

# Strict warnings and AVX2 (C only; NASM does not accept GCC flags)
add_compile_options($<$<COMPILE_LANGUAGE:C>:-Wall>)
add_compile_options($<$<COMPILE_LANGUAGE:C>:-Wextra>)
add_compile_options($<$<COMPILE_LANGUAGE:C>:-Wpedantic>)
add_compile_options($<$<COMPILE_LANGUAGE:C>:-Wno-unused-parameter>)
add_compile_options($<$<COMPILE_LANGUAGE:C>:-mavx2>)

# libpcap
find_library(PCAP_LIB pcap REQUIRED)

# Main capture engine
add_executable(capture_engine
    src/main.c
    src/packet_parser.c
    src/flow_table.c
    src/flow_features.c
    src/ipc_writer.c
    asm/features_avx2.asm
)
target_include_directories(capture_engine PRIVATE src)
target_link_libraries(capture_engine PRIVATE ${PCAP_LIB} m)

# Unit test binary (no network, no pcap)
add_executable(test_features
    tests/test_features.c
    asm/features_avx2.asm
)
target_include_directories(test_features PRIVATE src)
target_link_libraries(test_features PRIVATE m)

# IPC debug tool
add_executable(inspect_ipc
    tests/inspect_ipc.c
)
target_include_directories(inspect_ipc PRIVATE src)
