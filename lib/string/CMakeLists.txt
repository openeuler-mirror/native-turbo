cmake_minimum_required(VERSION 3.14)
project(memcpy C ASM)          # 必须同时启用 ASM，否则 .S 文件不会被编译

#---------- 用户可调选项 ----------
set(THIRDPARTY_SAFE_FLAGS "" CACHE STRING
    "extra safe cflags from outer project")
set(MEMCPY_C_FLAGS "${THIRDPARTY_SAFE_FLAGS}" CACHE STRING
    "extra cflags for memcpy")
separate_arguments(MEMCPY_C_FLAGS_LIST NATIVE_COMMAND "${MEMCPY_C_FLAGS}")

# 架构选择（未指定时自动检测）
set(MEMCPY_ARCH "" CACHE STRING
    "arch under string/: aarch64 | arm | x86_64 …")
if(NOT MEMCPY_ARCH)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _proc)
    if(_proc MATCHES "aarch64|arm64")
        set(MEMCPY_ARCH "aarch64")
    elseif(_proc MATCHES "x86_64|amd64")
        set(MEMCPY_ARCH "x86_64")
    elseif(_proc MATCHES "^arm")
        set(MEMCPY_ARCH "arm")
    else()
        set(MEMCPY_ARCH "aarch64")   # 默认兜底
    endif()
endif()

#---------- 源码收集 ----------
set(_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/string/${MEMCPY_ARCH}")
file(GLOB_RECURSE MEMCPY_SRCS CONFIGURE_DEPENDS
     "${_SRC_DIR}/*.c"
     "${_SRC_DIR}/*.S" "${_SRC_DIR}/*.s")
if(NOT MEMCPY_SRCS)
    message(FATAL_ERROR "[memcpy] no sources under ${_SRC_DIR}")
endif()

#---------- 构建目标 ----------
add_library(memcpy SHARED ${MEMCPY_SRCS})
set_target_properties(memcpy PROPERTIES LINKER_LANGUAGE C)

# glibc 符号版本默认值
if(NOT DEFINED MEMCPY_GLIBC_VERSION)
    if(MEMCPY_ARCH STREQUAL "x86_64")
        set(MEMCPY_GLIBC_VERSION "GLIBC_2.14")
    else()
        set(MEMCPY_GLIBC_VERSION "GLIBC_2.17")
    endif()
endif()
message(STATUS "[memcpy] export memcpy as ${MEMCPY_GLIBC_VERSION}")

# 头文件搜索路径
target_include_directories(memcpy
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:include>"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/string/${MEMCPY_ARCH}"
        "${CMAKE_CURRENT_SOURCE_DIR}/string")

# 编译 / 链接选项
target_compile_options(memcpy PRIVATE
    ${MEMCPY_C_FLAGS_LIST}
    -std=c99 -fPIC)
target_link_options(memcpy PRIVATE -Wl,-z,now)

#=====================================================
#  以下为 **固定 /usr/lib64** 的安装规则
#=====================================================
include(GNUInstallDirs)

# 1. 两个库都扔进 /usr/lib64
install(TARGETS memcpy
        EXPORT memcpyTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

# 2. 头文件（保持原样）
set(_INC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/string/include")
if(EXISTS "${_INC_DIR}")
  install(DIRECTORY "${_INC_DIR}/"
          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
          FILES_MATCHING PATTERN "*.h")
endif()

# 3. cmake 配置文件（保持原样）
install(FILES       "${CMAKE_CURRENT_SOURCE_DIR}/cmake/memcpy-config.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/memcpy")

# 4. 导出 Targets.cmake（保持原样）
install(EXPORT memcpyTargets
        NAMESPACE memcpy::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/memcpy"
        FILE        memcpyTargets.cmake)

# 5. 构建树导出（保持原样）
# export(EXPORT memcpyTargets
#        FILE "${CMAKE_CURRENT_BINARY_DIR}/memcpyTargets.cmake")

#=====================================================
#  构建并安装 libaor_memcpy_wrap.so
#=====================================================
set(AOR_WRAP_SRC ${CMAKE_CURRENT_SOURCE_DIR}/aor_memcpy_wrap.c)

add_library(aor_memcpy_wrap SHARED ${AOR_WRAP_SRC})
set_target_properties(aor_memcpy_wrap PROPERTIES
    OUTPUT_NAME aor_memcpy_wrap
    LINKER_LANGUAGE C
    C_STANDARD 99)

# 链接 libmemcpy.so 但不导出依赖
target_link_libraries(aor_memcpy_wrap
    PRIVATE memcpy -Wl,--exclude-libs,ALL)

target_compile_options(aor_memcpy_wrap PRIVATE
    ${MEMCPY_C_FLAGS_LIST}
    -std=c99 -fPIC -O2 -Wall -Wextra)
target_link_options(aor_memcpy_wrap PRIVATE -Wl,-z,now)

# 同样扔进 /usr/lib64
install(TARGETS aor_memcpy_wrap
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

#-----------------------------------------------------
#  贴心地生成一个全局可执行的包装脚本
#-----------------------------------------------------
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/run-with-memcpy" "\
#!/bin/sh\n\
export LD_PRELOAD=libaor_memcpy_wrap.so\n\
exec \"$@\"\n")
file(CHMOD "${CMAKE_CURRENT_BINARY_DIR}/run-with-memcpy"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                 GROUP_READ GROUP_EXECUTE
                 WORLD_READ WORLD_EXECUTE)
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/run-with-memcpy"
        DESTINATION bin)