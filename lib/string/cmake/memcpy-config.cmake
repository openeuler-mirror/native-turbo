# memcpy-config.cmake  (安装后供 find_package 使用)

# 计算本文件所在目录
get_filename_component(_memcpy_cmake_dir "${CMAKE_CURRENT_LIST_FILE}" PATH)

# 引入目标
include("${_memcpy_cmake_dir}/memcpyTargets.cmake")

# 绝对路径
set(MEMCPY_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../include")
set(MEMCPY_LIBRARY     "${CMAKE_CURRENT_LIST_DIR}/../../../lib/libmemcpy.so")

# 兼容变量
set(memcpy_FOUND TRUE)
set(memcpy_VERSION "0.1.0")
set(memcpy_INCLUDE_DIRS "${MEMCPY_INCLUDE_DIR}")
set(memcpy_LIBRARY      "${MEMCPY_LIBRARY}")

# 清理临时变量
unset(_memcpy_cmake_dir)