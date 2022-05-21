# 高性能基础库

#### 介绍

libdfe库实现高性能的用户态基础库, 提供glibc中未提供的接口, 针对数据流编程场景进行微架构级别的优化;
dataflow engine (dfe)


#### 构建/安装教程

```shell
# 下载
git clone https://gitee.com/gameoverboss/native-turbo.git

# 编译
cd native-turbo
meson build
cd build
meson compile

```


#### 使用说明

为了避免动态库引入PLT跳转开销, 本基础库仅提供静态库版本;


