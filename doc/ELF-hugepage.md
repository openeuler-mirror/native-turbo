# 可执行程序和动态库大页技术

#### 介绍

libc动态库解释器ld.so加载动态库, 支持将动态库映射到大页内存区间; 降低TLB cache miss提升CPU流水线执行效率, 最终提升应用的端到端性能;



#### 构建/安装教程

1. apply patch：glibc-patch目录中有针对openEuler SP1版本glibc的补丁，合入特性补丁代码
   如果内核未支持定制化的mmap，0002-elf-ld.so-use-special-mmap-for-hugepage-to-get-symbo.patch无需合入
2. 构建：在glibc源码目录的同层级目录下执行如下命令：
   mkdir build && cd build && ../glibc-2.28/configure --prefix=/usr --enable-static-pie --enable-hugepage-shared-library && make -j



#### 使用说明

1.  若需使用新编译的ld.so加载测试程序的动态库，在编译可执行程序的时候需要通过-Wl,--dyanmic-linker指定新编ld.so的位置
2.  对于要使用大页的动态库（libA.so为例），构建完成之后，使用hugepageedit标记动态库：./hugepageedit libA.so
3.  设置环境变量HUGEPAGE_PROBE非空，启动可执行程序，ld.so加载被hugepageedit标记的动态库会使用大页







